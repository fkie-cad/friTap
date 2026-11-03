// Unit tests for the base-address hook guard (module_identity.ts +
// library_scanner.ts markModuleHooked/isModuleHooked/forgetUnloadedModule) and
// the loaders that consult it (shared_functions.ts).
//
// Run: npm run test:agent
//
// WHY: Python ctypes CDLL('/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib') of an
// already-loaded libssl made the dlopen hook run the OpenSSL executor again under
// the dlopen() spelling (the marker was keyed by name), attaching a second set of
// Interceptor listeners: every plaintext record was emitted twice.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { HookRegistry } from "./registry.js";
import { PLATFORM_DARWIN } from "./shared_structures.js";
import { executorModuleName, forgetUnloadedModule, isModuleHooked, markModuleHooked, processScanResults } from "./library_scanner.js";
import { hookRegistry } from "./registry.js";
import { hookDynamicLoader, ssl_library_loader } from "./shared_functions.js";
import { findLoadedModule } from "./module_identity.js";

const G = globalThis as any;
G.send = () => { };

const CELLAR = "/opt/homebrew/Cellar/openssl@3/3.6.4/lib/libssl.3.dylib";
const SYMLINK = "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib";

type FakeModule = { name: string; path: string; base: string; ensureInitialized: () => void };
/** Loaded images, found by name or path like Frida's findModuleByName (no symlink resolution). */
const loaded: FakeModule[] = [];
function load(path: string, base: string): FakeModule {
    const module = { name: path.split("/").pop()!, path, base, ensureInitialized: () => { } };
    loaded.push(module);
    return module;
}
function unload(module: FakeModule): void {
    loaded.splice(loaded.indexOf(module), 1);
    forgetUnloadedModule(module);
}
const find = (n: string) => loaded.find(m => m.name === n || m.path === n) ?? null;
G.Process.findModuleByName = find;
G.Process.getModuleByName = (n: string) => {
    const m = find(n);
    if (m === null) throw new Error(`unable to find module '${n}'`);
    return { ...m, enumerateExports: () => [], getExportByName: () => G.ptr(1) };
};

// libc realpath(): resolves the Homebrew opt/ symlink, like the real one.
const SYMLINKS: Record<string, string> = { [SYMLINK]: CELLAR };
G.Module.findGlobalExportByName = (name: string) => (name === "realpath" ? { isNull: () => false } : null);
G.Memory.allocUtf8String = (text: string) => ({ text });
G.Memory.alloc = () => {
    const block: any = { text: null, readUtf8String: () => block.text };
    return block;
};
G.NativeFunction = function () {
    return (input: { text: string }, out: any) => {
        out.text = SYMLINKS[input.text] ?? input.text;
        return { isNull: () => false };
    };
};

function counter() {
    const calls: string[] = [];
    return { calls, hookFn: (moduleName: string) => { calls.push(moduleName); } };
}

function opensslRow(reg: HookRegistry, hookFn: (m: string, b: boolean) => void, protocol = "tls", library = "OpenSSL") {
    reg.register({ platform: PLATFORM_DARWIN, pattern: /libssl\.3\.dylib$/, hookFn, library, libraryType: "openssl", protocol });
}

/** Installs a dlopen hook for `reg` and returns a function simulating one dlopen(path). */
function dlopenHook(reg: HookRegistry, functionName: string, protocol = "tls"): (path: string) => void {
    let callbacks: any;
    const originalAttach = G.Interceptor.attach;
    G.Interceptor.attach = (_addr: any, cb: any) => { callbacks = cb; return { detach: () => { } }; };
    try {
        load(`/usr/lib/${functionName}.dylib`, `0x${(0x9000 + loaded.length).toString(16)}`);
        hookDynamicLoader(
            { platform: PLATFORM_DARWIN, platformLabel: "MacOS", loaderLibrary: new RegExp(functionName), functionName, extractModulePath: true } as any,
            reg, [`${functionName}.dylib`], false, protocol,
        );
    } finally {
        G.Interceptor.attach = originalAttach;
    }
    assert.ok(callbacks, "loader hook must be attached");
    return (path: string) => {
        const ctx: any = {};
        callbacks.onEnter.call(ctx, [{ readCString: () => path }]);
        callbacks.onLeave.call(ctx, { isNull: () => false });
    };
}

test("findLoadedModule follows a symlinked path to the mapped image", () => {
    const m = load(CELLAR, "0x1000");
    try {
        assert.equal(findLoadedModule(SYMLINK)?.base, "0x1000");
        assert.equal(findLoadedModule("libssl.3.dylib")?.base, "0x1000");
        assert.equal(findLoadedModule("/nowhere/libssl.3.dylib"), null);
    } finally { unload(m); }
});

test("same base under several names is hooked once (initial scan, then dlopen by real and symlinked path)", () => {
    const m = load(CELLAR, "0x2000");
    try {
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "tls");
        const dlopen = dlopenHook(reg, "dlopen_alias_test");
        dlopen(CELLAR);
        dlopen(SYMLINK);
        dlopen("libssl.3.dylib");
        assert.deepEqual(openssl.calls, ["libssl.3.dylib"]);
        assert.equal(isModuleHooked(SYMLINK, "tls"), true);
    } finally { unload(m); }
});

test("the dlopen path then the initial-scan / tlsLibHunter paths do not re-hook the same image", () => {
    const m = load(CELLAR, "0x3000");
    try {
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        dlopenHook(reg, "dlopen_first_test")(SYMLINK);
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", false, "tls");
        const scan = counter();
        hookRegistry.register({ platform: PLATFORM_DARWIN, pattern: /^never$/, hookFn: scan.hookFn, library: "scan", libraryType: "openssl_scan_test", protocol: "tls" });
        const entry = { name: "libssl.3.dylib", path: CELLAR, base_address: "0x3000", library_type: "openssl_scan_test", matched_exports: [], detected_version: "" };
        processScanResults(JSON.stringify([entry]), PLATFORM_DARWIN, false, "tls");
        assert.equal(openssl.calls.length, 1);
        assert.equal(scan.calls.length, 0);
    } finally { unload(m); }
});

test("two protocols on the same module both install", () => {
    const m = load(CELLAR, "0x4000");
    try {
        const reg = new HookRegistry();
        const tls = counter();
        const other = counter();
        opensslRow(reg, tls.hookFn, "tls", "OpenSSL");
        opensslRow(reg, other.hookFn, "ssh", "OpenSSL (ssh test)");
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "tls");
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "ssh");
        // Each protocol's own repeat is still deduplicated, under any alias.
        ssl_library_loader(PLATFORM_DARWIN, reg, [SYMLINK], "MacOS", false, "tls");
        ssl_library_loader(PLATFORM_DARWIN, reg, [CELLAR], "MacOS", false, "ssh");
        assert.equal(tls.calls.length, 1);
        assert.equal(other.calls.length, 1);
    } finally { unload(m); }
});

test("unload followed by a reload re-hooks the image (same or new base)", () => {
    const reg = new HookRegistry();
    const openssl = counter();
    opensslRow(reg, openssl.hookFn);
    const dlopen = dlopenHook(reg, "dlopen_reload_test");

    let m = load(CELLAR, "0x5000");
    dlopen(SYMLINK);
    assert.equal(openssl.calls.length, 1);
    unload(m);
    assert.equal(isModuleHooked(CELLAR, "tls"), false);

    m = load(CELLAR, "0x5000");          // same base again
    dlopen(CELLAR);
    assert.equal(openssl.calls.length, 2);
    unload(m);

    m = load(CELLAR, "0x6000");          // new base
    dlopen("libssl.3.dylib");
    assert.equal(openssl.calls.length, 3);
    dlopen(SYMLINK);                     // ...and is deduplicated again afterwards
    assert.equal(openssl.calls.length, 3);
    unload(m);
});

test("an image that is not a Frida module (e.g. a Wine PE DLL) is keyed by its spelling", () => {
    markModuleHooked("schannel_test.dll", "tls");
    assert.equal(isModuleHooked("schannel_test.dll", "tls"), true);
    assert.equal(isModuleHooked("schannel_test.dll", "ssh"), false);
    // Once the image becomes resolvable, the earlier spelling-keyed marker still counts.
    const m = load("/wine/drive_c/schannel_test.dll", "0x7000");
    try { assert.equal(isModuleHooked("schannel_test.dll", "tls"), true); } finally { unload(m); }
    assert.equal(isModuleHooked("schannel_test.dll", "tls"), false, "unload clears the spelling marker too");
});

test("a first load through a symlinked dlopen() path hands the executor the canonical module name", () => {
    const m = load(CELLAR, "0x8000");
    try {
        assert.equal(executorModuleName(SYMLINK), "libssl.3.dylib");
        assert.equal(executorModuleName("schannel_unresolved.dll"), "schannel_unresolved.dll", "unresolvable spelling is kept");
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        dlopenHook(reg, "dlopen_symlink_first_test")(SYMLINK);
        assert.deepEqual(openssl.calls, ["libssl.3.dylib"]);
        assert.doesNotThrow(() => G.Process.getModuleByName(openssl.calls[0]), "executor can resolve the name it was given");
    } finally { unload(m); }
});

test("a basename shared by two loaded images falls back to the unambiguous path", () => {
    const system = load("/usr/lib/libssl.3.dylib", "0x8800");
    const brew = load(CELLAR, "0x8900");
    try {
        assert.equal(executorModuleName(SYMLINK), CELLAR);
    } finally { unload(brew); unload(system); }
});
