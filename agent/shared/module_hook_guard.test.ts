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
import { hookDynamicLoader, loadedModulePath, ssl_library_loader } from "./shared_functions.js";
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
function dlopenHook(reg: HookRegistry, functionName: string, protocol = "tls", extractModulePath = true): (path: string) => void {
    let callbacks: any;
    const originalAttach = G.Interceptor.attach;
    G.Interceptor.attach = (_addr: any, cb: any) => { callbacks = cb; return { detach: () => { } }; };
    try {
        load(`/usr/lib/${functionName}.dylib`, `0x${(0x9000 + loaded.length).toString(16)}`);
        hookDynamicLoader(
            { platform: PLATFORM_DARWIN, platformLabel: "MacOS", loaderLibrary: new RegExp(functionName), functionName, extractModulePath } as any,
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

// WHY: `--protocol auto` recorded every SSL_read/SSL_write twice. The main pass
// ran under the selection label "auto"; installOhttpHooks then re-ran the TLS
// loader (initial scan + dlopen hook) under "tls". The module-level marker is
// keyed by the selection label, so the second pass did not see the first and
// re-installed the same OpenSSL row. The row-identity marker closes that gap.
test("a row installed under --protocol auto is not re-installed by a later tls pass (OHTTP re-run)", () => {
    const m = load(CELLAR, "0xa000");
    try {
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, new Set(["auto"]));
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "tls");
        assert.equal(openssl.calls.length, 1);
    } finally { unload(m); }
});

test("auto and tls dlopen hooks both firing for one load install the row once", () => {
    const m = load(CELLAR, "0xb000");
    try {
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        const autoLoader = dlopenHook(reg, "dlopen_auto_test", "auto");
        const tlsLoader = dlopenHook(reg, "dlopen_ohttp_test", "tls");
        autoLoader(SYMLINK);
        tlsLoader(SYMLINK);
        assert.equal(openssl.calls.length, 1);
    } finally { unload(m); }
});

test("a multi-protocol selection labelled by a non-tls protocol does not double the TLS row", () => {
    const m = load(CELLAR, "0xc000");
    try {
        const reg = new HookRegistry();
        const openssl = counter();
        opensslRow(reg, openssl.hookFn);
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "rc4,tls");
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "tls");
        assert.equal(openssl.calls.length, 1);
    } finally { unload(m); }
});

test("a row installed under auto still lets a different row on the module install later", () => {
    const m = load(CELLAR, "0xd000");
    try {
        const reg = new HookRegistry();
        const tls = counter();
        opensslRow(reg, tls.hookFn, "tls", "OpenSSL");
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "auto");
        const ssh = counter();
        opensslRow(reg, ssh.hookFn, "ssh", "OpenSSL (ssh row test)");
        ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "ssh");
        assert.equal(tls.calls.length, 1);
        assert.equal(ssh.calls.length, 1);
    } finally { unload(m); }
});

// Under --protocol auto, libssl matches the TLS row AND the RC4 key-hook row. The console
// line did not name the protocol (two identical "libssl found & will be hooked" lines), and
// library_detected was sent for RC4 even when its executor installed nothing (no -k): rc4
// was then reported as an idle protocol. An executor returning false is now not reported.
function captureSends(run: () => void): { consoles: string[]; detected: any[] } {
    const consoles: string[] = [];
    const detected: any[] = [];
    const original = G.send;
    G.send = (msg: any) => {
        if (msg?.contentType === "library_detected") detected.push(msg);
        else if (typeof msg?.console === "string") consoles.push(msg.console);
    };
    try { run(); } finally { G.send = original; }
    return { consoles, detected };
}

for (const [label, loader] of [["initial scan", "scan"], ["dlopen", "dlopen"]] as const) {
    test(`${label}: the console line names the protocol; a declining executor is neither announced nor reported`, () => {
        const m = load(CELLAR, label === "scan" ? "0x6000" : "0x7000");
        try {
            const reg = new HookRegistry();
            const rc4Calls: string[] = [];
            opensslRow(reg, () => { }, "tls", "OpenSSL");
            opensslRow(reg, (moduleName: string) => { rc4Calls.push(moduleName); return false; }, "rc4", "OpenSSL RC4");
            const { consoles, detected } = captureSends(() => {
                if (loader === "scan") ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "auto");
                else dlopenHook(reg, `dlopen_report_${label}`, "auto")(CELLAR);
            });
            assert.equal(rc4Calls.length, 1, "the RC4 executor still ran");
            assert.deepEqual(detected.map((d) => d.protocol), ["tls"]);
            const announced = consoles.filter((c) => c.includes("will be hooked"));
            assert.equal(announced.length, 1);
            assert.match(announced[0], /libssl\.3\.dylib (found|was loaded) & will be hooked on MacOS \(tls\)!/);
            // Recorded as handled: a rescan does not re-run the declined executor.
            ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", false, "auto");
            assert.equal(rc4Calls.length, 1);
        } finally { unload(m); }
    });
}

test("an executor returning true (or void) is reported under its own protocol", () => {
    const m = load(CELLAR, "0x8000");
    try {
        const reg = new HookRegistry();
        opensslRow(reg, () => { }, "tls", "OpenSSL");
        opensslRow(reg, () => true, "rc4", "OpenSSL RC4");
        const { consoles, detected } = captureSends(() =>
            ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "auto"));
        assert.deepEqual(detected.map((d) => d.protocol), ["tls", "rc4"]);
        assert.deepEqual(consoles.filter((c) => c.includes("will be hooked")).map((c) => c.match(/\((\w+)\)!$/)?.[1]), ["tls", "rc4"]);
    } finally { unload(m); }
});

// Pixel 5: the Android dynamic-loader config does not set extractModulePath, so
// library_detected carried path "" and the host could not tell GMS Cronet (mapped
// from com.google.android.gms-.../split_CronetDynamite_installtime.apk) from an
// embedded libcronet. The report now resolves the path itself.
for (const [label, extractModulePath] of [["without extractModulePath", false], ["with extractModulePath", true]] as const) {
    test(`dlopen ${label}: library_detected carries the mapped module path`, () => {
        const m = load(CELLAR, extractModulePath ? "0x9100" : "0x9200");
        try {
            const reg = new HookRegistry();
            opensslRow(reg, () => { }, "tls", "OpenSSL");
            const { detected } = captureSends(() =>
                dlopenHook(reg, `dlopen_path_${extractModulePath}`, "tls", extractModulePath)(CELLAR));
            assert.equal(detected.length, 1);
            assert.equal(detected[0].path, CELLAR);
        } finally { unload(m); }
    });
}

test("initial scan: library_detected carries the mapped module path", () => {
    const m = load(CELLAR, "0x9300");
    try {
        const reg = new HookRegistry();
        opensslRow(reg, () => { }, "tls", "OpenSSL");
        const { detected } = captureSends(() =>
            ssl_library_loader(PLATFORM_DARWIN, reg, ["libssl.3.dylib"], "MacOS", true, "tls"));
        assert.deepEqual(detected.map((d) => d.path), [CELLAR]);
    } finally { unload(m); }
});

test("loadedModulePath: the mapped path, or \"\" when unmapped or the lookup throws", () => {
    const m = load(CELLAR, "0x9400");
    try {
        assert.equal(loadedModulePath("libssl.3.dylib"), CELLAR);
    } finally { unload(m); }
    assert.equal(loadedModulePath("libssl.3.dylib"), "");
    const original = G.Process.findModuleByName;
    G.Process.findModuleByName = () => { throw new Error("boom"); };
    try {
        assert.equal(loadedModulePath("libssl.3.dylib"), "");
    } finally { G.Process.findModuleByName = original; }
});
