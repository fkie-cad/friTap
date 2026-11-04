// Unit tests for the legacy (default path) rustls-ffi keylog hooks:
//  - the constructor maps the rustls-ffi exports by their EXACT names (wildcards were keyed
//    under "*name" by readAddresses, so the by-name lookups found nothing → 0 keys);
//  - rustls_client_config_builder_new() returns the builder; _new_custom() returns a
//    rustls_result and writes the builder through its out-parameter — the keylog callback
//    must be set on the builder, never on the status code;
//  - an application-installed callback is shadowed once (not per builder, not our own cb).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { installFakes, listener, addr, call } from "../../../shared/write_hook_fakes.js";
import { RusTLS, legacyRustlsBuilderOutArg, isLegacyRustlsOk } from "./rustls.js";
import { Rustls_Linux } from "../platforms/linux/rustls_linux.js";
import { Rustls_Android } from "../platforms/android/rustls_android.js";

const G = globalThis as any;

const FFI_EXPORTS = [
    "rustls_connection_write_tls", "rustls_connection_read_tls", "rustls_client_config_builder_new",
    "rustls_client_config_builder_new_custom", "rustls_client_config_builder_set_key_log",
];

/** A fake pointer that also compares like a NativePointer (legacyRustlsBuilderOutArg). */
function ptrLike(value: number, name = `p${value}`): any {
    const p = addr(name);
    p.value = value;
    p.compare = (o: any) => Math.sign(value - Number(o.value));
    return p;
}

/** Run `fn` with ptr() returning comparable values (the shared stub drops the value). */
function withComparablePtr(fn: () => void): void {
    const realPtr = G.ptr;
    G.ptr = (v: any) => ptrLike(Number(v));
    try { fn(); } finally { G.ptr = realPtr; }
}

function symbolizedHooker(Platform: any, moduleName: string): any {
    const hooker = new Platform(moduleName, "libc", false);
    hooker.addresses[moduleName] = {
        rustls_client_config_builder_new: addr(`${moduleName}_new`),
        rustls_client_config_builder_new_custom: addr(`${moduleName}_new_custom`),
        rustls_client_config_builder_set_key_log: addr(`${moduleName}_set_key_log`),
    };
    return hooker;
}

test("legacy RusTLS maps the rustls-ffi exports by exact name (no wildcards)", () => {
    const realGetModule = G.Process.getModuleByName;
    G.Process.getModuleByName = () => ({ enumerateExports: () => FFI_EXPORTS.map((name) => ({ name })) });
    let hooker: any;
    try {
        hooker = new RusTLS("librustls_names.so", "libc", false);
    } catch {
        // readAddresses may fail on the stubbed module; the mapping is set before it.
    } finally {
        G.Process.getModuleByName = realGetModule;
    }
    const mapping = hooker?.library_method_mapping ?? {};
    assert.deepEqual(mapping["*librustls_names.so*"], FFI_EXPORTS);
});

for (const [label, Platform] of [["Linux", Rustls_Linux], ["Android", Rustls_Android]] as const) {
    test(`legacy ${label} rustls-ffi: new() and new_custom() (out-param) both get our keylog callback`, () => withComparablePtr(() => {
        const moduleName = `librustls_legacy_${label}`;
        const setKeyLogCalls: any[][] = [];
        installFakes({ [`${moduleName}_set_key_log`]: (...a: any[]) => { setKeyLogCalls.push(a); return 7000; } });
        const hooker = symbolizedHooker(Platform, moduleName);
        assert.equal(hooker.install_tls_keys_callback_hook(), true);

        const builder = addr("builder_from_new");
        listener(`${moduleName}_new`).onLeave.call({}, builder);
        assert.equal(setKeyLogCalls.at(-1)![0], builder);
        assert.equal(setKeyLogCalls.at(-1)![1], RusTLS.keyLogCB);

        // rustls-ffi >= 0.13: (provider, tls_versions, len, builder_out) → rustls_result.
        const custom = addr("builder_from_custom");
        const out: any = ptrLike(0x7fff0000, "builder_out");
        out.readPointer = () => custom;
        call(`${moduleName}_new_custom`, [ptrLike(0x5000_0000), ptrLike(0x5000_1000), ptrLike(2), out], 7000);
        assert.equal(setKeyLogCalls.at(-1)![0], custom, "callback set on the builder, not on the status code");

        const before = setKeyLogCalls.length;
        call(`${moduleName}_new_custom`, [ptrLike(0x5000_0000), ptrLike(0x5000_1000), ptrLike(2), out], 7001);
        assert.equal(setKeyLogCalls.length, before, "failed new_custom: nothing injected");
    }));
}

test("legacy rustls-ffi: an application callback is shadowed once, our own callback never", () => withComparablePtr(() => {
    const moduleName = "librustls_legacy_shadow";
    installFakes({ [`${moduleName}_set_key_log`]: () => 7000 });
    const hooker = symbolizedHooker(Rustls_Linux, moduleName);
    hooker.install_tls_keys_callback_hook();

    const attachedAt: string[] = [];
    const realAttach = G.Interceptor.attach;
    G.Interceptor.attach = (target: any, cb: any) => { attachedAt.push(String(target)); return realAttach(target, cb); };
    try {
        const userCb = addr("app_keylog_cb");
        call(`${moduleName}_set_key_log`, [addr("b1"), userCb, addr("ud")], 7000);
        call(`${moduleName}_set_key_log`, [addr("b2"), userCb, addr("ud")], 7000);
        assert.deepEqual(attachedAt, ["0xapp_keylog_cb"]);
        call(`${moduleName}_set_key_log`, [addr("b3"), addr("other_cb"), addr("ud")], 7001);
        assert.deepEqual(attachedAt, ["0xapp_keylog_cb"], "failed set_key_log: not shadowed");
    } finally {
        G.Interceptor.attach = realAttach;
    }
}));

test("legacy rustls-ffi helpers: out-param layouts and status codes", () => withComparablePtr(() => {
    const out4 = ptrLike(0x7fff_0000, "out4");
    assert.equal(legacyRustlsBuilderOutArg([ptrLike(0x1000_0000), ptrLike(0x2000_0000), ptrLike(2), out4] as any), out4);
    const out5 = ptrLike(0x7fff_1000, "out5");
    assert.equal(legacyRustlsBuilderOutArg([ptrLike(0x1000_0000), ptrLike(9), ptrLike(0x2000_0000), ptrLike(2), out5] as any), out5);
    assert.equal(isLegacyRustlsOk(7000), true);
    assert.equal(isLegacyRustlsOk(0), true);
    assert.equal(isLegacyRustlsOk(7001), false);
}));
