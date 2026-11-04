// Unit tests for the self-contained modern rustls path (--modern):
//  - dispatch: stripped → class-based patterns; symbolized → definition, falling back to
//    the modern class-based executor on a sync throw AND on an async rejection
//    (executeFromDefinition is async — a try/catch alone never sees its failure);
//  - gates: the class-based fallback installs no key hooks without -k;
//  - rustls-ffi builder hooks: new() returns the builder, new_custom() writes it through
//    its out-param (it returns a rustls_result) — the keylog callback must be set on the
//    builder, never on the status code;
//  - wiring: legacy rows use the legacy executor/class, modern rows the modern ones.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { installFakes, listener, addr, call } from "../../shared/write_hook_fakes.js";
import { setKeylogEnabled } from "../../shared/shared_structures.js";
import { RusTLS as ModernRusTLS, dispatchRustlsModern } from "../libs/rustls.js";
import { RusTLS as LegacyRusTLS } from "../../legacy/tls/libs/rustls.js";
import { Rustls_Linux_Modern } from "../platforms/linux/rustls_linux.js";
import { Rustls_Android_Modern } from "../platforms/android/rustls_android.js";
import { Rustls_Linux } from "../../legacy/tls/platforms/linux/rustls_linux.js";
import { Rustls_Android } from "../../legacy/tls/platforms/android/rustls_android.js";
import { createRustlsDefinition, rustlsBuilderOutArg } from "../definitions/rustls.js";

const G = globalThis as any;
const flush = () => new Promise((r) => setImmediate(r));

/** A fake pointer that also compares like a NativePointer (rustlsBuilderOutArg). */
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

function steps(over: Partial<{ symbolized: boolean; runDefinition: () => Promise<unknown> }> = {}) {
    const calls = { definition: 0, classBased: 0 };
    return {
        calls,
        steps: {
            symbolized: over.symbolized ?? true,
            runDefinition: () => { calls.definition++; return (over.runDefinition ?? (() => Promise.resolve(true)))(); },
            runClassBased: () => { calls.classBased++; },
        },
    };
}

test("dispatch: stripped module goes straight to the class-based pattern executor", () => {
    const { calls, steps: s } = steps({ symbolized: false });
    dispatchRustlsModern("librustls.so", s);
    assert.deepEqual(calls, { definition: 0, classBased: 1 });
});

test("dispatch: symbolized module uses the definition and no fallback when it succeeds", async () => {
    const { calls, steps: s } = steps();
    dispatchRustlsModern("librustls.so", s);
    await flush();
    assert.deepEqual(calls, { definition: 1, classBased: 0 });
});

// WHY: the old wrappers called executeFromDefinition without awaiting it, so a rejected
// promise (e.g. readAddresses throwing inside the async pipeline) never reached any fallback.
test("dispatch: an async definition failure (rejected promise) reaches the class-based fallback", async () => {
    const { calls, steps: s } = steps({ runDefinition: () => Promise.reject(new Error("resolve failed")) });
    dispatchRustlsModern("librustls.so", s);
    assert.equal(calls.classBased, 0, "fallback runs after the rejection, not eagerly");
    await flush();
    assert.deepEqual(calls, { definition: 1, classBased: 1 });
});

test("dispatch: a synchronous definition throw reaches the class-based fallback", () => {
    const { calls, steps: s } = steps({ runDefinition: () => { throw new Error("boom"); } });
    dispatchRustlsModern("librustls.so", s);
    assert.deepEqual(calls, { definition: 1, classBased: 1 });
});

test("dispatch: a throwing fallback is contained (no unhandled rejection)", async () => {
    let unhandled = 0;
    const onUnhandled = () => { unhandled++; };
    process.on("unhandledRejection", onUnhandled);
    try {
        dispatchRustlsModern("librustls.so", {
            symbolized: true,
            runDefinition: () => Promise.reject(new Error("x")),
            runClassBased: () => { throw new Error("class-based also failed"); },
        });
        await flush();
        await flush();
        assert.equal(unhandled, 0);
    } finally {
        process.off("unhandledRejection", onUnhandled);
    }
});

/** A modern platform hooker on a symbolized rustls-ffi module (addresses injected). */
function symbolizedHooker(Platform: any, moduleName: string): any {
    const hooker = new Platform(moduleName, "libc", false);
    hooker.addresses[moduleName] = {
        rustls_client_config_builder_new: addr(`${moduleName}_new`),
        rustls_client_config_builder_new_custom: addr(`${moduleName}_new_custom`),
        rustls_client_config_builder_set_key_log: addr(`${moduleName}_set_key_log`),
    };
    return hooker;
}

for (const [label, Platform] of [["Linux", Rustls_Linux_Modern], ["Android", Rustls_Android_Modern]] as const) {
    test(`modern ${label} class-based rustls: no key hooks without -k (symbol and pattern path)`, () => {
        const realAttach = G.Interceptor.attach;
        const findModule = G.Process.findModuleByName;
        let attached = 0;
        let scanned = 0;
        G.Interceptor.attach = () => { attached++; return { detach: () => { } }; };
        G.Process.findModuleByName = () => { scanned++; return null; };
        setKeylogEnabled(false);
        try {
            const hooker = symbolizedHooker(Platform, `librustls_nokeys_${label}.so`);
            hooker.execute_hooks();
            hooker.execute_pattern_hooks();
            assert.equal(attached, 0, "no Interceptor.attach");
            assert.equal(scanned, 0, "no pattern scan");
        } finally {
            setKeylogEnabled(true);
            G.Interceptor.attach = realAttach;
            G.Process.findModuleByName = findModule;
        }
    });
}

test("modern class-based rustls with -k: builder hooks inject our callback; new_custom via its out-param", () => withComparablePtr(() => {
    const setKeyLogCalls: any[][] = [];
    installFakes({ librustls_k_set_key_log: (...a: any[]) => { setKeyLogCalls.push(a); return 7000; } });
    setKeylogEnabled(true);
    const moduleName = "librustls_k";
    const hooker = new Rustls_Linux_Modern(moduleName, "libc", false);
    hooker.addresses[moduleName] = {
        rustls_client_config_builder_new: addr("librustls_k_new"),
        rustls_client_config_builder_new_custom: addr("librustls_k_new_custom"),
        rustls_client_config_builder_set_key_log: addr("librustls_k_set_key_log"),
    } as any;
    assert.equal(hooker.install_tls_keys_callback_hook(), true);
    assert.ok(listener("librustls_k_set_key_log"), "user-callback shadow attached");

    // new(): the builder is the return value.
    const builder = addr("builder_from_new");
    listener("librustls_k_new").onLeave.call({}, builder);
    assert.equal(setKeyLogCalls.at(-1)![0], builder);

    // new_custom() (rustls-ffi >= 0.13: provider, versions, len, builder_out) returns 7000.
    const custom = addr("builder_from_custom");
    const out: any = ptrLike(0x7fff0000, "builder_out");
    out.readPointer = () => custom;
    call("librustls_k_new_custom", [ptrLike(0x5000_0000), ptrLike(0x5000_1000), ptrLike(2), out], 7000);
    assert.equal(setKeyLogCalls.at(-1)![0], custom, "callback set on the builder, not on the status code");

    // A failing new_custom() leaves nothing to inject into.
    const before = setKeyLogCalls.length;
    call("librustls_k_new_custom", [ptrLike(0x5000_0000), ptrLike(0x5000_1000), ptrLike(2), out], 7001);
    assert.equal(setKeyLogCalls.length, before);
}));

test("rustlsBuilderOutArg: 4-arg (>= 0.13) and 5-arg (<= 0.10) new_custom layouts", () => withComparablePtr(() => {
    const out4 = ptrLike(0x7fff_0000, "out4");
    assert.equal(rustlsBuilderOutArg([ptrLike(0x1000_0000), ptrLike(0x2000_0000), ptrLike(2), out4] as any), out4);
    const out5 = ptrLike(0x7fff_1000, "out5");
    assert.equal(rustlsBuilderOutArg([ptrLike(0x1000_0000), ptrLike(9), ptrLike(0x2000_0000), ptrLike(2), out5] as any), out5);
}));

test("the rustls definition still targets the rustls-ffi API and installs keys only (no plaintext hooks)", () => {
    const def = createRustlsDefinition();
    assert.equal(def.libraryType, "rustls");
    assert.equal(def.keylog.kind, "custom");
    assert.equal(def.readHook, undefined, "rustls_connection_read_tls carries ciphertext");
    assert.equal(def.writeHook, undefined, "rustls_connection_write_tls carries ciphertext");
});

test("hooker classes: modern platforms extend the modern RusTLS, legacy platforms the legacy copy", () => {
    assert.equal(Object.getPrototypeOf(Rustls_Linux_Modern.prototype), ModernRusTLS.prototype);
    assert.equal(Object.getPrototypeOf(Rustls_Android_Modern.prototype), ModernRusTLS.prototype);
    assert.equal(Object.getPrototypeOf(Rustls_Linux.prototype), LegacyRusTLS.prototype);
    assert.equal(Object.getPrototypeOf(Rustls_Android.prototype), LegacyRusTLS.prototype);
});
