// Unit tests for the Frida glue in keylog_callback_tracker.ts, focused on how it
// degrades when a module lacks the optional symbols (LibreSSL-style builds with
// no SSL_CTX_get_keylog_callback / SSL_CTX_up_ref, a missing SSL_CTX_free, or a
// free hook that cannot be attached).
//
// Run: npm run test:agent  (node --import tsx --test agent/shared/keylog_callback_tracker.test.ts)
//
// The registry is module-global and restoreTrackedKeylogCallbacks() seals it
// for good, so every scenario installs first and the single restore runs in the
// last test. node:test runs the tests of one file in declaration order.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Memory/Interceptor/etc. BEFORE the module loads.
import "./frida-test-stubs.js";
// Reads the Frida globals only at call time, so the per-test overrides below apply.
import {
    createKeylogCallbackTracker, restoreTrackedKeylogCallbacks, retainedKeylogCallbackCount, sslCtxExDataClassIndex,
} from "./keylog_callback_tracker.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

class FakePtr {
    constructor(private readonly value: string) { }
    toString() { return this.value; }
    isNull() { return this.value === "0x0"; }
    toInt32() { return parseInt(this.value, 16) | 0; }
    equals(other: any) { return other !== null && other !== undefined && other.toString() === this.value; }
}
const p = (v: string) => new FakePtr(v);
G.NULL = p("0x0");

// ── Fake native world ──────────────────────────────────────────────────────
// ctx address -> keylog callback currently stored in it.
const ctxField = new Map<string, FakePtr>();
// function address -> JS implementation behind a NativeFunction.
const nativeImpl = new Map<string, (...args: any[]) => any>();
// function address -> attached onEnter listeners.
const listeners = new Map<string, Array<(args: any[]) => void>>();
const attachThrowsFor = new Set<string>();
// module name -> { symbol name -> address }.
const modules = new Map<string, Record<string, string>>();
// module name -> imports reported by enumerateImports() (absent = no such API).
const moduleImports = new Map<string, Array<{ name: string; address?: FakePtr; module?: string }>>();

function fakeModule(name: string): any {
    const symbols = modules.get(name);
    if (symbols === undefined) return null;
    const lookup = (sym: string) => (symbols[sym] !== undefined ? p(symbols[sym]) : null);
    const mod: any = { name, path: `/fake/lib/${name}`, findExportByName: lookup, findSymbolByName: lookup };
    const imports = moduleImports.get(name);
    if (imports !== undefined) mod.enumerateImports = () => imports;
    return mod;
}
G.Process.findModuleByName = (name: string) => fakeModule(name);
G.Process.findModuleByAddress = (address: FakePtr) => {
    for (const [name, symbols] of modules) {
        if (Object.values(symbols).includes(address.toString())) return fakeModule(name);
    }
    return null;
};
G.Process.enumerateModules = () => Array.from(modules.keys()).map(fakeModule);
G.NativeFunction = function (address: FakePtr) {
    const impl = nativeImpl.get(address.toString());
    if (impl === undefined) throw new Error(`no native impl at ${address}`);
    return impl;
};
G.Interceptor.attach = (address: FakePtr, callbacks: { onEnter?: (args: any[]) => void }) => {
    const key = address.toString();
    if (attachThrowsFor.has(key)) throw new Error(`cannot attach ${key}`);
    const list = listeners.get(key) ?? [];
    if (callbacks.onEnter) list.push(callbacks.onEnter);
    listeners.set(key, list);
    return { detach: () => { } };
};

/** Simulate a native call to `address` passing through any attached hooks. */
function callHooked(address: string, ...args: FakePtr[]): void {
    for (const onEnter of listeners.get(address) ?? []) onEnter(args);
}

/** Register a fake OpenSSL-like module. Pass only the symbols it should have. */
function defineModule(name: string, base: number, symbols: string[]): Record<string, string> {
    const table: Record<string, string> = {};
    symbols.forEach((sym, i) => { table[sym] = "0x" + (base + i * 0x10).toString(16); });
    modules.set(name, table);
    nativeImpl.set(table["SSL_CTX_set_keylog_callback"], (ctx: FakePtr, cb: FakePtr) => {
        ctxField.set(ctx.toString(), cb);
    });
    if (table["SSL_CTX_get_keylog_callback"] !== undefined) {
        nativeImpl.set(table["SSL_CTX_get_keylog_callback"], (ctx: FakePtr) => ctxField.get(ctx.toString()) ?? G.NULL);
    }
    return table;
}

const FULL = ["SSL_CTX_set_keylog_callback", "SSL_CTX_get_keylog_callback", "SSL_CTX_free", "SSL_CTX_up_ref"];

/** A fake libcrypto exporting `symbols`; OpenSSL_version_num returns `version`. */
function defineLibcrypto(name: string, base: number, symbols: string[], version: number): Record<string, string> {
    const table: Record<string, string> = {};
    symbols.forEach((sym, i) => { table[sym] = "0x" + (base + i * 0x10).toString(16); });
    modules.set(name, table);
    if (table["OpenSSL_version_num"] !== undefined) nativeImpl.set(table["OpenSSL_version_num"], () => version);
    return table;
}

const OUR_CB = p("0xc0de");
const APP_CB = p("0xa99");

// Scenario A: full BoringSSL-like symbol set.
const modA = defineModule("libA.so", 0x1000, FULL);
const trackerA = createKeylogCallbackTracker("libA.so", p(modA["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
// Scenario B: LibreSSL-like, no getter and no up_ref.
const modB = defineModule("libB.dylib", 0x2000, ["SSL_CTX_set_keylog_callback", "SSL_CTX_free"]);
const trackerB = createKeylogCallbackTracker("libB.dylib", p(modB["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
// Scenario C: SSL_CTX_free unresolvable -> no lifetime tracking.
const modC = defineModule("libC.so", 0x3000, ["SSL_CTX_set_keylog_callback", "SSL_CTX_get_keylog_callback"]);
const trackerC = createKeylogCallbackTracker("libC.so", p(modC["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
// Scenario D: SSL_CTX_free exists but Interceptor.attach on it throws.
const modD = defineModule("libD.so", 0x4000, FULL);
attachThrowsFor.add(modD["SSL_CTX_free"]);
// Scenario E: Homebrew OpenSSL 3.x -- libssl imports CRYPTO_free_ex_data from
// a separate libcrypto: destruction is observed (F1), SSL_CTX_up_ref inlined.
const cryptoE = defineLibcrypto("libcrypto.3.dylib", 0x5000, ["CRYPTO_free_ex_data", "OpenSSL_version_num"], 0x30600040);
moduleImports.set("libssl.3.dylib", [
    { name: "CRYPTO_free", module: "/fake/lib/libcrypto.3.dylib" },
    { name: "CRYPTO_free_ex_data", address: p(cryptoE["CRYPTO_free_ex_data"]), module: "/fake/lib/libcrypto.3.dylib" },
]);
const modE = defineModule("libssl.3.dylib", 0x6000, FULL);
const trackerE = createKeylogCallbackTracker("libssl.3.dylib", p(modE["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
// Scenario F: BoringSSL shared libcrypto (Android system libssl.so): the marker
// export rules F1 out, the refcount fallback restores at refs 0.
const cryptoF = defineLibcrypto("libcrypto.so", 0x7000,
    ["CRYPTO_free_ex_data", "OpenSSL_version_num", "CRYPTO_BUFFER_new"], 0x1010107f);
moduleImports.set("libssl.so", [{ name: "CRYPTO_free_ex_data", address: p(cryptoF["CRYPTO_free_ex_data"]) }]);
const modF = defineModule("libssl.so", 0x8000, FULL);
const trackerF = createKeylogCallbackTracker("libssl.so", p(modF["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
let trackerD: any = null;
let trackerDError: unknown = null;
try {
    trackerD = createKeylogCallbackTracker("libD.so", p(modD["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
} catch (e) {
    trackerDError = e;
}

test("full symbols: install writes our callback and hooks free + up_ref once", () => {
    trackerA.install(p("0xa1"));
    trackerA.install(p("0xa2"));
    assert.ok(ctxField.get("0xa1")!.equals(OUR_CB));
    assert.equal(listeners.get(modA["SSL_CTX_free"])!.length, 1);
    assert.equal(listeners.get(modA["SSL_CTX_up_ref"])!.length, 1);
    // A second tracker on the same module must not double-hook.
    createKeylogCallbackTracker("libA.so", p(modA["SSL_CTX_set_keylog_callback"]), OUR_CB, true);
    assert.equal(listeners.get(modA["SSL_CTX_free"])!.length, 1);
});

test("full symbols: up_ref keeps the CTX alive across one free; refs 0 restores in SSL_CTX_free", () => {
    trackerA.install(p("0xa3"));
    callHooked(modA["SSL_CTX_up_ref"], p("0xa3"));   // refs 2
    callHooked(modA["SSL_CTX_free"], p("0xa3"));     // refs 1 -> still tracked
    assert.ok(ctxField.get("0xa3")!.equals(OUR_CB));
    trackerA.install(p("0xa4"));
    callHooked(modA["SSL_CTX_free"], p("0xa4"));     // refs 0 -> restored now (CTX alive in onEnter)
    assert.ok(ctxField.get("0xa4")!.isNull());
});

test("observed destruction (OpenSSL 3.x libcrypto): frees with inlined up_ref keep the CTX tracked", () => {
    assert.equal(listeners.get(cryptoE["CRYPTO_free_ex_data"])!.length, 1);
    trackerE.install(p("0xe1"));
    callHooked(modE["SSL_CTX_free"], p("0xe1"));     // connection 1's SSL_free
    callHooked(modE["SSL_CTX_free"], p("0xe1"));     // connection 2's SSL_free
    assert.ok(ctxField.get("0xe1")!.equals(OUR_CB)); // still ours, still tracked
    trackerE.install(p("0xe2"));
    callHooked(cryptoE["CRYPTO_free_ex_data"], p("0x0"), p("0xe1"));  // CRYPTO_EX_INDEX_SSL: ignored
    callHooked(cryptoE["CRYPTO_free_ex_data"], p("0x1"), p("0xe2"));  // final SSL_CTX_free of 0xe2
});

test("BoringSSL libcrypto: no destruction hook, refcount fallback restores at refs 0", () => {
    assert.equal(listeners.get(cryptoF["CRYPTO_free_ex_data"]), undefined);
    trackerF.install(p("0xf1"));
    callHooked(modF["SSL_CTX_free"], p("0xf1"));
    assert.ok(ctxField.get("0xf1")!.isNull());
});

test("class index policy: only OpenSSL 1.1.0 .. 3.x without BoringSSL markers", () => {
    const none = () => false;
    assert.equal(sslCtxExDataClassIndex(none, 0x30600040), 1);
    assert.equal(sslCtxExDataClassIndex(none, 0x1010117f), 1);
    assert.equal(sslCtxExDataClassIndex(none, 0x1000214f), null);   // 1.0.2: index 2
    assert.equal(sslCtxExDataClassIndex(none, 0x20000000), null);   // LibreSSL
    assert.equal(sslCtxExDataClassIndex(none, 0x40000000), null);   // 4.x: unverified
    assert.equal(sslCtxExDataClassIndex(none, null), null);
    assert.equal(sslCtxExDataClassIndex((n) => n === "CRYPTO_BUFFER_new", 0x1010107f), null);
});

test("every keylog callback handed to a tracker is retained once, for the script's lifetime", () => {
    const before = retainedKeylogCallbackCount();
    assert.equal(before, 1);                          // all scenarios share OUR_CB
    createKeylogCallbackTracker("libA.so", p(modA["SSL_CTX_set_keylog_callback"]), p("0xbeef"), true);
    assert.equal(retainedKeylogCallbackCount(), 2);
});

test("null ctx is ignored", () => {
    trackerA.install(G.NULL);
    assert.equal(ctxField.has("0x0"), false);
});

test("noteAppCallback remembers the app's callback as the one to restore", () => {
    trackerA.install(p("0xa5"));
    trackerA.noteAppCallback(p("0xa5"), APP_CB);
    // Our own callback passing through the setter hook must not be recorded.
    trackerA.noteAppCallback(p("0xa5"), OUR_CB);
});

test("no getter, no up_ref (LibreSSL-like): install still works, no up_ref hook", () => {
    trackerB.install(p("0xb1"));
    assert.ok(ctxField.get("0xb1")!.equals(OUR_CB));
    assert.equal(listeners.get(modB["SSL_CTX_free"])!.length, 1);
});

test("no SSL_CTX_free: callback still installed, nothing tracked", () => {
    trackerC.install(p("0xc1"));
    assert.ok(ctxField.get("0xc1")!.equals(OUR_CB));
});

test("free hook attach failure does not throw and keeps the keylog tier working", () => {
    assert.equal(trackerDError, null);
    trackerD.install(p("0xd1"));
    assert.ok(ctxField.get("0xd1")!.equals(OUR_CB));
    // No up_ref hook is attached when the free hook failed.
    assert.equal(listeners.get(modD["SSL_CTX_up_ref"]), undefined);
});

test("restore puts previous callbacks back and seals the registry", () => {
    // 0xa2: app replaced our callback after install -> getter check skips it.
    ctxField.set("0xa2", APP_CB);
    const result = restoreTrackedKeylogCallbacks();

    assert.ok(ctxField.get("0xa1")!.isNull());              // restored to NULL
    assert.ok(ctxField.get("0xa2")!.equals(APP_CB));        // skipped: not ours
    assert.ok(ctxField.get("0xa3")!.isNull());              // alive via up_ref, restored
    assert.ok(ctxField.get("0xa4")!.isNull());              // restored at refs 0, not re-drained
    assert.ok(ctxField.get("0xa5")!.equals(APP_CB));        // restored to the app's cb
    assert.ok(ctxField.get("0xb1")!.isNull());              // no getter: blind restore
    assert.ok(ctxField.get("0xc1")!.equals(OUR_CB));        // untracked (no SSL_CTX_free)
    assert.ok(ctxField.get("0xd1")!.equals(OUR_CB));        // untracked (free hook failed)
    assert.ok(ctxField.get("0xe1")!.isNull());              // live CTX (F1): restored
    assert.ok(ctxField.get("0xe2")!.equals(OUR_CB));        // destroyed (F1): left alone
    assert.ok(ctxField.get("0xf1")!.isNull());              // restored earlier at refs 0
    assert.deepEqual(result, { restored: 5, skipped: 1 });
    assert.equal(retainedKeylogCallbackCount(), 2);         // detach never releases them

    assert.equal(trackerA.sealed, true);
    trackerA.install(p("0xa6"));
    assert.equal(ctxField.has("0xa6"), false);
    assert.deepEqual(restoreTrackedKeylogCallbacks(), { restored: 0, skipped: 0 });
});
