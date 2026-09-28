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
import { createKeylogCallbackTracker, restoreTrackedKeylogCallbacks } from "./keylog_callback_tracker.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

class FakePtr {
    constructor(private readonly value: string) { }
    toString() { return this.value; }
    isNull() { return this.value === "0x0"; }
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

G.Process.findModuleByName = (name: string) => {
    const symbols = modules.get(name);
    if (symbols === undefined) return null;
    const lookup = (sym: string) => (symbols[sym] !== undefined ? p(symbols[sym]) : null);
    return { name, findExportByName: lookup, findSymbolByName: lookup };
};
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

test("full symbols: up_ref keeps the CTX alive across one free; last free drops it", () => {
    trackerA.install(p("0xa3"));
    callHooked(modA["SSL_CTX_up_ref"], p("0xa3"));   // refs 2
    callHooked(modA["SSL_CTX_free"], p("0xa3"));     // refs 1 -> still tracked
    trackerA.install(p("0xa4"));
    callHooked(modA["SSL_CTX_free"], p("0xa4"));     // refs 0 -> dropped, never restored
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
    assert.ok(ctxField.get("0xa4")!.equals(OUR_CB));        // freed: left alone
    assert.ok(ctxField.get("0xa5")!.equals(APP_CB));        // restored to the app's cb
    assert.ok(ctxField.get("0xb1")!.isNull());              // no getter: blind restore
    assert.ok(ctxField.get("0xc1")!.equals(OUR_CB));        // untracked (no SSL_CTX_free)
    assert.ok(ctxField.get("0xd1")!.equals(OUR_CB));        // untracked (free hook failed)
    assert.deepEqual(result, { restored: 4, skipped: 1 });

    assert.equal(trackerA.sealed, true);
    trackerA.install(p("0xa6"));
    assert.equal(ctxField.has("0xa6"), false);
    assert.deepEqual(restoreTrackedKeylogCallbacks(), { restored: 0, skipped: 0 });
});
