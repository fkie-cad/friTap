// Unit tests for the pure SSL_CTX keylog-callback registry behind the
// BoringSSL callback tier's teardown restore (A4 dangling-callback hazard).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { KeylogCallbackRegistry } from "./keylog_callback_registry.js";

interface Entry { previous: string }

function drainKeys(registry: KeylogCallbackRegistry<Entry>): string[] {
    const seen: string[] = [];
    registry.sealAndDrain((key) => { seen.push(key); return true; });
    return seen;
}

test("an installed CTX is restored with its first-seen previous callback", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0x1000", () => ({ previous: "appCb" }));
    registry.recordInstall("0x1000", () => ({ previous: "SHOULD-NOT-REPLACE" }));
    const restored: Array<[string, string]> = [];
    const result = registry.sealAndDrain((key, e) => { restored.push([key, e.previous]); return true; });
    assert.deepEqual(restored, [["0x1000", "appCb"]]);
    assert.deepEqual(result, { restored: 1, skipped: 0 });
});

test("a CTX created and freed once is never restored", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0x1000", () => ({ previous: "NULL" }));
    registry.noteFree("0x1000");
    assert.deepEqual(drainKeys(registry), []);
});

test("a long-lived CTX survives its connections' SSL_free (observed up_ref)", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0xctx", () => ({ previous: "NULL" })); // SSL_CTX_new
    for (let i = 0; i < 3; i++) {
        registry.recordInstall("0xctx", () => ({ previous: "NULL" })); // SSL_new(ctx)
        registry.noteUpRef("0xctx");                                  // SSL_new's up_ref
        registry.noteFree("0xctx");                                   // SSL_free -> SSL_CTX_free
    }
    assert.equal(registry.refsOf("0xctx"), 1);
    assert.deepEqual(drainKeys(registry), ["0xctx"]);
});

test("an unobserved (inlined) up_ref drops the entry early: fail-safe", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0xctx", () => ({ previous: "NULL" })); // SSL_new, up_ref invisible
    registry.noteFree("0xctx");                                   // SSL_free's release
    assert.equal(registry.has("0xctx"), false);
    registry.recordInstall("0xctx", () => ({ previous: "NULL" })); // next SSL_new re-records
    assert.equal(registry.has("0xctx"), true);
});

test("re-install never lowers a tracked refcount below what was observed", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }));
    registry.noteUpRef("0xctx");
    registry.noteUpRef("0xctx");
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }));
    assert.equal(registry.refsOf("0xctx"), 3);
});

test("up_ref and free of an untracked CTX are ignored", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.noteUpRef("0xdead");
    registry.noteFree("0xdead");
    assert.equal(registry.size, 0);
    assert.equal(registry.refsOf("0xdead"), 0);
});

test("the cap evicts the least recently installed entry and keeps the newest", () => {
    const registry = new KeylogCallbackRegistry<Entry>(2);
    registry.recordInstall("a", () => ({ previous: "NULL" }));
    registry.recordInstall("b", () => ({ previous: "NULL" }));
    registry.recordInstall("a", () => ({ previous: "NULL" })); // touch: a is now freshest
    registry.recordInstall("c", () => ({ previous: "NULL" })); // evicts b
    assert.deepEqual(drainKeys(registry).sort(), ["a", "c"]);
});

test("sealing blocks further installs and a second drain is empty", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("a", () => ({ previous: "NULL" }));
    assert.deepEqual(drainKeys(registry), ["a"]);
    assert.equal(registry.sealed, true);
    assert.equal(registry.recordInstall("b", () => ({ previous: "NULL" })), false);
    assert.deepEqual(registry.sealAndDrain(() => true), { restored: 0, skipped: 0 });
});

test("a throwing or refusing restore is counted as skipped and does not stop the drain", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    for (const k of ["a", "b", "c"]) registry.recordInstall(k, () => ({ previous: "NULL" }));
    const result = registry.sealAndDrain((key) => {
        if (key === "a") throw new Error("access violation");
        return key !== "b";
    });
    assert.deepEqual(result, { restored: 1, skipped: 2 });
    assert.equal(registry.size, 0);
});

test("the entry factory runs only once per CTX", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    let calls = 0;
    const make = () => { calls++; return { previous: "NULL" }; };
    registry.recordInstall("a", make);
    registry.recordInstall("a", make);
    assert.equal(calls, 1);
});

test("a cap below 1 is rejected", () => {
    assert.throws(() => new KeylogCallbackRegistry<Entry>(0));
});
