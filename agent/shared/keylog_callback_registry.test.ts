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

test("an unobserved (inlined) up_ref: refs 0 restores via releaseLastRef, never a silent drop", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    const released: string[] = [];
    registry.recordInstall("0xctx", () => ({ previous: "appCb" })); // SSL_new, up_ref invisible
    registry.noteFree("0xctx", (e) => released.push(e.previous));  // SSL_free's release
    assert.deepEqual(released, ["appCb"]);                         // restored while alive
    assert.equal(registry.has("0xctx"), false);
    registry.recordInstall("0xctx", () => ({ previous: "appCb" })); // next SSL_new re-records
    assert.equal(registry.has("0xctx"), true);
});

test("fallback: install refs=1, two frees with inlined up_ref -> the CTX is still restored", () => {
    // Homebrew OpenSSL 3.x: SSL_new's up_ref is inlined, the install happens in
    // SSL_new's onLeave, so each connection's SSL_free brings refs 1 -> 0.
    const registry = new KeylogCallbackRegistry<Entry>();
    let restores = 0;
    const release = () => { restores++; };
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }));
    registry.noteFree("0xctx", release);
    registry.noteFree("0xctx", release);                           // already released: no-op
    assert.equal(restores, 1);
    assert.deepEqual(drainKeys(registry), []);                     // nothing left pointing at us
});

test("observed destruction: frees never drop the entry; detach restores it", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    let releases = 0;
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }), true);
    registry.noteFree("0xctx", () => { releases++; });
    registry.noteFree("0xctx", () => { releases++; });
    assert.equal(releases, 0);
    assert.equal(registry.has("0xctx"), true);
    assert.equal(registry.refsOf("0xctx"), 0);
    assert.deepEqual(drainKeys(registry), ["0xctx"]);
});

test("noteDestroyed drops the entry without restoring it", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }), true);
    registry.recordInstall("0xother", () => ({ previous: "NULL" }), true);
    registry.noteDestroyed("0xctx");
    registry.noteDestroyed("0xunknown");                           // untracked: ignored
    assert.deepEqual(drainKeys(registry), ["0xother"]);
});

test("a throwing releaseLastRef is swallowed and the entry is still removed", () => {
    const registry = new KeylogCallbackRegistry<Entry>();
    registry.recordInstall("0xctx", () => ({ previous: "NULL" }));
    registry.noteFree("0xctx", () => { throw new Error("access violation"); });
    assert.equal(registry.has("0xctx"), false);
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
