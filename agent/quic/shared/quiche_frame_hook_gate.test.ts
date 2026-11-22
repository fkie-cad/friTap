// Unit tests for the STREAM-frame install outcome gate (quiche_frame_hook_gate.ts).
//
// Run: npm run test:agent
//
// WHY: the body hooks must attach when the symbols resolve, not when the slow
// frame locator finishes; only the Readv decision needs the settled outcome.

import { test } from "node:test";
import assert from "node:assert/strict";
import { FrameHookGate } from "./quiche_frame_hook_gate.js";

function deferred<T>(): { promise: Promise<T>; resolve(v: T): void; reject(e: unknown): void } {
    let resolve!: (v: T) => void;
    let reject!: (e: unknown) => void;
    const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej; });
    return { promise, resolve, reject };
}

/** Mirrors installGoogleQuicheHooks: body attach after symbols, Readv after the frame outcome. */
async function installOrder(frames: Promise<boolean>, symbols: Promise<string>, events: string[]): Promise<void> {
    const gate = new FrameHookGate(frames);
    const resolved = await symbols;
    events.push(`bodies:${resolved}`);
    const readBodyGate = () => gate.hooked;
    events.push(`body-sees:${readBodyGate()}`);
    const frameHooked = await gate.settled();
    events.push(`readv-decision:${frameHooked}`);
    events.push(`body-sees:${readBodyGate()}`);
}

test("body hooks attach when symbols resolve while the frame install is pending", async () => {
    const frames = deferred<boolean>();
    const symbols = deferred<string>();
    const events: string[] = [];
    const done = installOrder(frames.promise, symbols.promise, events);
    symbols.resolve("resolved");
    await new Promise((r) => setImmediate(r));
    assert.deepEqual(events, ["bodies:resolved", "body-sees:false"]);  // Readv not decided yet
    frames.resolve(true);
    await done;
    assert.deepEqual(events, ["bodies:resolved", "body-sees:false", "readv-decision:true", "body-sees:true"]);
});

test("the Readv decision awaits the frame outcome even when frames lose", async () => {
    const frames = deferred<boolean>();
    const events: string[] = [];
    const done = installOrder(frames.promise, Promise.resolve("r"), events);
    await new Promise((r) => setImmediate(r));
    assert.equal(events.some((e) => e.startsWith("readv-decision")), false);
    frames.resolve(false);
    await done;
    assert.ok(events.includes("readv-decision:false"));
});

test("hooked reads the outcome at call time", async () => {
    const frames = deferred<boolean>();
    const gate = new FrameHookGate(frames.promise);
    assert.equal(gate.hooked, false);
    frames.resolve(true);
    assert.equal(await gate.settled(), true);
    assert.equal(gate.hooked, true);
});

test("a rejected frame install is not unhandled and rejects settled()", async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (e: unknown) => { unhandled.push(e); };
    process.on("unhandledRejection", onUnhandled);
    try {
        const gate = new FrameHookGate(Promise.reject(new Error("locator failed")));
        await new Promise((r) => setImmediate(r));
        await new Promise((r) => setImmediate(r));
        assert.deepEqual(unhandled, []);
        assert.equal(gate.hooked, false);
        await assert.rejects(gate.settled(), /locator failed/);
    } finally {
        process.off("unhandledRejection", onUnhandled);
    }
});
