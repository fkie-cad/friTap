// Unit tests for the shared holding-queue timer (hold_timer.ts).
//
// Run: npm run test:agent
//
// WHY: the body queue and the egress hold share the timer arming, the
// never-throw timeout and the pre-shutdown registration.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { HoldClock, HoldTimer } from "./hold_timer.js";
import { runPreShutdownFlushes } from "../../shared/pre_shutdown.js";

function fakeClock(timeoutMs = 100) {
    const armed = new Map<number, { fn: () => void; ms: number }>();
    let next = 1;
    const state = { shuttingDown: false };
    const clock: HoldClock = {
        timeoutMs,
        now: () => 0,
        schedule: (fn, ms) => { armed.set(next, { fn, ms }); return next++; },
        cancel: (h) => { armed.delete(h as number); },
        isShuttingDown: () => state.shuttingDown,
    };
    const fire = () => { const [h, t] = [...armed][0]; armed.delete(h); t.fn(); };
    return { clock, armed, state, fire };
}

function newTimer(onDue: () => void = () => {}) {
    const c = fakeClock();
    const flushed: number[] = [];
    const timer = new HoldTimer(c.clock, onDue, () => flushed.push(1));
    return { ...c, timer, flushed };
}

test("sync arms once per holding period with the clock's timeout or an explicit delay", () => {
    const { timer, armed } = newTimer();
    timer.sync(true);
    timer.sync(true, 5);
    assert.deepEqual([...armed.values()].map((t) => t.ms), [100]);
    timer.sync(false);
    assert.equal(armed.size, 0);
    timer.sync(true, 5);
    assert.deepEqual([...armed.values()].map((t) => t.ms), [5]);
});

test("restart re-arms from now", () => {
    const { timer, armed } = newTimer();
    timer.sync(true, 5);
    timer.restart(true);
    assert.deepEqual([...armed.values()].map((t) => t.ms), [100]);
    timer.restart(false);
    assert.equal(timer.armed, false);
});

test("the timeout runs onDue, not during shutdown, and never throws", () => {
    let due = 0;
    const t = newTimer(() => { due++; throw new Error("boom"); });
    t.timer.sync(true);
    assert.doesNotThrow(() => t.fire());
    assert.equal(due, 1);
    assert.equal(t.timer.armed, false);
    t.timer.sync(true);
    t.state.shuttingDown = true;
    t.fire();
    assert.equal(due, 1);
    t.timer.cancel();
});

test("the pre-shutdown flush is registered once per timer, held or not", () => {
    runPreShutdownFlushes();
    const t = newTimer();
    t.timer.sync(true);
    t.timer.sync(false);
    t.timer.sync(true);
    runPreShutdownFlushes();
    assert.deepEqual(t.flushed, [1]);
});
