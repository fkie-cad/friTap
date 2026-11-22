// Unit tests for the pre-shutdown flush registry (pre_shutdown.ts) and its
// place in releaseAgentHooks (fritap_agent.ts).
//
// Run: npm run test:agent
//
// WHY: every send is dropped once releaseAgentHooks sets the shutdown flag, so
// data an agent module still holds (QUIC bodies awaiting their stream id) must
// be flushed before it.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { registerPreShutdownFlush, runPreShutdownFlushes } from "./pre_shutdown.js";
import { registerDetachTeardown, runDetachTeardowns } from "./detach_teardown.js";

test("flushes run in registration order; a throwing flush does not stop the rest", () => {
    runPreShutdownFlushes();
    const order: string[] = [];
    registerPreShutdownFlush(() => order.push("a"));
    registerPreShutdownFlush(() => { throw new Error("boom"); });
    registerPreShutdownFlush(() => order.push("c"));
    assert.doesNotThrow(() => runPreShutdownFlushes());
    assert.deepEqual(order, ["a", "c"]);
});

test("the registry is emptied after a run", () => {
    let calls = 0;
    registerPreShutdownFlush(() => calls++);
    runPreShutdownFlushes();
    runPreShutdownFlushes();
    assert.equal(calls, 1);
});

test("detach teardowns run in reverse install order, isolated, once", () => {
    runDetachTeardowns();
    const order: string[] = [];
    registerDetachTeardown("a", () => order.push("a"));
    registerDetachTeardown("b", () => { throw new Error("boom"); });
    registerDetachTeardown("c", () => order.push("c"));
    assert.doesNotThrow(() => runDetachTeardowns());
    runDetachTeardowns();
    assert.deepEqual(order, ["c", "a"]);
});

test("releaseAgentHooks runs the flushes before it sets the shutdown flag", () => {
    const source = readFileSync(fileURLToPath(new URL("../fritap_agent.ts", import.meta.url)), "utf8");
    const start = source.indexOf("function releaseAgentHooks(): DetachReport {");
    assert.ok(start >= 0);
    const body = source.slice(start, source.indexOf("\n}\n", start));
    const flush = body.indexOf("runPreShutdownFlushes()");
    const flag = body.indexOf("setIsShuttingDown(true)");
    assert.ok(flush >= 0 && flag >= 0 && flush < flag);
});
