// Tests for releaseAgentHooks (fritap_agent.ts) as seen through the
// gracefulDetach / dispose RPC exports: the DetachReport v1 it returns, its
// step order, log capture after the shutdown flag, and run-once idempotency.
//
// Run: npm run test:agent
//
// Single test on purpose: releaseAgentHooks runs once per process (node:test
// runs each file in its own process), so the sequence is asserted in order.

import "./frida-test-stubs.js";
import { test } from "node:test";
import assert from "node:assert/strict";
import "../fritap_agent.js";
import { registerDetachTeardown } from "./detach_teardown.js";
import { registerPreShutdownFlush } from "./pre_shutdown.js";
import { log } from "../util/log.js";

const G = globalThis as any;

test("gracefulDetach returns a v1 report once; dispose and later calls get repeat:true", () => {
    const sent: any[] = [];
    G.send = (m: any) => sent.push(m);
    const markers = () => sent.flatMap((m) => m.detach_progress ? [m.detach_progress] : []);
    G.Interceptor.detachAll = () => {
        assert.deepEqual(markers().at(-1), { phase: "started", step: "interceptor-detach-all" });
        throw new Error("detach failed");
    };
    registerPreShutdownFlush(() => log("flushed before the flag"));
    registerDetachTeardown("probe", () => { log("inside teardown"); return { owned: 1 }; });

    const report = G.rpc.exports.gracefulDetach();

    assert.equal(report.version, 1);
    assert.equal(report.repeat, false);
    assert.deepEqual(JSON.parse(JSON.stringify(report)), report);
    const names: string[] = report.steps.map((s: any) => s.name);
    assert.deepEqual(markers(), [
        { phase: "entered", step: undefined },
        ...names.flatMap((step) => [{ phase: "started", step }, { phase: "finished", step }]),
    ]);
    assert.equal(names[0], "pre-shutdown-flush");
    assert.deepEqual(names.slice(-3), ["keylog-callbacks-restore", "interceptor-detach-all", "anchor-keylog-fields-restore"]);
    const probe = report.steps.find((s: any) => s.name === "teardown:probe");
    assert.deepEqual(probe.summary, { owned: 1 });
    assert.ok(names.indexOf("teardown:probe") < names.indexOf("keylog-callbacks-restore"));
    const detach = report.steps.find((s: any) => s.name === "interceptor-detach-all");
    assert.equal(detach.ok, false);
    assert.equal(detach.error, "Error: detach failed");
    // The flush ran before the flag (sent normally); the teardown log was captured.
    assert.ok(sent.some((m) => m.console === "flushed before the flag"));
    assert.ok(report.logs.some((l: any) => l.level === "info" && l.msg === "inside teardown"));
    assert.ok(report.logs.some((l: any) => l.msg.includes("Interceptor.detachAll threw")));
    assert.equal(sent.some((m) => m.console === "inside teardown"), false);

    const repeat = { version: 1, repeat: true, steps: [], logs: [], dropped_logs: 0, total_ms: 0 };
    assert.deepEqual(G.rpc.exports.gracefulDetach(), repeat);
    const beforeDispose = markers();
    assert.doesNotThrow(() => G.rpc.exports.dispose());
    assert.deepEqual(markers(), beforeDispose);
    // Capture scope is closed after the transaction: a late log is dropped, not captured.
    log("late");
    assert.equal(sent.some((m) => m.console === "late"), false);
});
