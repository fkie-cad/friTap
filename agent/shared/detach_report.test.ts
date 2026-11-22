// Unit tests for the DetachReport builder, the teardown log capture scope
// (log, devlog and the leveled devlog_* helpers) and the labelled
// detach-teardown registry (detach_report.ts, util/log.ts, detach_teardown.ts).
//
// Run: npm run test:agent
//
// WHY: once the shutdown flag is set every send is dropped, so a teardown that
// fails or skips sockets used to leave no trace. The report returned by the
// gracefulDetach RPC is the only channel that still reaches the host.

import "./frida-test-stubs.js";
import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import {
    DetachReportBuilder, DETACH_LOG_LIMIT, DETACH_TEXT_LIMIT,
    beginTeardownCapture, endTeardownCapture, withTeardownCapture,
    repeatDetachReport, sanitizeDetachSummary,
} from "./detach_report.js";
import { log, devlog, devlog_debug, devlog_info, devlog_warn, devlog_error } from "../util/log.js";
import { setIsShuttingDown } from "./shared_structures.js";
import { registerDetachTeardown, runDetachTeardowns } from "./detach_teardown.js";

const G = globalThis as any;

function captureSends(): any[] {
    const sent: any[] = [];
    G.send = (m: any) => sent.push(m);
    return sent;
}

afterEach(() => {
    endTeardownCapture();
    setIsShuttingDown(false);
    runDetachTeardowns();   // drop anything a test left registered
});

test("a step records name, ok and a non-negative integer duration", () => {
    const report = new DetachReportBuilder();
    report.step("quick", () => undefined);
    const [step] = report.finish().steps;
    assert.equal(step.name, "quick");
    assert.equal(step.ok, true);
    assert.ok(Number.isInteger(step.ms) && step.ms >= 0);
    assert.equal("summary" in step, false);
    assert.equal("error" in step, false);
});

test("a throwing step is recorded as failed with a clipped error and later steps still run", () => {
    const report = new DetachReportBuilder();
    report.step("boom", () => { throw new Error("x".repeat(1000)); });
    report.step("after", () => undefined);
    const steps = report.finish().steps;
    assert.equal(steps[0].ok, false);
    assert.ok(steps[0].error!.startsWith("Error: xxx"));
    assert.equal(steps[0].error!.length, DETACH_TEXT_LIMIT);
    assert.deepEqual(steps.map((s) => [s.name, s.ok]), [["boom", false], ["after", true]]);
});

test("a non-Error throw is stringified", () => {
    const report = new DetachReportBuilder();
    report.step("odd", () => { throw 42; });
    assert.equal(report.finish().steps[0].error, "42");
});

test("summaries keep only finite numbers, strings and booleans of plain objects", () => {
    const pointerLike = { toString: () => "0x1234" };
    assert.deepEqual(
        sanitizeDetachSummary({ n: 3, s: "y".repeat(500), b: false, nan: NaN, inf: Infinity, p: pointerLike, nested: { a: 1 }, nil: null }),
        { n: 3, s: "y".repeat(DETACH_TEXT_LIMIT), b: false },
    );
    assert.equal(sanitizeDetachSummary(5), undefined);
    assert.equal(sanitizeDetachSummary([1, 2]), undefined);
    assert.equal(sanitizeDetachSummary(new Map([["a", 1]])), undefined);
    assert.equal(sanitizeDetachSummary({ only: pointerLike }), undefined);
});

test("a step's sanitised return value becomes its summary", () => {
    const report = new DetachReportBuilder();
    report.step("counts", () => ({ restored: 2, skipped: 0, ptr: { x: 1 } }));
    assert.deepEqual(report.finish().steps[0].summary, { restored: 2, skipped: 0 });
});

test("finish() is JSON-round-trippable with the v1 shape", () => {
    const report = new DetachReportBuilder();
    report.step("a", () => ({ k: 1 }));
    report.addLog("info", "hello");
    const out = report.finish();
    assert.deepEqual(JSON.parse(JSON.stringify(out)), out);
    assert.deepEqual(Object.keys(out).sort(), ["dropped_logs", "logs", "repeat", "steps", "total_ms", "version"]);
    assert.equal(out.version, 1);
    assert.equal(out.repeat, false);
});

test("the repeat report is empty and flagged", () => {
    assert.deepEqual(repeatDetachReport(), { version: 1, repeat: true, steps: [], logs: [], dropped_logs: 0, total_ms: 0 });
});

test("inside the capture scope log/devlog go to the report, not to send", () => {
    const sent = captureSends();
    setIsShuttingDown(true);
    const report = new DetachReportBuilder();
    withTeardownCapture(report, () => {
        log("info line");
        devlog("debug line");
    });
    assert.deepEqual(sent, []);
    assert.deepEqual(report.finish().logs, [
        { level: "info", msg: "info line" },
        { level: "debug", msg: "debug line" },
    ]);
});

test("captured logs are capped at 100 entries x 300 chars, the rest counted as dropped", () => {
    const report = new DetachReportBuilder();
    beginTeardownCapture(report);
    log("z".repeat(1000));
    for (let i = 1; i < DETACH_LOG_LIMIT + 6; i++) devlog(`line ${i}`);
    endTeardownCapture();
    const out = report.finish();
    assert.equal(out.logs.length, DETACH_LOG_LIMIT);
    assert.equal(out.logs[0].msg.length, DETACH_TEXT_LIMIT);
    assert.equal(out.dropped_logs, 6);
});

test("outside the scope a shutting-down log/devlog is still dropped", () => {
    const sent = captureSends();
    const report = new DetachReportBuilder();
    withTeardownCapture(report, () => undefined);
    setIsShuttingDown(true);
    log("late");
    devlog("late");
    assert.deepEqual(sent, []);
    assert.deepEqual(report.finish().logs, []);
});

test("outside the scope and not shutting down log/devlog send as before", () => {
    const sent = captureSends();
    log("a");
    devlog("b");
    assert.deepEqual(sent, [
        { contentType: "console", console: "a" },
        { contentType: "console_dev", console_dev: "b" },
    ]);
});

test("inside the capture scope every devlog_* variant is captured with its own level, none sent", () => {
    const sent = captureSends();
    setIsShuttingDown(true);
    const report = new DetachReportBuilder();
    withTeardownCapture(report, () => {
        devlog_debug("d", { extra: 1 });
        devlog_info("i");
        devlog_warn("w");
        devlog_error("e");
    });
    assert.deepEqual(sent, []);
    assert.deepEqual(report.finish().logs, [
        { level: "debug", msg: "d" },
        { level: "info", msg: "i" },
        { level: "warn", msg: "w" },
        { level: "error", msg: "e" },
    ]);
});

test("devlog_* keeps its empty-message rule while capturing", () => {
    const report = new DetachReportBuilder();
    withTeardownCapture(report, () => {
        devlog_debug("");
        devlog_warn(undefined as any);
    });
    const out = report.finish();
    assert.deepEqual(out.logs, []);
    assert.equal(out.dropped_logs, 0);
});

test("outside the scope a shutting-down devlog_* is still dropped", () => {
    const sent = captureSends();
    const report = new DetachReportBuilder();
    withTeardownCapture(report, () => undefined);
    setIsShuttingDown(true);
    devlog_debug("late");
    devlog_info("late");
    devlog_warn("late");
    devlog_error("late");
    assert.deepEqual(sent, []);
    assert.deepEqual(report.finish().logs, []);
});

test("outside the scope and not shutting down devlog_* sends as before", () => {
    const sent = captureSends();
    devlog_debug("a");
    devlog_error("b");
    assert.deepEqual(sent.map((m) => [m.contentType, m.level, m.message]), [
        ["console_debug", "debug", "a"],
        ["console_error", "error", "b"],
    ]);
});

test("the cap and dropped count hold across mixed log variants", () => {
    const sent = captureSends();
    setIsShuttingDown(true);
    const report = new DetachReportBuilder();
    const variants = [log, devlog, devlog_debug, devlog_info, devlog_warn, devlog_error];
    const extra = 7;
    withTeardownCapture(report, () => {
        for (let i = 0; i < DETACH_LOG_LIMIT + extra; i++) variants[i % variants.length]("x".repeat(1000));
    });
    const out = report.finish();
    assert.equal(sent.length, 0);
    assert.equal(out.logs.length, DETACH_LOG_LIMIT);
    assert.equal(out.dropped_logs, extra);
    assert.ok(out.logs.every((entry) => entry.msg.length === DETACH_TEXT_LIMIT));
    assert.deepEqual(out.logs.slice(0, 6).map((entry) => entry.level), ["info", "debug", "debug", "info", "warn", "error"]);
});

test("the capture scope ends even when its body throws", () => {
    const sent = captureSends();
    assert.throws(() => withTeardownCapture(new DetachReportBuilder(), () => { throw new Error("x"); }));
    log("after");
    assert.equal(sent.length, 1);
});

test("teardowns run in reverse order as labelled steps, isolated, with summaries", () => {
    const order: string[] = [];
    registerDetachTeardown("first", () => { order.push("first"); });
    registerDetachTeardown("broken", () => { throw new Error("boom"); });
    registerDetachTeardown("counted", () => { order.push("counted"); return { owned: 2 }; });
    const report = new DetachReportBuilder();
    assert.doesNotThrow(() => runDetachTeardowns(report));
    assert.deepEqual(order, ["counted", "first"]);
    const steps = report.finish().steps;
    assert.deepEqual(steps.map((s) => [s.name, s.ok]), [
        ["teardown:counted", true], ["teardown:broken", false], ["teardown:first", true],
    ]);
    assert.deepEqual(steps[0].summary, { owned: 2 });
    assert.equal(steps[1].error, "Error: boom");
});

test("a teardown run empties the registry", () => {
    let calls = 0;
    registerDetachTeardown("once", () => { calls++; });
    runDetachTeardowns(new DetachReportBuilder());
    const second = new DetachReportBuilder();
    runDetachTeardowns(second);
    assert.equal(calls, 1);
    assert.deepEqual(second.finish().steps, []);
});
