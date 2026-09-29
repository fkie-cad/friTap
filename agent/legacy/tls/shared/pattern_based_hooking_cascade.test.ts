// Unit tests for the LEGACY PatternBasedHooking `cascadeCompleted` flag
// (agent/legacy/tls/shared/pattern_based_hooking.ts). Without it
// classifyPatternPoll could not tell a failed cascade from a running one, so
// pollPatternOutcome waited the full 120 s hard bound before tier 4 ran.
//
// Memory.scan is replaced by a queue the test drains by hand, so each scan's
// onMatch/onError/onComplete fires exactly when the test says.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";

import { PatternBasedHooking } from "./pattern_based_hooking.js";
import { classifyPatternPoll, type PatternPollTiming } from "../../../shared/boringssl_pattern_hook.js";

const G = globalThis as any;

interface PendingScan { pattern: string; callbacks: any; }
let pendingScans: PendingScan[] = [];

beforeEach(() => {
    pendingScans = [];
    G.Memory.scan = (_base: any, _size: number, pattern: string, callbacks: any) => {
        pendingScans.push({ pattern, callbacks });
    };
});

function fakeAddress(value: number): any {
    return {
        value,
        add: (n: number) => fakeAddress(value + Number(n)),
        compare: (other: any) => Math.sign(value - other.value),
        toString: () => "0x" + value.toString(16),
    };
}

/** Small module (below the large-module r-x-only bound) with one readable range. */
function fakeModule(): any {
    const base = fakeAddress(0x1000);
    return {
        name: "libcronet.so", base, size: 0x1000,
        enumerateRanges: () => [{ base, size: 0x1000, protection: "r-x" }],
    };
}

/** Complete the oldest pending scan; `outcome` picks which callbacks fire. */
function finishNextScan(outcome: "miss" | "match" | "error" = "miss"): PendingScan {
    const scan = pendingScans.shift();
    assert.ok(scan, "expected a pending Memory.scan");
    if (outcome === "match") scan.callbacks.onMatch(fakeAddress(0x1100), 4);
    if (outcome === "error") scan.callbacks.onError("access violation");
    scan.callbacks.onComplete();
    return scan;
}

function drainScansAsMisses(): void {
    while (pendingScans.length > 0) finishNextScan("miss");
}

const PATTERNS = { primary: "AA BB", fallback: "CC DD" };
const T: PatternPollTiming = { intervalMs: 100, maxIntervalMs: 2000, graceMs: 200, softTimeoutMs: 10000, hardTimeoutMs: 120000 };

test("a fresh hooker has not completed a cascade", () => {
    assert.equal(new PatternBasedHooking(fakeModule()).cascadeCompleted, false);
});

test("primary + fallback miss (no second_fallback) completes the cascade as a real miss", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(PATTERNS, () => { });
    assert.equal(hooker.cascadeCompleted, false, "primary scan still running");
    assert.equal(finishNextScan().pattern, "AA BB");
    assert.equal(hooker.cascadeCompleted, false, "fallback scan still running");
    assert.equal(finishNextScan().pattern, "CC DD");
    assert.equal(hooker.cascadeCompleted, true);
    assert.equal(hooker.found_ssl_log_secret, false);
    assert.equal(hooker.no_hooking_success, true);
    assert.equal(classifyPatternPoll(hooker, T.graceMs, T), "no-match");
});

test("second_fallback miss completes the cascade only after the third scan", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern({ ...PATTERNS, second_fallback: "EE FF" }, () => { });
    finishNextScan();
    finishNextScan();
    assert.equal(hooker.cascadeCompleted, false, "second_fallback scan still running");
    assert.equal(finishNextScan().pattern, "EE FF");
    assert.equal(hooker.cascadeCompleted, true);
    assert.equal(classifyPatternPoll(hooker, T.graceMs, T), "no-match");
});

test("a primary match sets found_ssl_log_secret and completes the cascade", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(PATTERNS, () => { });
    finishNextScan("match");
    assert.equal(hooker.found_ssl_log_secret, true);
    assert.equal(hooker.no_hooking_success, false);
    assert.equal(hooker.cascadeCompleted, true);
    assert.equal(pendingScans.length, 0, "no fallback scan after a match");
    assert.equal(classifyPatternPoll(hooker, 0, T), "matched");
});

test("a fallback match completes the cascade", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(PATTERNS, () => { });
    finishNextScan("miss");
    finishNextScan("match");
    assert.equal(hooker.found_ssl_log_secret, true);
    assert.equal(hooker.cascadeCompleted, true);
});

test("no usable pattern settles immediately", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(null, () => { });
    assert.equal(hooker.cascadeCompleted, true);
    assert.equal(pendingScans.length, 0);
});

test("an onError rescan keeps the hooker unsettled until it also terminates", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(PATTERNS, () => { });
    // Primary whole-module scan faults: onError starts the readable-parts
    // rescan, and onComplete still drives the outer cascade to the fallback.
    finishNextScan("error");
    // Queue: [rescan's first range scan (primary), outer cascade's fallback scan].
    assert.deepEqual(pendingScans.map((s) => s.pattern), ["AA BB", "CC DD"]);
    // Finish only the outer cascade's fallback scan: the outer cascade is done.
    pendingScans.pop()!.callbacks.onComplete();
    assert.equal(hooker.cascadeCompleted, false, "readable-parts rescan still running");
    drainScansAsMisses();
    assert.equal(hooker.cascadeCompleted, true);
    assert.equal(hooker.found_ssl_log_secret, false);
});

test("re-entering for a second cascade un-settles the hooker", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hookModuleByPattern(PATTERNS, () => { });
    drainScansAsMisses();
    assert.equal(hooker.cascadeCompleted, true);
    hooker.hookModuleByPattern({ primary: "11 22", fallback: "33 44" }, () => { });
    assert.equal(hooker.cascadeCompleted, false, "a new cascade is running");
    drainScansAsMisses();
    assert.equal(hooker.cascadeCompleted, true);
});

test("hook_DumpKeys with no JSON entry for the module settles without scanning", () => {
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hook_DumpKeys("libcronet.so", "libcronet.so", JSON.stringify({ modules: {} }), () => { });
    assert.equal(pendingScans.length, 0);
    assert.equal(hooker.cascadeCompleted, true);
});

test("hook_DumpKeys settles only after the JSON-driven cascade terminates", () => {
    const json = JSON.stringify({
        modules: { "libcronet.so": { [G.Process.platform]: { [G.Process.arch]: { "Dump-Keys": PATTERNS } } } },
    });
    const hooker = new PatternBasedHooking(fakeModule());
    hooker.hook_DumpKeys("libcronet.so", "libcronet.so", json, () => { });
    assert.equal(hooker.cascadeCompleted, false);
    drainScansAsMisses();
    assert.equal(hooker.cascadeCompleted, true);
});
