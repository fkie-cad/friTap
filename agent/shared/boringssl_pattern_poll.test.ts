// Unit tests for the pattern-outcome poll (agent/shared/boringssl_pattern_hook.ts):
// the soft timeout must NOT resolve a still-running scan as a miss (A3) —
// otherwise the chain starts tier 4 next to a scan that can still match.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = () => { };

import {
    classifyPatternPoll,
    nextPatternPollDelay,
    pollPatternOutcome,
    type PatternPollTiming,
} from "./boringssl_pattern_hook.js";

const T: PatternPollTiming = { intervalMs: 100, maxIntervalMs: 2000, graceMs: 200, softTimeoutMs: 10000, hardTimeoutMs: 120000 };

test("classify: a match wins at any time", () => {
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: true }, 0, T), "matched");
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: true, cascadeCompleted: true }, 500000, T), "matched");
});

test("classify: a completed cascade is a real miss only past the grace window", () => {
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false, cascadeCompleted: true }, 100, T), "still-scanning");
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false, cascadeCompleted: true }, 200, T), "no-match");
});

test("classify: past the SOFT timeout a running scan is still-scanning, not a miss", () => {
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false, cascadeCompleted: false }, 10000, T), "still-scanning");
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false, cascadeCompleted: false }, 60000, T), "still-scanning");
});

test("classify: legacy hookers (no cascadeCompleted) wait for the hard bound", () => {
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false }, 30000, T), "still-scanning");
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false }, 120000, T), "gave-up");
});

test("classify: the hard bound gives up on a scan that is still running", () => {
    assert.equal(classifyPatternPoll({ found_ssl_log_secret: false, cascadeCompleted: false }, 120000, T), "gave-up");
});

test("delay: fixed before the soft timeout, then doubling to the cap", () => {
    assert.equal(nextPatternPollDelay(5000, 100, T), 100);
    assert.equal(nextPatternPollDelay(10000, 100, T), 200);
    assert.equal(nextPatternPollDelay(11000, 200, T), 400);
    assert.equal(nextPatternPollDelay(20000, 1600, T), 2000);
    assert.equal(nextPatternPollDelay(30000, 2000, T), 2000);
});

const FAST: PatternPollTiming = { intervalMs: 5, maxIntervalMs: 20, graceMs: 0, softTimeoutMs: 20, hardTimeoutMs: 2000 };

test("poll: a scan that matches AFTER the soft timeout resolves true", async () => {
    const hooker = { found_ssl_log_secret: false, cascadeCompleted: false };
    setTimeout(() => { hooker.found_ssl_log_secret = true; }, 80); // well past softTimeoutMs=20
    assert.equal(await pollPatternOutcome(hooker, "libmonochrome_64.so", FAST), true);
});

test("poll: a cascade that completes after the soft timeout without a match resolves false", async () => {
    const hooker = { found_ssl_log_secret: false, cascadeCompleted: false };
    setTimeout(() => { hooker.cascadeCompleted = true; }, 80);
    const t0 = Date.now();
    assert.equal(await pollPatternOutcome(hooker, "libx.so", FAST), false);
    assert.ok(Date.now() - t0 >= 75, "did not resolve at the soft timeout");
});

test("poll: gives up at the hard bound when the scan never settles", async () => {
    const hooker = { found_ssl_log_secret: false, cascadeCompleted: false };
    const t0 = Date.now();
    assert.equal(await pollPatternOutcome(hooker, "libx.so", { ...FAST, hardTimeoutMs: 100 }), false);
    assert.ok(Date.now() - t0 >= 95);
});
