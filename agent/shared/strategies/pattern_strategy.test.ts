// Run: npm run test:agent
//
// PatternStrategy.tryHookAsync() keeps swallowing scan errors for its callers,
// and reports them through the optional ScanStatus.

import { test, afterEach } from "node:test";
import assert from "node:assert/strict";
import "../frida-test-stubs.js";

import { PatternStrategy } from "./pattern_strategy.js";

const G = globalThis as any;
const originalGetModule = G.Process.getModuleByName;
const originalScan = G.Memory.scan;

const PATTERNS = { libx: { linux: { x64: { f: "aa bb", g: "cc dd" } } } };
const HIT = { tag: "hit" };

function stubModule(): void {
    G.Process.getModuleByName = () => ({
        name: "libx", base: 0x1000, size: 0x100,
        enumerateRanges: () => [{ base: 0x1000, size: 0x100 }],
    });
}

/** Memory.scan stub: pattern -> "hit" | "miss" | "error" (onError, then onComplete without a match). */
function stubScan(outcome: Record<string, "hit" | "miss" | "error">): void {
    G.Memory.scan = (_base: any, _size: number, pattern: string, cb: any) => {
        if (outcome[pattern] === "hit") cb.onMatch(HIT, 2);
        if (outcome[pattern] === "error") cb.onError("access violation");
        cb.onComplete();
    };
}

afterEach(() => {
    G.Process.getModuleByName = originalGetModule;
    G.Memory.scan = originalScan;
});

test("a clean scan leaves the status complete", async () => {
    stubModule();
    stubScan({ "aa bb": "hit", "cc dd": "miss" });
    const status = { complete: true };
    const res = await new PatternStrategy(PATTERNS).tryHookAsync("libx", "x", ["f", "g"], status);
    assert.equal(res.resolvedAddresses.get("f"), HIT);
    assert.equal(res.resolvedAddresses.has("g"), false);
    assert.equal(status.complete, true);
});

test("a scan read error marks the status incomplete; the result is unchanged and callers without a status still work", async () => {
    stubModule();
    stubScan({ "aa bb": "hit", "cc dd": "error" });
    const status = { complete: true };
    const withStatus = await new PatternStrategy(PATTERNS).tryHookAsync("libx", "x", ["f", "g"], status);
    const without = await new PatternStrategy(PATTERNS).tryHookAsync("libx", "x", ["f", "g"]);
    assert.equal(status.complete, false);
    assert.deepEqual(withStatus.hookedFunctions, ["f"]);
    assert.deepEqual(without.hookedFunctions, ["f"]);
    assert.deepEqual(withStatus.errors, without.errors);
});

test("a module lookup failure is reported as incomplete", async () => {
    G.Process.getModuleByName = () => { throw new Error("unable to find module"); };
    const status = { complete: true };
    const res = await new PatternStrategy(PATTERNS).tryHookAsync("libx", "x", ["f"], status);
    assert.equal(res.success, false);
    assert.equal(status.complete, false);
    assert.match(res.errors.join(), /unable to find module/);
});

test("patternsFor follows tryHookAsync's lookup", () => {
    const ps = new PatternStrategy({ libx: { linux: { default: { f: ["aa", "bb"], g: "cc" } } } });
    assert.deepEqual(ps.patternsFor("libx", "x", "f"), ["aa", "bb"]);
    assert.deepEqual(ps.patternsFor("liby", "libx", "g"), ["cc"], "falls back to the library type");
    assert.deepEqual(ps.patternsFor("libx", "x", "h"), []);
    assert.deepEqual(ps.patternsFor("libx", "x", undefined), []);
    assert.deepEqual(new PatternStrategy().patternsFor("libx", "x", "f"), []);
});
