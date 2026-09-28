// Unit tests for clampReadableLength (agent/ms_agent/core/memory.ts): the scan
// length must be clamped to the live mapping's end so a range that shrank since
// the configure()-time snapshot is never scanned past what is still mapped (N4).
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/core/memory.test.ts)

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { clampReadableLength } from "./memory.js";

test("a request fully inside the mapping keeps its size", () => {
    assert.equal(clampReadableLength(0x1000, 0x400, 0x1000, 0x2000), 0x400);
    assert.equal(clampReadableLength(0x1400, 0x400, 0x1000, 0x2000), 0x400);
});

test("a request running off the end is truncated to the live end", () => {
    // mapping [0x1000, 0x3000); base 0x2800 -> only 0x800 remain of a 0x1000 request.
    assert.equal(clampReadableLength(0x2800, 0x1000, 0x1000, 0x2000), 0x800);
});

test("a request ending exactly at the mapping end is unchanged", () => {
    assert.equal(clampReadableLength(0x1000, 0x2000, 0x1000, 0x2000), 0x2000);
});

test("a base at or past the mapping end yields 0", () => {
    assert.equal(clampReadableLength(0x3000, 0x10, 0x1000, 0x2000), 0);
    assert.equal(clampReadableLength(0x4000, 0x10, 0x1000, 0x2000), 0);
});

test("a base before the mapping yields 0", () => {
    assert.equal(clampReadableLength(0x800, 0x400, 0x1000, 0x2000), 0);
});

test("degenerate sizes yield 0", () => {
    assert.equal(clampReadableLength(0x1000, 0, 0x1000, 0x2000), 0);
    assert.equal(clampReadableLength(0x1000, -5, 0x1000, 0x2000), 0);
    assert.equal(clampReadableLength(0x1000, 0x400, 0x1000, 0), 0);
});
