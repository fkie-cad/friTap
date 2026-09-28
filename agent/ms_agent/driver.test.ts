// Unit tests for the memory-scan driver's needs_mapped_index gate
// (agent/ms_agent/driver.ts).
//
// Run: npm run test:agent
//
// The gate decides whether scanProfileOnce() builds the per-scan '---' range index.
// The RC4 profile sets needs_mapped_index:false to skip it (the RC4 engine never
// classifies pointers); every other profile keeps the code default (build it).

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Interceptor/etc. BEFORE agent modules load.
import "../shared/frida-test-stubs.js";
import { needsMappedIndex } from "./driver.js";

test("needsMappedIndex: defaults to true when unset (today's always-build behavior)", () => {
    assert.equal(needsMappedIndex(null), true);
    assert.equal(needsMappedIndex(undefined), true);
    assert.equal(needsMappedIndex({}), true);
    assert.equal(needsMappedIndex({ params: {} }), true);
    assert.equal(needsMappedIndex({ params: { needs_mapped_index: true } }), true);
});

test("needsMappedIndex: false only when a profile explicitly opts out (RC4)", () => {
    assert.equal(needsMappedIndex({ params: { needs_mapped_index: false } }), false);
    // A non-boolean must NOT disable the build (only an explicit `false` does).
    assert.equal(needsMappedIndex({ params: { needs_mapped_index: 0 } }), true);
    assert.equal(needsMappedIndex({ params: { needs_mapped_index: "false" } }), true);
});
