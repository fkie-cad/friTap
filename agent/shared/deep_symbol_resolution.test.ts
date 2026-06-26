// Unit tests for the per-module deep-symbol-resolution opt-in
// (agent/shared/deep_symbol_resolution.ts).
//
// Run: npm run test:agent
//
// No Frida runtime needed — the module is a pure in-process Set, so these tests
// just lock the enable / isEnabled contract and per-module isolation: opting one
// module in must never silently widen the exports → enumerateSymbols() fallback
// to other (unrelated) modules.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
    enableDeepSymbolResolution,
    isDeepSymbolResolutionEnabled,
} from "./deep_symbol_resolution.js";

test("modules are not deep-resolved until explicitly enabled", () => {
    assert.equal(isDeepSymbolResolutionEnabled("libssl.so"), false);
});

test("enableDeepSymbolResolution opts a single module in", () => {
    enableDeepSymbolResolution("libhttpengine.so");
    assert.equal(isDeepSymbolResolutionEnabled("libhttpengine.so"), true);
});

test("the opt-in is scoped to the exact module name", () => {
    enableDeepSymbolResolution("libhttpengine.so");
    // A different module stays on the default exports-only path.
    assert.equal(isDeepSymbolResolutionEnabled("libconscrypt_jni.so"), false);
});

test("enabling is idempotent", () => {
    enableDeepSymbolResolution("libfoo.so");
    enableDeepSymbolResolution("libfoo.so");
    assert.equal(isDeepSymbolResolutionEnabled("libfoo.so"), true);
});
