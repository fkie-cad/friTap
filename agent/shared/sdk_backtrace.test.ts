// Unit tests for the opt-in SDK/caller-attribution helper (shared/sdk_backtrace.ts).
//
// Run: npm run test:agent
//
// Covers (without a device): the pure native-frame symbolizer (mapping, 32-frame
// cap, per-frame failure fallback) and the CRITICAL flag-off guarantee — when
// --attribute-sdk is off (the default; config_batch is empty in tests, so
// attribute_sdk stays false), maybeCaptureCallerStack() reads no SSL state (the
// join provider is never invoked) and emits no message. The on-device capture
// path (Thread.backtrace / Java stack) is exercised manually on a device.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;

// DebugSymbol stub: module + symbol derived from the address string.
G.DebugSymbol = {
    fromAddress: (p: any) => ({ moduleName: "libfoo.so", name: "sym_" + p.toString() }),
};

import { symbolizeNativeFrames, maybeCaptureCallerStack, forgetSsl } from "./sdk_backtrace.js";

function ptr(s: string): any { return { toString: () => s }; }

test("symbolizeNativeFrames maps module/symbol/address", () => {
    const frames = symbolizeNativeFrames([ptr("0x10"), ptr("0x20")]);
    assert.equal(frames.length, 2);
    assert.deepEqual(frames[0], { module: "libfoo.so", symbol: "sym_0x10", address: "0x10" });
    assert.equal(frames[1].address, "0x20");
});

test("symbolizeNativeFrames caps at 32 frames by default", () => {
    const addrs = Array.from({ length: 50 }, (_, i) => ptr("0x" + i));
    assert.equal(symbolizeNativeFrames(addrs).length, 32);
});

test("symbolizeNativeFrames honours an explicit max", () => {
    const addrs = Array.from({ length: 10 }, (_, i) => ptr("0x" + i));
    assert.equal(symbolizeNativeFrames(addrs, 4).length, 4);
});

test("symbolizeNativeFrames falls back to the raw address when symbolization throws", () => {
    const prev = G.DebugSymbol.fromAddress;
    G.DebugSymbol.fromAddress = () => { throw new Error("no symbol"); };
    try {
        const frames = symbolizeNativeFrames([ptr("0xdead")]);
        assert.deepEqual(frames[0], { module: "", symbol: null, address: "0xdead" });
    } finally {
        G.DebugSymbol.fromAddress = prev;
    }
});

test("maybeCaptureCallerStack is inert when attribute_sdk is off (default)", () => {
    const sent: any[] = [];
    const prevSend = G.send;
    G.send = (m: any) => sent.push(m);
    let providerCalls = 0;
    try {
        maybeCaptureCallerStack(ptr("0x1"), {} as any, () => { providerCalls++; return {}; });
        maybeCaptureCallerStack(ptr("0x2"), {} as any, () => { providerCalls++; return {}; });
    } finally {
        G.send = prevSend;
    }
    assert.equal(sent.length, 0, "no caller_stack message is emitted when the flag is off");
    assert.equal(providerCalls, 0, "the join provider is never invoked when the flag is off (no SSL state read)");
});

test("forgetSsl is a safe no-op when nothing was captured", () => {
    assert.doesNotThrow(() => forgetSsl("0xabc"));
});
