// Unit tests for nss_layout_constants.ts: the acceptance rules shared by the
// three NSS keylog-writer backends.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import {
    calleesPerLabel, isPlausibleWriterClientRandomOffset, NSS_HEX_TABLE, readsHexTable, singleOffset,
} from "./nss_layout_constants.js";

const ascii = (text: string) => Uint8Array.from(text, (c) => c.charCodeAt(0));

test("plausible writer offsets honour the range and the ABI alignment", () => {
    assert.ok(isPlausibleWriterClientRandomOffset(0x650, 8));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x654, 8));
    assert.ok(isPlausibleWriterClientRandomOffset(0x424, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x42a, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x30, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x3000, 4));
});

test("readsHexTable matches the table by content, and an unreadable or short read is no match", () => {
    assert.ok(readsHexTable((a, n) => (a === 0x10 ? ascii(NSS_HEX_TABLE.slice(0, n)) : null), 0x10));
    assert.ok(!readsHexTable((a, n) => ascii("x".repeat(n)), 0x10));
    assert.ok(!readsHexTable(() => null, 0x10));
    assert.ok(!readsHexTable(() => ascii("0123"), 0x10));
});

test("singleOffset accepts only a hex-table reference plus exactly one offset", () => {
    assert.deepEqual(singleOffset(true, new Set([0x650])), { clientRandomOff: 0x650 });
    assert.equal(singleOffset(false, new Set([0x650])), null);
    assert.equal(singleOffset(true, new Set()), null);
    assert.equal(singleOffset(true, new Set([0x650, 0x658])), null);
});

test("calleesPerLabel keeps label alignment and drops unresolved items", () => {
    const p = { tag: "p" } as unknown as NativePointer;
    assert.deepEqual(calleesPerLabel([[1, 2], [], [3]], (n) => (n === 2 ? p : null)), [[p], [], []]);
});
