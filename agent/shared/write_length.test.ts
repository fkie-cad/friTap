// Unit tests for shared/write_length.ts (written-byte accounting of TLS write hooks).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { bytesWrittenFromRetval, bytesWrittenFromOutParam } from "./write_length.js";

function outParam(value: number): any {
    return { isNull: () => false, readU32: () => value };
}
const NULL_PTR: any = { isNull: () => true, readU32: () => { throw new Error("NULL deref"); } };

test("bytesWrittenFromRetval: full, partial and clamped writes", () => {
    assert.equal(bytesWrittenFromRetval(100, 100), 100);
    assert.equal(bytesWrittenFromRetval(100, 40), 40, "partial write: only what was consumed");
    assert.equal(bytesWrittenFromRetval(100, 4096), 100, "never more than requested");
});

test("bytesWrittenFromRetval: failures and empty requests emit nothing", () => {
    assert.equal(bytesWrittenFromRetval(100, 0), 0);
    assert.equal(bytesWrittenFromRetval(100, -1), 0);
    assert.equal(bytesWrittenFromRetval(0, 5), 0);
    assert.equal(bytesWrittenFromRetval(undefined as any, 5), 0, "unprepared invocation context");
});

test("bytesWrittenFromOutParam: *written on success, clamped to the request", () => {
    assert.equal(bytesWrittenFromOutParam(100, 1, outParam(100)), 100);
    assert.equal(bytesWrittenFromOutParam(100, 1, outParam(30)), 30);
    assert.equal(bytesWrittenFromOutParam(100, 1, outParam(500)), 100);
});

test("bytesWrittenFromOutParam: failure ignores *written; NULL written falls back to num", () => {
    assert.equal(bytesWrittenFromOutParam(100, 0, outParam(100)), 0);
    assert.equal(bytesWrittenFromOutParam(100, -1, outParam(100)), 0);
    assert.equal(bytesWrittenFromOutParam(100, 1, NULL_PTR), 100);
    assert.equal(bytesWrittenFromOutParam(100, 1, undefined), 100);
});
