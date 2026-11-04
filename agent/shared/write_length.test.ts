// Unit tests for shared/write_length.ts (written-byte accounting of TLS write hooks).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { mem, NULL_PTR } from "./write_hook_fakes.js";

import {
    bytesWrittenFromRetval, bytesWrittenFromOutParam, BufferedSendTracker, writtenPayload,
    GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED, UNKNOWN_WRITE_LENGTH,
} from "./write_length.js";

function outParam(value: number): any {
    return { isNull: () => false, readU32: () => value };
}

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

// ── BufferedSendTracker (gnutls_record_send would-block retries) ─────────────
// WHY: on GNUTLS_E_AGAIN/E_INTERRUPTED GnuTLS has already buffered the record; the app
// retries with the same arguments OR with NULL/0, and the successful retry returns the
// buffered record's length. Emitting from the retry's own (NULL) buffer loses the data;
// emitting on every attempt duplicates it.

const buf = mem;
const NULL_BUF = NULL_PTR;
const text = (b: ArrayBuffer | null) => (b === null ? null : Buffer.from(b).toString());

test("BufferedSendTracker: E_AGAIN then a NULL/0 flush emits the buffered record once", () => {
    const t = new BufferedSendTracker();
    assert.equal(t.settle("s1", buf("hello world"), 11, GNUTLS_E_AGAIN), null);
    assert.equal(t.settle("s1", NULL_BUF, 0, GNUTLS_E_AGAIN), null, "still blocked: keeps the first copy");
    assert.equal(text(t.settle("s1", NULL_BUF, 0, 11)), "hello world");
    assert.equal(t.size, 0, "flushed: nothing pending");
});

test("BufferedSendTracker: E_INTERRUPTED then a same-arguments retry emits once", () => {
    const t = new BufferedSendTracker();
    assert.equal(t.settle("s1", buf("abc"), 3, GNUTLS_E_INTERRUPTED), null);
    assert.equal(text(t.settle("s1", buf("abc"), 3, 3)), "abc");
    assert.equal(text(t.settle("s1", buf("next"), 4, 4)), "next", "later sends use their own buffer");
});

test("BufferedSendTracker: the flush returns the buffered record's length (one record of a larger request)", () => {
    const t = new BufferedSendTracker();
    const big = "x".repeat(20000);
    t.settle("s1", buf(big), big.length, GNUTLS_E_AGAIN);
    assert.equal(t.settle("s1", NULL_BUF, 0, 16384)!.byteLength, 16384);
});

test("BufferedSendTracker: a hard error drops the pending record; errors emit nothing", () => {
    const t = new BufferedSendTracker();
    t.settle("s1", buf("stale"), 5, GNUTLS_E_AGAIN);
    assert.equal(t.settle("s1", NULL_BUF, 0, -10), null);
    assert.equal(t.size, 0);
    assert.equal(text(t.settle("s1", buf("fresh"), 5, 5)), "fresh", "no stale record after the error");
    assert.equal(t.settle("s2", buf("nope"), 4, -1), null);
});

test("BufferedSendTracker: sessions are independent; partial success is clamped", () => {
    const t = new BufferedSendTracker();
    t.settle("a", buf("AAAA"), 4, GNUTLS_E_AGAIN);
    assert.equal(text(t.settle("b", buf("BBBBBB"), 6, 2)), "BB");
    assert.equal(text(t.settle("a", NULL_BUF, 0, 4)), "AAAA");
});

test("BufferedSendTracker: memory is bounded per record and per session count", () => {
    const t = new BufferedSendTracker(undefined, 2, 8);
    t.settle("a", buf("0123456789ABCDEF"), 16, GNUTLS_E_AGAIN);
    t.settle("b", buf("bb"), 2, GNUTLS_E_AGAIN);
    t.settle("c", buf("cc"), 2, GNUTLS_E_AGAIN);
    assert.equal(t.size, 2, "oldest session evicted");
    assert.equal(t.settle("a", NULL_BUF, 0, 16), null, "evicted: a NULL flush has nothing to emit");
    assert.equal(text(t.settle("c", NULL_BUF, 0, 2)), "cc");
    const capped = new BufferedSendTracker(undefined, 2, 8);
    capped.settle("a", buf("0123456789ABCDEF"), 16, GNUTLS_E_AGAIN);
    assert.equal(text(capped.settle("a", NULL_BUF, 0, 16)), "01234567", "copy capped at maxPendingBytes");
});


test("BufferedSendTracker: a full flush hands out the buffered copy itself (no second copy)", () => {
    const t = new BufferedSendTracker();
    t.settle("s1", buf("record"), 6, GNUTLS_E_AGAIN);
    const first = t.settle("s1", NULL_BUF, 0, 6);
    assert.equal(text(first), "record");
    assert.equal(text(t.settle("s1", buf("other"), 5, 5)), "other", "not handed out twice");
});

test("BufferedSendTracker: nothing pending -> no LRU lookup on success", () => {
    const t = new BufferedSendTracker();
    const lru = (t as any).pending;
    let lookups = 0;
    const get = lru.get.bind(lru);
    lru.get = (k: string) => { lookups++; return get(k); };
    assert.equal(text(t.settle("s1", buf("abc"), 3, 3)), "abc");
    assert.equal(lookups, 0);
    t.settle("s2", buf("xy"), 2, GNUTLS_E_AGAIN);
    assert.equal(text(t.settle("s1", buf("abc"), 3, 3)), "abc", "other session's pending record is not used");
    assert.equal(t.size, 1);
});

// ── writtenPayload (the one "bytes actually written" rule of every write hook) ──

test("writtenPayload: min(requested, retval) bytes; failures and NULL buffers emit nothing", () => {
    assert.equal(text(writtenPayload(buf("hello world"), 11, 5)), "hello");
    assert.equal(text(writtenPayload(buf("hi"), 2, 4096)), "hi", "never more than requested");
    assert.equal(writtenPayload(buf("hi"), 2, 0), null);
    assert.equal(writtenPayload(buf("hi"), 2, -1), null);
    assert.equal(writtenPayload(NULL_BUF, 2, 2), null);
    assert.equal(writtenPayload(buf("hi"), 0, 2), null, "empty request");
});

test("writtenPayload: UNKNOWN_WRITE_LENGTH trusts the return value alone", () => {
    assert.equal(text(writtenPayload(buf("abcdef"), UNKNOWN_WRITE_LENGTH, 4)), "abcd");
    assert.equal(writtenPayload(buf("abcdef"), UNKNOWN_WRITE_LENGTH, -1), null);
});

test("writtenPayload: with a tracker, settles per stringified session (buffered retry)", () => {
    const t = new BufferedSendTracker();
    const session: any = { toString: () => "0xsess" };
    assert.equal(writtenPayload(buf("queued"), 6, GNUTLS_E_AGAIN, session, t), null);
    assert.equal(text(writtenPayload(NULL_BUF, 0, 6, "0xsess", t)), "queued");
});
