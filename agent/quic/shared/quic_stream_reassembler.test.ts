// Unit tests for the QUIC stream reassembler (quic_stream_reassembler.ts).
//
// Run: npm run test:agent
//
// WHY: the Google QUICHE STREAM-frame hooks see retransmitted, overlapping and
// reordered frames; HTTP/3 framing and QPACK need each stream's bytes exactly
// once, in order, from offset 0 (a uni stream starts with its type byte).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    MAX_UNSTARTED_PENDING_FRAGMENTS, QuicStreamReassembler, ReassembledChunk,
} from "./quic_stream_reassembler.js";

const bytes = (s: string) => new TextEncoder().encode(s);
const text = (chunks: ReassembledChunk[]) => chunks.map((c) => new TextDecoder().decode(c.data)).join("");

test("in-order fragments pass through unchanged with their offsets", () => {
    const r = new QuicStreamReassembler();
    const a = r.push("s", 0, bytes("abc"));
    const b = r.push("s", 3, bytes("def"));
    assert.deepEqual(a.map((c) => c.offset), [0]);
    assert.deepEqual(b.map((c) => c.offset), [3]);
    assert.equal(text([...a, ...b]), "abcdef");
});

test("retransmissions and overlaps are delivered once", () => {
    const r = new QuicStreamReassembler();
    let out = r.push("s", 0, bytes("abcd"));
    out = out.concat(r.push("s", 0, bytes("abcd")));       // full retransmission
    out = out.concat(r.push("s", 2, bytes("cdef")));       // overlap: only "ef" is new
    assert.equal(text(out), "abcdef");
});

test("a reordered fragment waits for the gap and is then drained in order", () => {
    const r = new QuicStreamReassembler();
    assert.equal(text(r.push("s", 0, bytes("ab"))), "ab");
    assert.deepEqual(r.push("s", 4, bytes("ef")), []);
    assert.deepEqual(r.push("s", 6, bytes("g")), []);
    assert.equal(text(r.push("s", 2, bytes("cd"))), "cdefg");
});

test("a stream whose first frame arrives after a later one still starts at offset 0", () => {
    const r = new QuicStreamReassembler();
    assert.deepEqual(r.push("s", 3, bytes("def")), []);
    assert.equal(text(r.push("s", 0, bytes("abc"))), "abcdef");
});

test("a late-joined stream (offset 0 never seen) is abandoned, not emitted mid-stream", () => {
    const r = new QuicStreamReassembler();
    for (let i = 0; i <= MAX_UNSTARTED_PENDING_FRAGMENTS; i++) {
        assert.deepEqual(r.push("s", 1000 + i * 10, bytes("0123456789")), []);
    }
    assert.deepEqual(r.push("s", 0, bytes("x")), []);       // too late: ignored for good
});

test("streams are independent per key (connection, direction, stream id)", () => {
    const r = new QuicStreamReassembler();
    assert.equal(text(r.push("in|c1|0", 0, bytes("req"))), "req");
    assert.equal(text(r.push("out|c1|0", 0, bytes("resp"))), "resp");
    assert.equal(text(r.push("in|c2|0", 0, bytes("other"))), "other");
});

test("a FIN-completed stream is forgotten; a late retransmission is dropped", () => {
    const r = new QuicStreamReassembler();
    assert.equal(text(r.push("s", 0, bytes("abc"), true)), "abc");
    assert.deepEqual(r.push("s", 0, bytes("abc"), true), []);
});

test("a bare FIN (no data) at the end completes the stream", () => {
    const r = new QuicStreamReassembler();
    assert.equal(text(r.push("s", 0, bytes("ab"))), "ab");
    assert.deepEqual(r.push("s", 2, new Uint8Array(0), true), []);
    assert.deepEqual(r.push("s", 2, bytes("zz")), []);
});

test("the number of tracked streams is bounded", () => {
    const r = new QuicStreamReassembler(4);
    for (let i = 0; i < 10; i++) r.push("s" + i, 0, bytes("x"));
    assert.equal(r.trackedStreams, 4);
});

test("canDeliver is false for retransmitted ranges and ignored streams", () => {
    const r = new QuicStreamReassembler();
    assert.equal(r.canDeliver("s", 0, 3), true);                  // unknown stream
    r.push("s", 0, bytes("abc"));
    assert.equal(r.canDeliver("s", 0, 3), false);                 // pure retransmission
    assert.equal(r.canDeliver("s", 1, 3), true);                  // overlaps new bytes
    r.push("s", 3, bytes("d"), true);                             // FIN completes -> ignored
    assert.equal(r.canDeliver("s", 4, 10), false);
});

test("buffered bytes are bounded across all streams", () => {
    const r = new QuicStreamReassembler(16, 10);
    r.push("a", 0, bytes("x"));
    r.push("b", 0, bytes("y"));
    assert.deepEqual(r.push("a", 5, bytes("123456")), []);       // 6 bytes held
    assert.equal(r.pendingBytes, 6);
    r.push("b", 5, bytes("123456"));                              // 12 > 10: stream b abandoned
    assert.equal(r.pendingBytes, 6);
    assert.deepEqual(r.push("b", 1, bytes("zzzz")), []);          // b stays ignored
    assert.equal(text(r.push("a", 1, bytes("bcde"))), "bcde123456");
    assert.equal(r.pendingBytes, 0);
});

test("evicting a stream releases its buffered bytes from the global budget", () => {
    const r = new QuicStreamReassembler(1);
    r.push("a", 0, bytes("x"));
    r.push("a", 5, bytes("held"));
    assert.equal(r.pendingBytes, 4);
    r.push("b", 0, bytes("y"));                                   // evicts "a"
    assert.equal(r.pendingBytes, 0);
});
