// Unit tests for locating QuicStream::id_ (quiche_stream_id.ts).
//
// Run: npm run test:agent
//
// WHY: Chrome run C5 (Pixel 5) reported the same HTTP/3 bodies on both the
// STREAM-frame path and the de-framed body path. The body hooks read the stream
// id one pointer before session_ — on current QUICHE that is the tail of the
// sequencer, so every body carried a small bogus id (0, 1, 3, ...) and the
// per-stream ownership check never found the frame path's real stream.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { Address, QuicheMemory } from "./quiche_layout.js";
import { MAX_LEARNING_OBSERVATIONS, QuicheStreamIdLearner } from "./quiche_stream_id.js";

const SESSION_SLOT = 0x80;          // stream+0x80 -> session_ (as learned on C5)
const LEGACY_SLOT = 0x78;           // session_ - 8: sequencer tail (what C5 read)
const URGENCY_SLOT = 0x90;          // priority_ (HTTP urgency 0..7)
const ID_SLOT = 0xd0;               // id_ (session_ + 0x50 in current QUICHE)
const CONN = "0x7201de3600#1";

/** Stream objects laid out like current QUICHE, each its own fake region. */
class StreamMemory implements QuicheMemory {
    readonly pointerSize = 8;
    private readonly objects = new Map<bigint, Uint8Array>();

    add(stream: bigint, id: number, legacy: number, urgency: number): bigint {
        const bytes = new Uint8Array(0x200);
        const view = new DataView(bytes.buffer);
        view.setUint32(LEGACY_SLOT, legacy, true);
        view.setUint32(URGENCY_SLOT, urgency, true);
        view.setUint32(ID_SLOT, id, true);
        view.setUint32(0xb8, 0x10000 + id * 977, true);   // stream_bytes_read_: varying, not an id
        this.objects.set(stream, bytes);
        return stream;
    }
    readPointer(_a: Address): Address | null { return null; }
    readBytes(a: Address, length: number): Uint8Array | null {
        for (const [base, bytes] of this.objects) {
            if (a >= base && a < base + BigInt(bytes.length)) {
                const off = Number(a - base);
                return bytes.slice(off, Math.min(bytes.length, off + length));
            }
        }
        return null;
    }
    isModuleAddress(_a: Address): boolean { return false; }
}

/** C5-like streams: real ids 12, 16, 20, ... whose legacy slot always reads 0. */
function c5Streams(mem: StreamMemory, count: number): Array<{ stream: bigint; id: number }> {
    const out = [];
    for (let i = 0; i < count; i++) {
        const id = 12 + 4 * i;
        out.push({ stream: mem.add(0x7000_0000n + BigInt(i) * 0x1000n, id, 0, i % 2 === 0 ? 0 : 4), id });
    }
    return out;
}

test("without the frame hooks (no oracle) the legacy slot is read as before", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    mem.add(0x7000_0000n, 12, 4, 3);
    assert.equal(learner.learning, "legacy");
    assert.equal(learner.streamId(mem, 0x7000_0000n, SESSION_SLOT, CONN, true), 4);
});

test("C5 repro: the legacy slot gives one bogus id for many streams", () => {
    const mem = new StreamMemory();
    const legacy = new QuicheStreamIdLearner();
    const ids = c5Streams(mem, 6).map((s) => legacy.streamId(mem, s.stream, SESSION_SLOT, CONN, true));
    assert.deepEqual(ids, [0, 0, 0, 0, 0, 0]);
});

test("with the frame hooks live, id_ is learned from ingress bodies matching real frame stream ids", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams = c5Streams(mem, 6);
    learner.noteStream(CONN, 0);            // stream 0 is real too: zeroed slots must not win
    for (const s of streams) learner.noteStream(CONN, s.id);
    const seen = streams.map((s) => learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true));
    // Unknown (never a guessed id) until four distinct streams agreed, then the real id.
    assert.deepEqual(seen, [null, null, null, 24, 28, 32]);
    assert.equal(learner.learning, "learned");
    assert.equal(learner.offset, ID_SLOT - SESSION_SLOT);
    assert.equal(learner.streamId(mem, streams[0].stream, SESSION_SLOT, CONN, false), 12);
});

test("a learned id_ is read on connections the frame path never reported (pre-hook \"bodies\" ones)", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams = c5Streams(mem, 6);
    for (const s of streams.slice(0, 4)) learner.noteStream(CONN, s.id);
    for (const s of streams.slice(0, 4)) learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true);
    assert.equal(learner.learning, "learned");
    const bodiesOnly = "0x7205531c00#1";
    assert.equal(learner.streamId(mem, streams[4].stream, SESSION_SLOT, bodiesOnly, true), 28);
    assert.equal(learner.streamId(mem, streams[5].stream, SESSION_SLOT, bodiesOnly, false), 32);
});

test("egress bodies never teach (their frame may not have been written yet)", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams = c5Streams(mem, 6);
    for (const s of streams) learner.noteStream(CONN, s.id);
    for (const s of streams) assert.equal(learner.streamId(mem, s.stream, SESSION_SLOT, CONN, false), null);
    assert.equal(learner.learning, "learning");
});

test("ids seen only on another connection teach nothing", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams = c5Streams(mem, 6);
    for (const s of streams) learner.noteStream("0x7201de3600", s.id);   // generation 0 only
    for (const s of streams) assert.equal(learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true), null);
    assert.equal(learner.learning, "learning");
});

test("one stream the oracle does not know yet does not disqualify the real slot", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams = c5Streams(mem, 6);
    learner.noteStream(CONN, 4);                                          // unrelated, makes the oracle non-empty
    learner.streamId(mem, streams[0].stream, SESSION_SLOT, CONN, true);   // a miss for every slot
    for (const s of streams.slice(1)) learner.noteStream(CONN, s.id);
    for (const s of streams.slice(1)) learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true);
    assert.equal(learner.offset, ID_SLOT - SESSION_SLOT);
});

test("learning gives up when no slot ever matches; ids then stay unknown", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    learner.noteStream(CONN, 999_996);
    const stream = mem.add(0x7000_0000n, 12, 1, 3);
    for (let i = 0; i < MAX_LEARNING_OBSERVATIONS; i++) learner.streamId(mem, stream, SESSION_SLOT, CONN, true);
    assert.equal(learner.learning, "failed");
    assert.equal(learner.streamId(mem, stream, SESSION_SLOT, CONN, true), null);
});

// ---- seeded offset (cross-run hint) -------------------------------------------

test("a seeded id_ offset is used at once and confirmed by matching frame stream ids", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    const settled: boolean[] = [];
    learner.onSeedSettled = (holds) => settled.push(holds);
    learner.enableOracle();
    assert.equal(learner.seedOffset(ID_SLOT - SESSION_SLOT), true);
    assert.equal(learner.validatedOffset, null);              // in use, but not confirmed yet
    const streams = c5Streams(mem, 4);
    // Egress records before any oracle id already get the real id.
    assert.equal(learner.streamId(mem, streams[0].stream, SESSION_SLOT, CONN, false), 12);
    for (const s of streams) learner.noteStream(CONN, s.id);
    assert.deepEqual(streams.map((s) => learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true)), [12, 16, 20, 24]);
    assert.deepEqual(settled, [true]);
    assert.equal(learner.validatedOffset, ID_SLOT - SESSION_SLOT);
    assert.equal(learner.learning, "learned");
});

test("a seeded id_ offset contradicted by the frame ids reverts to learning, which finds the real slot", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    const settled: boolean[] = [];
    learner.onSeedSettled = (holds) => settled.push(holds);
    learner.enableOracle();
    learner.seedOffset(URGENCY_SLOT - SESSION_SLOT);       // a stale offset: priority_, not id_
    const streams = c5Streams(mem, 8);
    for (const s of streams) learner.noteStream(CONN, s.id);
    assert.equal(learner.streamId(mem, streams[0].stream, SESSION_SLOT, CONN, true), 0);
    assert.deepEqual(settled, []);                        // one miss is tolerated (MAX_MISSES)
    assert.equal(learner.streamId(mem, streams[1].stream, SESSION_SLOT, CONN, true), null);
    assert.deepEqual(settled, [false]);
    assert.equal(learner.learning, "learning");
    for (const s of streams.slice(2)) learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true);
    assert.equal(learner.offset, ID_SLOT - SESSION_SLOT);
    assert.deepEqual(settled, [false]);                   // learning afterwards does not settle the seed again
});

test("a seeded id_ offset is used before the frame hooks are live and checked once they are", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    const settled: boolean[] = [];
    learner.onSeedSettled = (holds) => settled.push(holds);
    learner.seedOffset(ID_SLOT - SESSION_SLOT);
    const streams = c5Streams(mem, 4);
    // Frame-hook anchor scan still running: the seed, not the legacy slot (which reads 0).
    assert.deepEqual(streams.map((s) => learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true)), [12, 16, 20, 24]);
    assert.deepEqual(settled, []);
    learner.enableOracle();
    for (const s of streams) learner.noteStream(CONN, s.id);
    assert.deepEqual(streams.map((s) => learner.streamId(mem, s.stream, SESSION_SLOT, CONN, true)), [12, 16, 20, 24]);
    assert.deepEqual(settled, [true]);
});

test("a seed is ignored once learning started or when outside the scan window", () => {
    const learner = new QuicheStreamIdLearner();
    assert.equal(learner.seedOffset(0x400), false);
    assert.equal(learner.seedOffset(0x50), true);
    assert.equal(learner.seedOffset(0x58), false);
    assert.equal(learner.offset, 0x50);
});

test("while the frame hooks are being located the legacy slot is not trusted; once they fail it is", () => {
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    mem.add(0x7000_0000n, 12, 4, 3);
    learner.awaitOracle();
    assert.equal(learner.learning, "awaiting");
    assert.equal(learner.streamId(mem, 0x7000_0000n, SESSION_SLOT, CONN, true), null);
    learner.oracleUnavailable();
    assert.equal(learner.learning, "legacy");
    assert.equal(learner.streamId(mem, 0x7000_0000n, SESSION_SLOT, CONN, true), 4);
});

test("awaiting ends when the frame hooks go live; a late awaitOracle is ignored", () => {
    const learner = new QuicheStreamIdLearner();
    learner.awaitOracle();
    learner.enableOracle();
    assert.equal(learner.learning, "learning");
    learner.awaitOracle();
    assert.equal(learner.learning, "learning");
});
