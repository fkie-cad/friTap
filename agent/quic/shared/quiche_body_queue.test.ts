// Unit tests for holding de-framed QUIC bodies while QuicStream::id_ is learned
// (quiche_body_queue.ts, reportQuicheBody in quiche_frame_capture.ts).
//
// Run: npm run test:agent
//
// WHY: on a cold Chrome run, bodies sent before the learner settles would carry
// stream id -1, and the host would merge a WriteOrBufferBody chunk into an
// unrelated frame-path request flow.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { Address, QuicheMemory } from "./quiche_layout.js";
import {
    MAX_LEARNING_OBSERVATIONS, QuicheStreamIdLearner, isStreamIdPending, lazyStreamIdWindow, readStreamIdWindow,
} from "./quiche_stream_id.js";
import { MAX_PENDING_BODY_HOLD_MS, PENDING_BODY_TIMEOUT_MS, PendingBody, QuicheBodyQueue } from "./quiche_body_queue.js";
import { attachBodyQueue, awaitFrameHookOutcome, emitFragment, reportQuicheBody } from "./quiche_frame_capture.js";
import { QuicheLayoutState, QuicheStreamRecord } from "./quiche_records.js";
import { runPreShutdownFlushes } from "../../shared/pre_shutdown.js";

const G = globalThis as any;
const SESSION_SLOT = 0x80;
const ID_SLOT = 0xd0;               // session_ + 0x50 (current QUICHE)
let nextConnection = 0;

class StreamMemory implements QuicheMemory {
    readonly pointerSize = 8;
    private readonly objects = new Map<bigint, Uint8Array>();
    reads = 0;

    add(stream: bigint, id: number): bigint {
        const bytes = new Uint8Array(0x200);
        const view = new DataView(bytes.buffer);
        view.setUint32(ID_SLOT, id, true);
        view.setUint32(0xb8, 0x10000 + id * 977, true);
        this.objects.set(stream, bytes);
        return stream;
    }
    readPointer(_a: Address): Address | null { return null; }
    readBytes(a: Address, length: number): Uint8Array | null {
        this.reads++;
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

interface Sent { streamId: number; payload: string; text: string; heldMs?: number; }

function capture(body: () => void): Sent[] {
    const previous = G.send;
    const sent: Sent[] = [];
    G.send = (msg: any, data: ArrayBuffer) => {
        sent.push({ streamId: msg.stream_id, payload: msg.quic_payload, text: new TextDecoder().decode(data),
                    heldMs: msg.held_ms });
    };
    try {
        body();
    } finally {
        G.send = previous;
    }
    return sent;
}

/** Module state of one learner (each test gets its own body queue). */
const states = new WeakMap<QuicheStreamIdLearner, QuicheLayoutState>();
function stateOf(learner: QuicheStreamIdLearner, mem: StreamMemory): QuicheLayoutState {
    let state = states.get(learner);
    if (state === undefined) {
        state = { moduleName: "test", mem, streamIds: learner } as QuicheLayoutState;
        states.set(learner, state);
    }
    return state;
}

/** A body record built the way streamLinkedRecord builds it. */
function bodyRecord(learner: QuicheStreamIdLearner, mem: StreamMemory, conn: string, stream: bigint,
                    canTeach: boolean): QuicheStreamRecord {
    const window = lazyStreamIdWindow(mem, stream, SESSION_SLOT);
    const streamId = learner.streamId(mem, stream, SESSION_SLOT, conn, canTeach, window);
    const record: QuicheStreamRecord = { message: { ssl_session_id: conn }, streamId, connection: 0x7201de3600n };
    if (streamId === null && isStreamIdPending(learner.learning)) record.pending = { state: stateOf(learner, mem), window };
    return record;
}

function report(learner: QuicheStreamIdLearner, mem: StreamMemory, conn: string, stream: bigint,
                canTeach: boolean, text: string): void {
    reportQuicheBody(bodyRecord(learner, mem, conn, stream, canTeach), new TextEncoder().encode(text).buffer, true);
}

/** Learner with the frame oracle live and streams 12, 16, 20, ... registered on `conn`. */
function learningSetup(count: number) {
    const conn = `bq-${nextConnection++}`;
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    const streams: bigint[] = [];
    for (let i = 0; i < count; i++) {
        const id = 12 + 4 * i;
        streams.push(mem.add(0x7000_0000n + BigInt(i) * 0x1000n, id));
        learner.noteStream(conn, id);
    }
    return { conn, mem, learner, streams };
}

test("bodies are held while learning, then flushed with their real ids in arrival order", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const sent = capture(() => {
        report(learner, mem, conn, streams[0], false, "egress-12");    // egress never teaches
        report(learner, mem, conn, streams[0], true, "in-12");
        report(learner, mem, conn, streams[1], true, "in-16");
        report(learner, mem, conn, streams[2], true, "in-20");
        assert.equal(learner.learning, "learning");
        report(learner, mem, conn, streams[3], true, "in-24");         // 4th distinct match: learned
    });
    assert.equal(learner.learning, "learned");
    assert.deepEqual(sent.map((s) => [s.streamId, s.text]), [
        [12, "egress-12"], [12, "in-12"], [16, "in-16"], [20, "in-20"], [24, "in-24"],
    ]);
    assert.ok(sent.every((s) => s.payload === "body"));
    // Held records carry held_ms; the teaching record went out directly and does not.
    assert.ok(sent.slice(0, 4).every((s) => Number.isInteger(s.heldMs) && s.heldMs! >= 0));
    assert.equal(sent[4].heldMs, undefined);
});

test("pre-shutdown releases held bodies with stream id -1", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const held = capture(() => {
        report(learner, mem, conn, streams[0], true, "in-12");
        report(learner, mem, conn, streams[1], true, "in-16");
    });
    assert.equal(held.length, 0);
    const sent = capture(() => runPreShutdownFlushes());
    assert.deepEqual(sent.map((s) => [s.streamId, s.text]), [[-1, "in-12"], [-1, "in-16"]]);
    assert.ok(sent.every((s) => s.heldMs !== undefined));
});

test("nothing is sent while the learner is still learning", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const sent = capture(() => {
        report(learner, mem, conn, streams[0], false, "egress");
        report(learner, mem, conn, streams[1], true, "in");
    });
    assert.deepEqual(sent, []);
});

test("a held egress body of a frame-owned stream is dropped at flush, not duplicated", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const sent = capture(() => {
        const frame = (streamId: number, offset: number, text: string) => emitFragment(
            { message: { ssl_session_id: conn }, streamId }, "write", offset, new TextEncoder().encode(text), false);
        frame(0, 4096, "mid");                                         // pre-attach connection: bodies mode
        report(learner, mem, conn, streams[0], false, "egress-12");    // held: id unknown
        frame(12, 0, "HEADERS+DATA");                                  // stream 12 opened after the hooks
        for (let i = 0; i < 4; i++) report(learner, mem, conn, streams[i], true, `in-${12 + 4 * i}`);
    });
    assert.deepEqual(sent.filter((s) => s.payload === "body").map((s) => [s.streamId, s.text]),
                     [[16, "in-16"], [20, "in-20"], [24, "in-24"]]);
    assert.equal(sent.filter((s) => s.text === "egress-12").length, 0);
});

test("a held teaching record reads its stream window once, shared with the learner", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const sent = capture(() => {
        mem.reads = 0;
        report(learner, mem, conn, streams[0], true, "in-12");
        assert.equal(mem.reads, 1);
        report(learner, mem, conn, streams[1], false, "egress-16");   // no teaching: read only to hold
        assert.equal(mem.reads, 2);
    });
    assert.deepEqual(sent, []);
});

test("a body of a frames-mode connection is dropped without being held or read", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const sent = capture(() => {
        emitFragment({ message: { ssl_session_id: conn }, streamId: 2 }, "write", 0,
                     new TextEncoder().encode("SETTINGS"), false);           // uni stream at 0: frames
        mem.reads = 0;
        report(learner, mem, conn, streams[0], false, "egress-12");
        assert.equal(mem.reads, 0);
    });
    assert.equal(stateOf(learner, mem).bodyQueue, undefined);
    assert.deepEqual(sent.filter((s) => s.payload === "body"), []);
});

test("learning failure flushes the held bodies with stream id -1", () => {
    const conn = `bq-${nextConnection++}`;
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    learner.enableOracle();
    learner.noteStream(conn, 999_999);                                 // never matches any slot
    const streams = Array.from({ length: 8 }, (_, i) => mem.add(0x7100_0000n + BigInt(i) * 0x1000n, 12 + 4 * i));
    const sent = capture(() => {
        for (let i = 0; i < MAX_LEARNING_OBSERVATIONS; i++) report(learner, mem, conn, streams[i % 8], true, `b${i}`);
    });
    assert.equal(learner.learning, "failed");
    assert.equal(sent.length, MAX_LEARNING_OBSERVATIONS);
    assert.ok(sent.every((s) => s.streamId === -1));
    assert.deepEqual(sent.map((s) => s.text), Array.from({ length: MAX_LEARNING_OBSERVATIONS }, (_, i) => `b${i}`));
});

function entry(key: string, size: number): PendingBody<string> {
    return { record: key, data: new ArrayBuffer(size), window: null };
}

test("queue bound: past the record limit the oldest go out with an unknown id", () => {
    const released: Array<[string, number | null]> = [];
    const queue = new QuicheBodyQueue<string>((e, id) => released.push([e.record, id]), 3, 1 << 20);
    for (const k of ["a", "b", "c", "d", "e"]) queue.push(entry(k, 10));
    assert.deepEqual(released, [["a", null], ["b", null]]);
    assert.equal(queue.size, 3);
    queue.flush(() => 7);
    assert.deepEqual(released.slice(2), [["c", 7], ["d", 7], ["e", 7]]);
    assert.equal(queue.size, 0);
    assert.equal(queue.heldBytes, 0);
});

test("queue bound: past the byte limit the oldest go out, and an oversized record is not held", () => {
    const released: string[] = [];
    const queue = new QuicheBodyQueue<string>((e) => released.push(e.record), 100, 1000);
    queue.push(entry("a", 400));
    queue.push(entry("b", 400));
    queue.push(entry("c", 400));
    assert.deepEqual(released, ["a"]);
    assert.equal(queue.heldBytes, 800);
    queue.push(entry("huge", 5000));
    assert.deepEqual(released, ["a", "b", "c", "huge"]);
    assert.equal(queue.size, 0);
});

test("a learned offset reads each held record's id from its own window copy", () => {
    const { conn, mem, learner, streams } = learningSetup(4);
    const windows = streams.map((s) => readStreamIdWindow(mem, s, SESSION_SLOT));
    assert.equal(learner.streamIdFromWindow(windows[0]), null);        // not learned yet
    for (let i = 0; i < 4; i++) learner.streamId(mem, streams[i], SESSION_SLOT, conn, true);
    assert.deepEqual(windows.map((w) => learner.streamIdFromWindow(w)), [12, 16, 20, 24]);
    assert.equal(learner.streamIdFromWindow(null), null);
});

/** Manual timer: `fire()` runs the armed callback. */
function fakeTimer(shuttingDown = false) {
    const armed = new Map<number, () => void>();
    let next = 1;
    const delays: number[] = [];
    const time = { ms: 10_000 };
    return {
        armed, delays, time,
        clock: {
            timeoutMs: PENDING_BODY_TIMEOUT_MS,
            now: () => time.ms,
            schedule: (fn: () => void, ms: number) => { delays.push(ms); armed.set(next, fn); return next++; },
            cancel: (h: unknown) => { armed.delete(h as number); },
            isShuttingDown: () => shuttingDown,
        },
        fire() { const [h, fn] = [...armed][0]; armed.delete(h); fn(); },
    };
}

// The hold bound caps how late a held record's receive time can be.
test("the hold limit is 1.5 s or less", () => {
    assert.ok(PENDING_BODY_TIMEOUT_MS > 0 && PENDING_BODY_TIMEOUT_MS <= 1500);
});

test("each released record carries the ms it was held", () => {
    const t = fakeTimer();
    const released: Array<[string, number]> = [];
    const queue = new QuicheBodyQueue<string>((e, _id, heldMs) => released.push([e.record, heldMs]), 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    t.time.ms += 300;
    queue.push(entry("b", 10));
    t.time.ms += 200;
    queue.flush(() => 4);
    assert.deepEqual(released, [["a", 500], ["b", 200]]);
});

test("pre-shutdown releases held records with an unknown id", () => {
    const t = fakeTimer();
    const released: Array<[string, number | null]> = [];
    const queue = new QuicheBodyQueue<string>((e, id) => released.push([e.record, id]), 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    runPreShutdownFlushes();
    assert.deepEqual(released, [["a", null]]);
    assert.equal(queue.timerArmed, false);
});

test("timeout: held records go out with an unknown id after the hold limit; one timer per holding period", () => {
    const t = fakeTimer();
    const released: Array<[string, number | null]> = [];
    const queue = new QuicheBodyQueue<string>((e, id) => released.push([e.record, id]), 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    queue.push(entry("b", 10));
    assert.deepEqual(t.delays, [PENDING_BODY_TIMEOUT_MS]);            // armed once, not per record
    t.fire();
    assert.deepEqual(released, [["a", null], ["b", null]]);
    assert.equal(queue.size, 0);
    assert.equal(queue.timerArmed, false);
    queue.push(entry("c", 10));                                      // a new holding period re-arms
    assert.equal(t.armed.size, 1);
});

test("timeout: a flush before the limit cancels the timer", () => {
    const t = fakeTimer();
    const released: Array<[string, number | null]> = [];
    const queue = new QuicheBodyQueue<string>((e, id) => released.push([e.record, id]), 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    assert.equal(t.armed.size, 1);
    queue.flush(() => 4);
    assert.equal(t.armed.size, 0);
    assert.equal(queue.timerArmed, false);
    assert.deepEqual(released, [["a", 4]]);
});

test("timeout: an overflow that drains the queue cancels the timer", () => {
    const t = fakeTimer();
    const queue = new QuicheBodyQueue<string>(() => {}, 256, 100, t.clock);
    queue.push(entry("huge", 500));
    assert.equal(t.armed.size, 0);
    assert.equal(queue.timerArmed, false);
});

test("timeout: once shutdown is flagged the callback releases nothing", () => {
    const t = fakeTimer(true);
    const released: string[] = [];
    const queue = new QuicheBodyQueue<string>((e) => released.push(e.record), 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    t.fire();
    assert.deepEqual(released, []);
});

test("timeout: a throwing release never escapes the timer callback", () => {
    const t = fakeTimer();
    const queue = new QuicheBodyQueue<string>(() => { throw new Error("boom"); }, 256, 1 << 20, t.clock);
    queue.push(entry("a", 10));
    assert.doesNotThrow(() => t.fire());
});

test("the extended hold (frame hooks still pending) is bounded to 15 s", () => {
    assert.ok(MAX_PENDING_BODY_HOLD_MS > PENDING_BODY_TIMEOUT_MS && MAX_PENDING_BODY_HOLD_MS <= 15_000);
});

// Cold Chrome run: the body hooks attach seconds before the frame locator settles;
// the legacy slot read in that window put stream id 0 on 19 bodies.

const LEGACY_SLOT = SESSION_SLOT - 8;

interface Released { text: string; id: number | null; heldMs: number; frameHooksLive?: boolean; }

/** A learner awaiting the frame hooks, its queue on a fake clock, and streams 12, 16, ... (legacy slot 0x40+i). */
function gateSetup(count: number) {
    const conn = `bq-${nextConnection++}`;
    const mem = new StreamMemory();
    const learner = new QuicheStreamIdLearner();
    const t = fakeTimer();
    const released: Released[] = [];
    const queue = attachBodyQueue(new QuicheBodyQueue<QuicheStreamRecord>((e, id, heldMs) => released.push({
        text: new TextDecoder().decode(e.data), id, heldMs, frameHooksLive: e.frameHooksLive,
    }), 256, 1 << 20, t.clock), learner);
    const state = { moduleName: "test", mem, streamIds: learner, bodyQueue: queue } as QuicheLayoutState;
    const streams: bigint[] = [];
    for (let i = 0; i < count; i++) {
        const stream = mem.add(0x7300_0000n + BigInt(i) * 0x1000n, 12 + 4 * i);
        new DataView((mem as any).objects.get(stream).buffer).setUint32(LEGACY_SLOT, 0x40 + i, true);
        streams.push(stream);
    }
    let settle!: (hooked: boolean) => void;
    let fail!: (e: Error) => void;
    const install = new Promise<boolean>((resolve, reject) => { settle = resolve; fail = reject; });
    awaitFrameHookOutcome(learner, install, () => queue);
    const report = (i: number, canTeach: boolean, frameHooksLive: boolean, text: string) => {
        const window = lazyStreamIdWindow(mem, streams[i], SESSION_SLOT);
        const streamId = learner.streamId(mem, streams[i], SESSION_SLOT, conn, canTeach, window);
        const record: QuicheStreamRecord = { message: { ssl_session_id: conn }, streamId, connection: 0x7301de3600n };
        if (streamId === null && isStreamIdPending(learner.learning)) record.pending = { state, window };
        reportQuicheBody(record, new TextEncoder().encode(text).buffer, frameHooksLive);
    };
    return { conn, learner, t, released, queue, report, settle, fail, install };
}

const settled = () => new Promise((resolve) => setImmediate(resolve));

test("frame hooks pending: bodies are held, never sent with the legacy slot", () => {
    const g = gateSetup(4);
    assert.equal(g.learner.learning, "awaiting");
    const sent = capture(() => {
        g.report(0, true, false, "in");
        g.report(1, false, false, "out");
    });
    assert.deepEqual(sent, []);
    assert.deepEqual(g.released, []);
    assert.equal(g.queue.size, 2);
});

test("frame hooks pending: the timeout keeps holding up to the 15 s bound, then releases unattributed", () => {
    const g = gateSetup(1);
    g.report(0, true, false, "a");
    for (let held = PENDING_BODY_TIMEOUT_MS; held < MAX_PENDING_BODY_HOLD_MS; held += PENDING_BODY_TIMEOUT_MS) {
        g.t.time.ms += PENDING_BODY_TIMEOUT_MS;
        g.t.fire();
        assert.deepEqual(g.released, [], `released after ${held} ms`);
        assert.equal(g.queue.timerArmed, true);
    }
    g.t.time.ms += PENDING_BODY_TIMEOUT_MS;
    g.t.fire();
    assert.deepEqual(g.released.map((r) => [r.text, r.id, r.heldMs]), [["a", null, MAX_PENDING_BODY_HOLD_MS]]);
});

test("frame hooks go live and id_ is learned: held bodies get their real ids", async () => {
    const g = gateSetup(4);
    g.report(0, false, false, "w0");
    g.report(1, true, false, "r1");
    g.t.time.ms += 6000;
    g.t.fire();                                                         // still pending: held on
    g.settle(true);
    await settled();
    assert.equal(g.learner.learning, "learning");
    assert.equal(g.queue.size, 2);
    assert.deepEqual(g.t.delays.slice(-1), [PENDING_BODY_TIMEOUT_MS]);  // fresh timeout for learning
    for (let i = 0; i < 4; i++) g.learner.noteStream(g.conn, 12 + 4 * i);
    for (let i = 0; i < 4; i++) g.report(i, true, true, `t${i}`);
    assert.equal(g.learner.learning, "learned");
    assert.deepEqual(g.released.slice(0, 2).map((r) => [r.text, r.id, r.frameHooksLive]),
                     [["w0", 12, false], ["r1", 16, false]]);
    assert.ok(g.released[0].heldMs >= 6000);
});

test("frame hooks live, id_ still learning: the hold outlasts the 1.5 s timeout until learned", async () => {
    const g = gateSetup(4);
    g.report(0, false, false, "w0");
    g.settle(true);
    await settled();
    assert.equal(g.learner.learning, "learning");
    for (let i = 0; i < 4; i++) {                                       // ~6 s of learning on Chrome
        g.t.time.ms += PENDING_BODY_TIMEOUT_MS;
        g.t.fire();
    }
    assert.deepEqual(g.released, []);
    for (let i = 0; i < 4; i++) g.learner.noteStream(g.conn, 12 + 4 * i);
    for (let i = 0; i < 4; i++) g.report(i, true, true, `t${i}`);
    assert.equal(g.learner.learning, "learned");
    assert.deepEqual(g.released.slice(0, 1).map((r) => [r.text, r.id]), [["w0", 12]]);
});

test("frame hooks fail: held bodies go out with the legacy slot of their own window", async () => {
    const g = gateSetup(3);
    for (let i = 0; i < 3; i++) g.report(i, i % 2 === 0, false, `b${i}`);
    g.settle(false);
    await settled();
    assert.equal(g.learner.learning, "legacy");
    assert.deepEqual(g.released.map((r) => [r.text, r.id]), [["b0", 0x40], ["b1", 0x41], ["b2", 0x42]]);
    assert.equal(g.queue.timerArmed, false);
    const sent = capture(() => g.report(0, true, false, "late"));    // later bodies: legacy slot, not held
    assert.deepEqual(sent.map((s) => s.streamId), [0x40]);
});

test("a rejected install counts as failed; one rejecting after the hooks went live does not fall back", async () => {
    const g = gateSetup(1);
    g.report(0, true, false, "a");
    g.fail(new Error("locator threw"));
    await settled();
    assert.deepEqual(g.released.map((r) => r.id), [0x40]);

    const live = gateSetup(1);
    live.report(0, true, false, "b");
    live.learner.enableOracle();                                       // hooks attached, then a later step threw
    live.fail(new Error("crypto binding threw"));
    await settled();
    assert.equal(live.learner.learning, "learning");
    assert.deepEqual(live.released, []);
});

test("warm run: a seeded id_ offset is used while the frame hooks are pending (nothing held)", () => {
    const g = gateSetup(2);
    assert.ok(g.learner.seedOffset(ID_SLOT - SESSION_SLOT));
    const sent = capture(() => g.report(1, true, false, "warm"));
    assert.deepEqual(sent.map((s) => s.streamId), [16]);
    assert.equal(g.queue.size, 0);
});

test("pre-shutdown during the pending window releases held bodies unattributed", () => {
    const g = gateSetup(1);
    g.report(0, true, false, "a");
    runPreShutdownFlushes();
    assert.deepEqual(g.released.map((r) => r.id), [null]);
});
