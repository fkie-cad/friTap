// Unit tests for holding egress QUIC chunks until their connection resolves
// (quiche_egress_hold.ts, releaseHeldEgress in quiche_frame_capture.ts).
//
// Run: npm run test:agent
//
// WHY: held chunks must survive LRU eviction and shutdown, and a connection
// that never resolves must not lose every request header.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { HoldClock } from "./hold_timer.js";
import {
    EgressReleaseReason, EGRESS_HOLD_TIMEOUT_MS, HeldChunk, MAX_EGRESS_HOLD_MS, QuicheEgressHold,
} from "./quiche_egress_hold.js";
import { releaseHeldEgress } from "./quiche_frame_capture.js";
import { Address, QuicheMemory } from "./quiche_layout.js";
import { isSessionLayoutPending, QuicheLayoutState } from "./quiche_records.js";
import { runPreShutdownFlushes } from "../../shared/pre_shutdown.js";

const G = globalThis as any;

class FakeClock implements HoldClock {
    timeoutMs = EGRESS_HOLD_TIMEOUT_MS;
    time = 0;
    shuttingDown = false;
    scheduled: { fn: () => void; at: number; cancelled: boolean }[] = [];
    now = () => this.time;
    schedule = (fn: () => void, ms: number) => {
        const handle = { fn, at: this.time + ms, cancelled: false };
        this.scheduled.push(handle);
        return handle;
    };
    cancel = (handle: unknown) => { (handle as { cancelled: boolean }).cancelled = true; };
    isShuttingDown = () => this.shuttingDown;
    get live() { return this.scheduled.filter((t) => !t.cancelled); }
    /** Advance to `ms` and fire every due, uncancelled timer once. */
    advance(ms: number): void {
        this.time = ms;
        for (const t of [...this.scheduled]) {
            if (!t.cancelled && t.at <= ms) { t.cancelled = true; t.fn(); }
        }
    }
}

interface Released { key: string; held: number[]; reason: EgressReleaseReason; }

const chunksOf = (held: HeldChunk<number>[]) => held.map((h) => h.chunk);

function newHold(maxSessions = 4, maxChunks = 8, maxBytes = 1 << 20) {
    const clock = new FakeClock();
    const released: Released[] = [];
    const heldMs: number[][] = [];
    const hold = new QuicheEgressHold<number>((key, held, reason) => {
        released.push({ key, held: chunksOf(held), reason });
        heldMs.push(held.map((h) => h.heldMs));
    }, { maxSessions, maxChunks, maxBytes, sizeOf: (n) => n, clock });
    return { clock, released, heldMs, hold };
}

test("held chunks stay held until the timeout, then go out in order", () => {
    const { clock, released, hold } = newHold();
    hold.hold("s1", 1);
    hold.hold("s1", 2);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS - 1);
    assert.deepEqual(released, []);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released, [{ key: "s1", held: [1, 2], reason: "timeout" }]);
    assert.equal(hold.size, 0);
    assert.equal(hold.timerArmed, false);
});

test("one timer per holding period, not per chunk", () => {
    const { clock, hold } = newHold();
    for (let i = 0; i < 5; i++) hold.hold("s1", i);
    hold.hold("s2", 9);
    assert.equal(clock.scheduled.length, 1);
});

test("the timeout counts from a session's first chunk; later sessions get their own deadline", () => {
    const { clock, released, hold } = newHold();
    hold.hold("s1", 1);
    clock.time = 2000;
    hold.hold("s2", 2);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released.map((r) => r.key), ["s1"]);
    assert.equal(clock.live.length, 1);
    assert.equal(clock.live[0].at, 2000 + EGRESS_HOLD_TIMEOUT_MS);
    clock.advance(2000 + EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released.map((r) => r.key), ["s1", "s2"]);
});

test("take returns the held chunks and disarms the timer when nothing is left", () => {
    const { released, hold } = newHold();
    hold.hold("s1", 1);
    hold.hold("s1", 2);
    assert.deepEqual(chunksOf(hold.take("s1")), [1, 2]);
    assert.deepEqual(hold.take("s1"), []);
    assert.equal(hold.timerArmed, false);
    assert.deepEqual(released, []);
});

test("an LRU-evicted session is released, not dropped", () => {
    const { released, hold } = newHold(2);
    hold.hold("s1", 1);
    hold.hold("s2", 2);
    hold.hold("s3", 3);
    assert.deepEqual(released, [{ key: "s1", held: [1], reason: "evicted" }]);
    assert.equal(hold.size, 2);
});

test("past the per-session budget every held chunk goes out at once", () => {
    const { released, hold } = newHold(4, 3);
    for (let i = 1; i <= 4; i++) hold.hold("s1", i);
    assert.deepEqual(released, [{ key: "s1", held: [1, 2, 3, 4], reason: "budget" }]);
    assert.equal(hold.has("s1"), false);
});

test("pre-shutdown releases every held session before the shutdown flag", () => {
    runPreShutdownFlushes();
    const { released, hold } = newHold();
    hold.hold("s1", 1);
    hold.hold("s2", 2);
    runPreShutdownFlushes();
    assert.deepEqual(released, [
        { key: "s1", held: [1], reason: "shutdown" },
        { key: "s2", held: [2], reason: "shutdown" },
    ]);
    assert.equal(hold.timerArmed, false);
});

test("a timeout after shutdown started releases nothing (sends are dropped anyway)", () => {
    const { clock, released, hold } = newHold();
    hold.hold("s1", 1);
    clock.shuttingDown = true;
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released, []);
    runPreShutdownFlushes();
});

test("each released chunk carries the ms it was held, on timeout and on take", () => {
    const { clock, heldMs, hold } = newHold();
    hold.hold("s1", 1);
    clock.time = 1000;
    hold.hold("s1", 2);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(heldMs, [[EGRESS_HOLD_TIMEOUT_MS, EGRESS_HOLD_TIMEOUT_MS - 1000]]);
    hold.hold("s2", 3);
    clock.time += 250;
    assert.deepEqual(hold.take("s2"), [{ chunk: 3, heldMs: 250 }]);
});

test("past the total byte budget the oldest sessions go out first", () => {
    const { released, hold } = newHold(4, 8, 100);
    hold.hold("s1", 40);
    hold.hold("s2", 40);
    hold.hold("s3", 30);                          // 110 > 100: s1 (oldest) goes
    assert.deepEqual(released, [{ key: "s1", held: [40], reason: "budget" }]);
    assert.equal(hold.heldBytes, 70);
    hold.take("s2");
    assert.equal(hold.heldBytes, 30);
});

test("capacity eviction picks the oldest-held session even if another is written often", () => {
    const { released, hold } = newHold(2);
    hold.hold("s1", 1);
    hold.hold("s2", 2);
    for (let i = 0; i < 3; i++) { hold.has("s1"); hold.hold("s1", 10 + i); }
    hold.hold("s3", 3);
    assert.deepEqual(released, [{ key: "s1", held: [1, 10, 11, 12], reason: "evicted" }]);
});

test("byte-budget eviction picks the oldest-held session even if another is written often", () => {
    const { released, hold } = newHold(4, 8, 100);
    hold.hold("s1", 10);
    hold.hold("s2", 10);
    for (let i = 0; i < 3; i++) { hold.has("s1"); hold.hold("s1", 10); }
    hold.hold("s2", 60);                          // 110 > 100: s1 (oldest held) goes
    assert.deepEqual(released, [{ key: "s1", held: [10, 10, 10, 10], reason: "budget" }]);
    assert.equal(hold.heldBytes, 70);
});

test("a single chunk over the byte budget goes out at once", () => {
    const { released, hold } = newHold(4, 8, 100);
    hold.hold("s1", 500);
    assert.deepEqual(released, [{ key: "s1", held: [500], reason: "budget" }]);
    assert.equal(hold.heldBytes, 0);
    assert.equal(hold.timerArmed, false);
});

test("eviction and timeout release the held bytes too", () => {
    const { clock, hold } = newHold(1);
    hold.hold("s1", 10);
    hold.hold("s2", 20);                          // evicts s1
    assert.equal(hold.heldBytes, 20);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.equal(hold.heldBytes, 0);
});

test("a taken session is not released again before shutdown", () => {
    runPreShutdownFlushes();
    const { released, hold } = newHold();
    hold.hold("s1", 1);
    hold.take("s1");
    hold.hold("s2", 2);
    runPreShutdownFlushes();
    assert.deepEqual(released, [{ key: "s2", held: [2], reason: "shutdown" }]);
});

// WHY: released under the session's key while the session layout was still being
// learned, a stream's offset-0 chunk split from its later connection-keyed ones.
test("a timeout keeps holding while holdWhile is true, up to MAX_EGRESS_HOLD_MS", () => {
    const clock = new FakeClock();
    const released: Released[] = [];
    const hold = new QuicheEgressHold<number>((key, held, reason) => {
        released.push({ key, held: chunksOf(held), reason });
    }, { clock, holdWhile: (n) => n !== 9 });
    hold.hold("s1", 1);
    hold.hold("s9", 9);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released, [{ key: "s9", held: [9], reason: "timeout" }]);
    assert.ok(hold.has("s1") && hold.timerArmed);
    for (let t = 2 * EGRESS_HOLD_TIMEOUT_MS; t < MAX_EGRESS_HOLD_MS; t += EGRESS_HOLD_TIMEOUT_MS) clock.advance(t);
    assert.ok(hold.has("s1"));
    clock.advance(MAX_EGRESS_HOLD_MS);
    assert.deepEqual(released[1], { key: "s1", held: [1], reason: "timeout" });
    assert.equal(hold.timerArmed, false);
});

test("an extended session goes out on the first timeout after holdWhile turns false", () => {
    const clock = new FakeClock();
    const released: Released[] = [];
    let pending = true;
    const hold = new QuicheEgressHold<number>((key, held, reason) => {
        released.push({ key, held: chunksOf(held), reason });
    }, { clock, holdWhile: () => pending });
    hold.hold("s1", 1);
    clock.advance(EGRESS_HOLD_TIMEOUT_MS);
    assert.equal(released.length, 0);
    pending = false;
    clock.advance(2 * EGRESS_HOLD_TIMEOUT_MS);
    assert.deepEqual(released, [{ key: "s1", held: [1], reason: "timeout" }]);
});

// ---- releaseHeldEgress: the normal emit path with whatever addressing is known ----

class PointerMemory implements QuicheMemory {
    readonly pointerSize = 8;
    constructor(private readonly pointers: Map<Address, Address>) {}
    readPointer(a: Address): Address | null { return this.pointers.get(a) ?? null; }
    readBytes(_a: Address, _length: number): Uint8Array | null { return null; }
    isModuleAddress(_a: Address): boolean { return false; }
}

let nextSession = 0x7000_0000n;

function unresolvedState(pointers: Map<Address, Address>, sessionConnection: number | null): QuicheLayoutState {
    // connAttempts at the cap: no layout discovery runs against the fake memory.
    return { moduleName: "test", mem: new PointerMemory(pointers), layout: null, attempts: 0,
             triedStreams: new Set(), connLayout: null, sessionConnection, connAttempts: 1 << 30 } as QuicheLayoutState;
}

function sendsOf(body: () => void): any[] {
    const previous = G.send;
    const sent: any[] = [];
    G.send = (msg: any, data: ArrayBuffer | null) => {
        if (data) sent.push({ ...msg, text: new TextDecoder().decode(data) });
    };
    try { body(); } finally { G.send = previous; }
    return sent;
}

const bytes = (s: string) => new TextEncoder().encode(s);

test("the session layout is pending until learned or out of attempts", () => {
    const learning = { ...unresolvedState(new Map(), null), connAttempts: 0 } as QuicheLayoutState;
    assert.equal(isSessionLayoutPending(learning), true);
    assert.equal(isSessionLayoutPending(unresolvedState(new Map(), null)), false);
    assert.equal(isSessionLayoutPending({ ...learning, sessionConnection: 0x40 }), false);
});

test("unresolved session: chunks go out in order under a synthetic tuple keyed by the session", () => {
    const session = nextSession += 0x1000n;
    const state = unresolvedState(new Map(), null);
    const sent = sendsOf(() => releaseHeldEgress("0x" + session.toString(16), [
        { chunk: { state, session, streamId: 0, offset: 0, bytes: bytes("GET ") }, heldMs: 1200 },
        { chunk: { state, session, streamId: 0, offset: 4, bytes: bytes("/x") }, heldMs: 700 },
    ], "timeout"));
    const chunks = sent.filter((m) => m.text !== "");
    assert.deepEqual(chunks.map((m) => [m.stream_offset, m.text]), [[0, "GET "], [4, "/x"]]);
    assert.ok(chunks.every((m) => m.endpoints_synthetic === true));
    assert.ok(chunks.every((m) => String(m.ssl_session_id).includes(session.toString(16))));
    assert.deepEqual(chunks.map((m) => m.held_ms), [1200, 700]);     // back-dated per chunk by the host
});

test("connection known but layout unresolved: keyed by the connection, like ingress", () => {
    const session = nextSession += 0x1000n;
    const connection = 0x5100_0000n + session;
    const state = unresolvedState(new Map([[session + 0x40n, connection]]), 0x40);
    const sent = sendsOf(() => releaseHeldEgress("0x" + session.toString(16), [
        { chunk: { state, session, streamId: 4, offset: 0, bytes: bytes("hdrs") }, heldMs: 0 },
    ], "evicted"));
    const chunk = sent.find((m) => m.text === "hdrs");
    assert.ok(chunk);
    assert.equal(chunk.endpoints_synthetic, true);
    assert.ok(String(chunk.ssl_session_id).includes(connection.toString(16)));
    assert.equal(chunk.held_ms, undefined);
});
