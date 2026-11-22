// Unit tests for the stream position on frame-path QUIC records (quiche_frame_capture.ts).
//
// Run: npm run test:agent
//
// WHY: the host rebuilds QUIC STREAM frames from these records, so every
// emitted chunk must carry its stream offset, and FIN only on the chunk that
// reaches the stream's final size.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { bodyHookReports, emitFragment } from "./quiche_frame_capture.js";
import { QuicStreamReassembler } from "./quic_stream_reassembler.js";

const G = globalThis as any;
const bytes = (s: string) => new TextEncoder().encode(s);
let nextConnection = 0;

interface Sent { offset: number; fin: boolean; text: string; }

/** Run `body` with a fresh connection key, returning the emitted stream chunks. */
function captureChunks(body: (record: { message: { [key: string]: any }; streamId: number }) => void): Sent[] {
    const previous = G.send;
    const sent: Sent[] = [];
    G.send = (msg: any, data: ArrayBuffer) => {
        sent.push({ offset: msg.stream_offset, fin: msg.fin === true, text: new TextDecoder().decode(data) });
    };
    try {
        body({ message: { ssl_session_id: `test-conn-${nextConnection++}` }, streamId: 0 });
    } finally {
        G.send = previous;
    }
    return sent;
}

test("in-order fragments carry their offsets; FIN only on the last chunk", () => {
    const sent = captureChunks((record) => {
        emitFragment(record, "read", 0, bytes("abc"), false);
        emitFragment(record, "read", 3, bytes("def"), false);
        emitFragment(record, "read", 6, bytes("gh"), true);
    });
    assert.deepEqual(sent, [
        { offset: 0, fin: false, text: "abc" },
        { offset: 3, fin: false, text: "def" },
        { offset: 6, fin: true, text: "gh" },
    ]);
});

test("out-of-order frames are reassembled with offsets in order", () => {
    const sent = captureChunks((record) => {
        emitFragment(record, "write", 6, bytes("gh"), true);   // FIN arrives first
        emitFragment(record, "write", 3, bytes("def"), false);
        emitFragment(record, "write", 0, bytes("abc"), false);
    });
    assert.deepEqual(sent, [
        { offset: 0, fin: false, text: "abc" },
        { offset: 3, fin: false, text: "def" },
        { offset: 6, fin: true, text: "gh" },
    ]);
});

test("a FIN frame that leaves a gap does not mark its chunk as final", () => {
    const sent = captureChunks((record) => {
        emitFragment(record, "read", 0, bytes("ab"), false);
        emitFragment(record, "read", 4, bytes("ef"), true);     // gap at 2..4
        emitFragment(record, "read", 2, bytes("cd"), false);
    });
    assert.deepEqual(sent, [
        { offset: 0, fin: false, text: "ab" },
        { offset: 2, fin: false, text: "cd" },
        { offset: 4, fin: true, text: "ef" },
    ]);
});

test("a stream without FIN never reports fin", () => {
    const sent = captureChunks((record) => {
        emitFragment(record, "read", 0, bytes("abc"), false);
        emitFragment(record, "read", 3, bytes("def"), false);
    });
    assert.deepEqual(sent.map((s) => s.fin), [false, false]);
});

test("reassembler marks only the chunk reaching the final size", () => {
    const r = new QuicStreamReassembler();
    assert.equal(r.push("s", 4, bytes("ef"), true).length, 0);
    const out = r.push("s", 0, bytes("abcd"));
    assert.deepEqual(out.map((c) => [c.offset, c.fin === true]), [[0, false], [4, true]]);
});

test("reassembler: a bare FIN after the data marks no chunk", () => {
    const r = new QuicStreamReassembler();
    assert.equal(r.push("s", 0, bytes("ab"))[0].fin, undefined);
    assert.deepEqual(r.push("s", 2, new Uint8Array(0), true), []);
});

// ---- frame path vs body path on one connection (Chrome run C5) -------------

/** Emit `text` as a frame-path chunk of `streamId` on `connection`; returns the chunks sent. */
function emitOn(connection: string, streamId: number, offset: number, text: string): Sent[] {
    const previous = G.send;
    const sent: Sent[] = [];
    G.send = (msg: any, data: ArrayBuffer) => {
        sent.push({ offset: msg.stream_offset, fin: msg.fin === true, text: new TextDecoder().decode(data) });
    };
    try {
        emitFragment({ message: { ssl_session_id: connection }, streamId }, "read", offset, bytes(text), false);
    } finally {
        G.send = previous;
    }
    return sent;
}

function bodyReported(connection: string, streamId: number | null): boolean {
    return bodyHookReports({ message: { ssl_session_id: connection }, streamId, connection: 0x7201de3600n });
}

test("C5: a frame-owned stream's body is skipped when the body record carries the real stream id", () => {
    const conn = `c5-${nextConnection++}`;
    emitOn(conn, 0, 4096, "mid");                                 // pre-attach connection: bodies mode
    assert.equal(emitOn(conn, 12, 0, "HEADERS+DATA").length, 1);  // request opened after the hooks
    assert.equal(bodyReported(conn, 12), false);
    // The C5 bug: the body record read a bogus id (0) from the legacy id_ slot,
    // missed stream 12's owner entry and was reported a second time.
    assert.equal(bodyReported(conn, 0), true);
});

test("a body-owned stream is never emitted by the frame path afterwards", () => {
    const conn = `c5-${nextConnection++}`;
    emitOn(conn, 0, 4096, "mid");
    assert.equal(bodyReported(conn, 16), true);
    assert.deepEqual(emitOn(conn, 16, 0, "late frames"), []);
});

test("an unknown-id body is dropped on a connection whose streams the frame path owns", () => {
    const conn = `c5-${nextConnection++}`;
    emitOn(conn, 0, 4096, "mid");
    assert.equal(bodyReported(conn, null), true);                 // no frame-owned stream yet
    emitOn(conn, 20, 0, "HEADERS");
    assert.equal(bodyReported(conn, null), false);
    assert.equal(bodyReported(conn, -1), false);
});

test("migration (generation #1): a stream continuing on the new key is reported by one path only", () => {
    const conn = `c5-${nextConnection++}`;
    emitOn(conn, 0, 4096, "mid");
    assert.equal(emitOn(conn, 24, 0, "before migration").length, 1);
    const migrated = `${conn}#1`;                                 // tracker re-keys on the new path
    assert.deepEqual(emitOn(migrated, 24, 16, "after migration"), []); // mid-stream on a new key
    assert.equal(bodyReported(migrated, 24), true);               // so the body path carries it
    assert.deepEqual(emitOn(migrated, 24, 31, "more"), []);
    // A request opened after the migration is frame-owned on the new key, its body skipped.
    assert.equal(emitOn(migrated, 28, 0, "new request").length, 1);
    assert.equal(bodyReported(migrated, 28), false);
});
