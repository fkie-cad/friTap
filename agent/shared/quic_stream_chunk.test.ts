// Unit tests for sendQuicStreamChunk (agent/shared/shared_structures.ts).
//
// Run: npm run test:agent
//
// WHY: frame-path callers re-use one message object across chunks, so a FIN
// stamped on one chunk must not leak onto the next.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { sendQuicStreamChunk } from "./shared_structures.js";

const G = globalThis as any;

test("stamps stream_offset, fin, quic_payload and midstream; clears a stale fin", () => {
    const previous = G.send;
    const sent: any[] = [];
    G.send = (msg: any) => { sent.push({ ...msg }); };
    const message: { [key: string]: any } = { ssl_session_id: "0x1" };
    try {
        sendQuicStreamChunk(message, [1], 0, { offset: 0, fin: true, midstream: true });
        sendQuicStreamChunk(message, [2], 0, { offset: 1, fin: false, midstream: true });
    } finally {
        G.send = previous;
    }
    assert.deepEqual(sent.map((m) => [m.stream_offset, m.fin, m.quic_payload, m.quic_midstream, m.transport]),
                     [[0, true, "stream", true, "udp"], [1, undefined, "stream", true, "udp"]]);
});
