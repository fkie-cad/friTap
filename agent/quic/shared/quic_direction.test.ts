// Unit tests for buildQuicMessage 4-tuple orientation and its synthetic flag.
//
// Run: npm run test:agent
//
// WHY: QUIC send hooks (Google QUICHE WriteHeaders/WriteOrBufferBody, Cloudflare
// quiche_stream_send, Neqo send_request_body) emitted peer -> local like reads.
// The host orients records device -> server by direction, so a Chrome request's
// "server" became the device's own synthetic address ("GET 10.0.0.1/").

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildQuicMessage, QuicConnectionInfo, QuicConnectionTracker } from "./quic_connection_tracker.js";

const INFO: QuicConnectionInfo = {
    serverName: "", scid: "", dcid: "", ssFamily: "AF_INET",
    localAddr: 0x0A000001, localPort: 50000,
    peerAddr: 0x8EFA4A2E, peerPort: 443,
};

test("a QUIC read travels peer -> local (default)", () => {
    const m = buildQuicMessage(INFO, "0x1", "QuicSpdyStream_OnDataFramePayload");
    assert.deepEqual([m.src_addr, m.src_port, m.dst_addr, m.dst_port], [INFO.peerAddr, 443, INFO.localAddr, 50000]);
});

test("a QUIC write travels local -> peer", () => {
    const m = buildQuicMessage(INFO, "0x1", "QuicSpdyStream_WriteHeaders", "write");
    assert.deepEqual([m.src_addr, m.src_port, m.dst_addr, m.dst_port], [INFO.localAddr, 50000, INFO.peerAddr, 443]);
    assert.equal(m.function, "QuicSpdyStream_WriteHeaders");
    assert.equal(m.ssl_session_id, "0x1");
});

test("QUIC records carry their direction and producing library explicitly", () => {
    const read = buildQuicMessage(INFO, "0x1", "QuicConnection_OnStreamFrame", "read", "libmonochrome_64.so");
    const write = buildQuicMessage(INFO, "0x1", "QuicSession_WriteStreamData", "write");
    assert.equal(read.direction, "read");
    assert.equal(read.library, "libmonochrome_64.so");
    assert.equal(write.direction, "write");
    assert.equal("library" in write, false);
});

test("only a synthesized tuple is flagged endpoints_synthetic", () => {
    const tracker = new QuicConnectionTracker();
    const synthesized = buildQuicMessage(tracker.synthesizeInfo("0xabc"), "0xabc", "QuicSession_WriteStreamData", "write");
    assert.equal(synthesized.endpoints_synthetic, true);
    const real = buildQuicMessage(INFO, "0x1", "QuicSession_WriteStreamData", "write");
    assert.equal("endpoints_synthetic" in real, false);
});

test("a linked tuple is flagged only while its local side is guessed", () => {
    const tracker = new QuicConnectionTracker();
    const peer = { family: "AF_INET", addr: 0x8EFB9B77, port: 443 };
    const self = { family: "AF_INET", addr: 0xC0A80102, port: 51000 };
    const flag = (c: { info: QuicConnectionInfo; connKey: string }) =>
        buildQuicMessage(c.info, c.connKey, "f", "write").endpoints_synthetic;
    assert.equal(flag(tracker.resolveLinked("0x10", null, null)), true);
    const halfGuessed = tracker.resolveLinked("0x10", null, peer);
    assert.equal(flag(halfGuessed), true);
    const upgraded = tracker.resolveLinked("0x10", self, peer);
    assert.equal(upgraded.connKey, halfGuessed.connKey);
    assert.equal(flag(upgraded), undefined);
    assert.equal(flag(tracker.resolveLinked("0x20", self, peer)), undefined);
});
