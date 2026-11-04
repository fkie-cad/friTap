// Unit tests for buildQuicMessage 4-tuple orientation.
//
// Run: npm run test:agent
//
// WHY: QUIC send hooks (Google QUICHE WriteHeaders/WriteOrBufferBody, Cloudflare
// quiche_stream_send, Neqo send_request_body) emitted peer -> local like reads.
// The host orients records device -> server by direction, so a Chrome request's
// "server" became the device's own synthetic address ("GET 10.0.0.1/").

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildQuicMessage, QuicConnectionInfo } from "./quic_connection_tracker.js";

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
