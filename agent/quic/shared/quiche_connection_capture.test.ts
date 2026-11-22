// Unit tests for the per-connection Google QUICHE capture-path choice
// (quiche_connection_capture.ts).
//
// Run: npm run test:agent
//
// WHY: raw STREAM-frame bytes decode (QPACK) only for connections seen from
// their start; connections that predate the hooks must keep the de-framed body
// path, and no connection may ever be reported by both paths.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { QuicheConnectionCapture, isUniStream } from "./quiche_connection_capture.js";

test("stream id bit 1 marks unidirectional streams", () => {
    assert.deepEqual([0, 1, 2, 3, 4, 6, 7, 10, 11].map(isUniStream),
                     [false, false, true, true, false, true, true, true, true]);
});

test("a connection first seen on a control stream at offset 0 is captured as frames", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.onFrame("0xc1", 2, 0), "frames");     // client control stream
    assert.equal(c.onFrame("0xc1", 0, 0), "frames");     // later request stream
    assert.equal(c.onBody("0xc1"), "frames");            // body hooks stay silent
    assert.equal(c.onFrame("0xc2", 3, 0), "frames");     // server control first also counts
});

test("a connection first seen mid-life uses the body path for good", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.onFrame("0xa", 8, 0), "bodies");      // request stream first
    assert.equal(c.onFrame("0xa", 2, 0), "bodies");      // no switch later
    assert.equal(c.onFrame("0xb", 10, 4096), "bodies");  // uni stream mid-way
    assert.equal(c.onBody("0xd"), "bodies");             // body hook first
    assert.equal(c.onFrame("0xd", 2, 0), "bodies");
});

test("modeOf reports a decided path without deciding one", () => {
    const capture = new QuicheConnectionCapture();
    assert.equal(capture.modeOf("0xc1"), undefined);
    assert.equal(capture.modeOf("0xc1"), undefined);
    capture.onBody("0xc1");
    assert.equal(capture.modeOf("0xc1"), "bodies");
});

// Per-stream ownership: a request opened after the hooks on a preconnected
// ("bodies") connection is captured raw by the frame path, never by both paths.

test("a bidi stream first chunked at offset 0 on a bodies connection is frame-owned (midstream)", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.onStreamFrame("0xa", 8, 4096), "bodies"); // decides the connection: bodies
    assert.equal(c.onStreamFrame("0xa", 12, 0), "midstream");
    assert.equal(c.onStreamFrame("0xa", 12, 1200), "midstream"); // later chunks keep the owner
    assert.equal(c.onBodyStream("0xa", 12), "midstream");        // body hook stays silent
    assert.equal(c.mayReportFrame("0xa", 12), true);
});

test("a bidi stream first chunked past offset 0 on a bodies connection stays with the body path", () => {
    const c = new QuicheConnectionCapture();
    c.onBody("0xa");
    assert.equal(c.onStreamFrame("0xa", 16, 512), "bodies");
    assert.equal(c.onStreamFrame("0xa", 16, 0), "bodies");       // decided on first sight
    assert.equal(c.onBodyStream("0xa", 16), "bodies");
    assert.equal(c.mayReportFrame("0xa", 16), false);
});

test("uni / control streams on a bodies connection are still dropped", () => {
    const c = new QuicheConnectionCapture();
    c.onBody("0xa");
    assert.equal(c.onStreamFrame("0xa", 2, 0), "bodies");
    assert.equal(c.onStreamFrame("0xa", 7, 0), "bodies");
    assert.equal(c.mayReportFrame("0xa", 6), false);
    assert.equal(c.onBodyStream("0xa", 3), "bodies");
});

test("a stream the body hook reports first keeps the body path", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.onBodyStream("0xa", 20), "bodies");
    assert.equal(c.onStreamFrame("0xa", 20, 0), "bodies");
    assert.equal(c.mayReportFrame("0xa", 20), false);
    assert.equal(c.onBodyStream("0xa", null), "bodies");          // unknown stream: per-connection rule
});

test("frames connections are unchanged by per-stream ownership", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.onStreamFrame("0xc1", 2, 0), "frames");
    assert.equal(c.onStreamFrame("0xc1", 0, 0), "frames");
    assert.equal(c.onStreamFrame("0xc1", 4, 900), "frames");
    assert.equal(c.onBodyStream("0xc1", 0), "frames");
    assert.equal(c.onBodyStream("0xc1", null), "frames");
    assert.equal(c.mayReportFrame("0xc1", 6), true);
});

test("mayReportFrame accepts undecided streams without deciding them", () => {
    const c = new QuicheConnectionCapture();
    assert.equal(c.mayReportFrame("0xa", 8), true);                // unknown connection
    c.onBody("0xa");
    assert.equal(c.mayReportFrame("0xa", 8), true);                // undecided bidi stream
    assert.equal(c.onStreamFrame("0xa", 8, 0), "midstream");      // still decidable afterwards
});

// Unknown body stream ids (QuicStream::id_ not located yet): never a duplicate.

test("an unknown-stream body is dropped once the frame path owns a stream of the connection", () => {
    const c = new QuicheConnectionCapture();
    c.onBody("0xa");
    assert.equal(c.onUnknownBodyStream("0xa"), "bodies");          // nothing frame-owned yet
    assert.equal(c.onStreamFrame("0xa", 12, 0), "midstream");
    assert.equal(c.onUnknownBodyStream("0xa"), "midstream");       // could be stream 12's bytes
    assert.equal(c.onBodyStream("0xa", null), "midstream");
    assert.equal(c.onUnknownBodyStream("0xb"), "bodies");          // other connections unaffected
});

test("ownership is symmetric: whichever path sees a stream first owns it, on one shared key", () => {
    const c = new QuicheConnectionCapture();
    c.onBody("0xa");
    // Frame first: the body path stays silent for that stream.
    assert.equal(c.onStreamFrame("0xa", 12, 0), "midstream");
    assert.equal(c.onBodyStream("0xa", 12), "midstream");
    // Body first: the frame path stays silent for that stream, even from offset 0.
    assert.equal(c.onBodyStream("0xa", 16), "bodies");
    assert.equal(c.mayReportFrame("0xa", 16), false);
    assert.equal(c.onStreamFrame("0xa", 16, 0), "bodies");
});
