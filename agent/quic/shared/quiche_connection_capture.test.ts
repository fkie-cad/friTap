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
