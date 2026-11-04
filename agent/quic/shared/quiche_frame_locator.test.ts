// Unit tests for the Google QUICHE STREAM-frame locator (quiche_frame_locator.ts).
//
// Run: npm run test:agent
//
// WHY: Chrome's libmonochrome is stripped and its byte patterns drift per build.
// QuicConnection::OnStreamFrame / QuicSession::WriteStreamData are located by
// the QUIC error-detail literals they reference; a hook must only be placed
// when every load site of every anchor lies in ONE function. Fixtures are the
// real function bounds measured in Chrome 133.0.6943.137 libmonochrome_64.so.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { MAX_FUNCTION_BYTES, agreeOnFunction } from "./quiche_frame_locator.js";

const ON_STREAM_FRAME = { start: 0x54e74b4, size: 0x1c4 };
const WRITE_STREAM_DATA = { start: 0x551c06c, size: 0xe8 };

test("both OnStreamFrame anchors resolving to one function pick it", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], [ON_STREAM_FRAME]]), 0x54e74b4);
    assert.equal(agreeOnFunction([[WRITE_STREAM_DATA]]), 0x551c06c);
});

test("anchors that disagree, or one anchor used in two functions, pick nothing", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], [WRITE_STREAM_DATA]]), null);
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME, WRITE_STREAM_DATA]]), null);
});

test("a missing anchor, an unbounded site or an oversized function picks nothing", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], []]), null);
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME, null]]), null);
    assert.equal(agreeOnFunction([[{ start: 0x1000, size: MAX_FUNCTION_BYTES + 4 }]]), null);
    assert.equal(agreeOnFunction([]), null);
});

test("a function whose FDE size is unknown is still accepted when all sites agree", () => {
    assert.equal(agreeOnFunction([[{ start: 0x2000, size: null }, { start: 0x2000, size: null }]]), 0x2000);
});
