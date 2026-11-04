// Unit tests for the stripped-BoringSSL SSL_read/SSL_write locator
// (boringssl_plaintext_locator.ts).
//
// Run: npm run test:agent
//
// WHY: Chrome's libmonochrome statically links a stripped BoringSSL, so friTap
// captured keys but no TCP TLS plaintext. The locator identifies SSL_read /
// SSL_write by the BoringSSL error reasons their ssl_lib.cc error sites raise.
// Fixtures are the real site tables of Chrome 133 libmonochrome_64.so (SSL_read
// calls SSL_peek) and of mainline Cronet's stable_cronet_libssl.so (SSL_peek
// inlined into SSL_read; ground truth from its exported symbols).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    ErrorSite, decodeErrorReason, peekShapedFunctions, pickSslReadImpl,
    pickSslWrite, reasonsByFunction, resolveSslRead,
} from "./boringssl_plaintext_locator.js";
import { blTargetOffset, movzW } from "../../shared/arm64.js";
import { searchSortedStarts } from "../../shared/eh_frame.js";

const MOV_W0_SSL = 0x52800200;        // mov w0, #0x10 (ERR_LIB_SSL)
const MOV_W1_WZR = 0x2a1f03e1;        // mov w1, wzr
const movW2 = (reason: number) => (0x52800002 | (reason << 5)) >>> 0;
const MOV_W4_LINE = 0x52807584;       // mov w4, #0x3ac
const ADRP_X3 = 0xb0fd90c3;           // adrp x3, ...
const ADD_X3 = 0x9120ac63;            // add x3, x3, #0x82b
const NOP = 0xd503201f;

test("decodes mov-immediate and BL encodings taken from libmonochrome", () => {
    assert.equal(movzW(movW2(0x42), 2), 0x42);
    assert.equal(movzW(MOV_W0_SSL, 0), 0x10);
    assert.equal(movzW(MOV_W0_SSL, 2), null);
    // 0x5410100: bl 0x51511b0 (Chrome's SSL_peek(ssl, &byte, 1) call site)
    assert.equal(blTargetOffset(0x5410100, 0x97f5042c), 0x51511b0);
    assert.equal(blTargetOffset(0x5410100, NOP), null);
});

test("an error site's reason is the mov w2 next to the __FILE__ load", () => {
    const window = [NOP, NOP, NOP, NOP, NOP, NOP, ADRP_X3, ADD_X3, MOV_W0_SSL, MOV_W1_WZR,
                    movW2(0xe2), MOV_W4_LINE, NOP];
    assert.equal(decodeErrorReason(window, 6), 0xe2);
});

test("a window without mov w0, #ERR_LIB_SSL is not an SSL error site", () => {
    const window = [NOP, NOP, NOP, NOP, NOP, NOP, ADRP_X3, ADD_X3, MOV_W1_WZR, movW2(0xe2), NOP];
    assert.equal(decodeErrorReason(window, 6), null);
});

// Chrome 133.0.6943.137 libmonochrome_64.so, (function, reason) of every ssl_lib.cc site.
const MONOCHROME_SITES: ErrorSite[] = [
    [0x514fb58, 68], [0x51500d8, 68], [0x5150740, 185], [0x5150cc8, 299], [0x5150cc8, 150],
    [0x5150da8, 134], [0x5150f58, 66], [0x515103c, 182], [0x515103c, 50], [0x51511b0, 66],
    [0x5151258, 226], [0x5151258, 215], [0x5151490, 66], [0x5151490, 215], [0x5151490, 226],
    [0x5151490, 111], [0x51515e4, 226], [0x51515e4, 291], [0x5151748, 194], [0x5151b0c, 66],
    [0x5151b0c, 182], [0x5151d1c, 239], [0x5151fd8, 213], [0x515207c, 315],
].map(([func, reason]) => ({ func, reason }));

test("libmonochrome: SSL_write is the function raising quic/uninitialized/bad-length", () => {
    const groups = reasonsByFunction(MONOCHROME_SITES);
    assert.equal(pickSslWrite(groups), 0x5151490);
    assert.equal(pickSslReadImpl(groups), 0x5151258);
    assert.deepEqual(peekShapedFunctions(groups).sort(), [0x5150f58, 0x51511b0]);
});

test("libmonochrome: SSL_read is the wrapper whose first call is SSL_peek", () => {
    const peekShaped = [
        { func: 0x5150f58, callees: new Set([0x510b118, 0x5150000]) },          // SSL_process_quic_post_handshake
        { func: 0x51511b0, callees: new Set([0x510b118, 0x5151258, 0x883c2a0]) }, // SSL_peek
    ];
    const wrappersOf = (peek: number) => (peek === 0x51511b0 ? [0x515113c] : []);
    assert.equal(resolveSslRead(peekShaped, 0x5151258, wrappersOf), 0x515113c);
});

test("an ambiguous wrapper set resolves to nothing rather than a guess", () => {
    const peekShaped = [{ func: 0x51511b0, callees: new Set([0x5151258]) }];
    assert.equal(resolveSslRead(peekShaped, 0x5151258, () => [0x1000, 0x2000]), null);
    assert.equal(resolveSslRead(peekShaped, 0x5151258, () => []), null);
});

// stable_cronet_libssl.so (Cronet 133.0.6876.3): SSL_peek inlined into SSL_read.
const CRONET_SITES: ErrorSite[] = [
    [0x4c538, 134], [0x4c770, 66], [0x4c99c, 66], [0x4ca78, 66], [0x4cb18, 226], [0x4cb18, 215],
    [0x4cdd0, 66], [0x4cdd0, 226], [0x4cdd0, 111], [0x4cdd0, 215], [0x4cf34, 226], [0x4cf34, 66],
    [0x4cf34, 246], [0x4e0e4, 66], [0x4e0e4, 182], [0x50238, 66],
].map(([func, reason]) => ({ func, reason }));

test("inlined SSL_peek: SSL_read is the peek-shaped reader with the larger call set", () => {
    const groups = reasonsByFunction(CRONET_SITES);
    assert.equal(pickSslWrite(groups), 0x4cdd0);
    const impl = pickSslReadImpl(groups)!;
    assert.equal(impl, 0x4cb18);
    const ERR = 0x67000, MEMCPY = 0x68000, DISCARD = 0x49dd0, ABORT = 0x68100;
    const callees: Record<number, number[]> = {
        0x4c770: [ERR, 0x4c600],
        0x4c99c: [ERR, impl, MEMCPY, DISCARD, ABORT],   // SSL_read
        0x4ca78: [ERR, impl, MEMCPY],                   // SSL_peek
        0x50238: [ERR],
    };
    const peekShaped = peekShapedFunctions(groups).map((func) => ({ func, callees: new Set(callees[func] ?? []) }));
    assert.equal(resolveSslRead(peekShaped, impl, () => []), 0x4c99c);
});

test("eh_frame_hdr search returns the last function starting at or before an address", () => {
    const starts = [0x100, 0x200, 0x340, 0x900];
    const at = (i: number) => starts[i];
    assert.equal(searchSortedStarts(starts.length, at, 0x0ff), -1);
    assert.equal(searchSortedStarts(starts.length, at, 0x100), 0);
    assert.equal(searchSortedStarts(starts.length, at, 0x33f), 1);
    assert.equal(searchSortedStarts(starts.length, at, 0x5000), 3);
});
