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
    blThenMovzPattern, chooseSslReadImpl, copyVerdict, libLoadedBefore, pickCalledSslReadImpl, needsStubCallerScan, pickSslReadWithoutImpl, ErrorSite, decodeArgsAfter, decodeErrorReason, decodeFileLoad, decodeStubCall, fileLoadAt,
    isOutlinedErrorStub, peekShapedFunctions, pickInlinedSslRead, pickSslReadImpl,
    pickSslWrite, reasonsByFunction, resolveSslRead, afterCallsTo, inlinedReadShapedFunctions, pickConsumingReader,
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

// macOS Chrome 157 Google Chrome Framework: SSL_peek inlined into SSL_read AND into a
// network-stack function; neither callee set contains the other.
const CHROME157_IMPL = 0x1046a18;

test("macOS Chrome 157: SSL_read is the one reader whose first call is ssl_read_impl", () => {
    const peekShaped = [
        { func: 0x1046920, callees: new Set([CHROME157_IMPL, 0x10, 0x20, 0x30, 0x40]) },           // SSL_read
        { func: 0x109ccfc, callees: new Set([0x5f3c0, CHROME157_IMPL, 0x10, 0x50, 0x60, 0x70]) },  // net-stack peek copy
    ];
    const consumes = (f: number) => (f === 0x1046920 ? true : null);
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => [], consumes), 0x1046920);
});

// Google Chrome Framework (157, arm64) @0x1046920..0x1046a18: bl ssl_read_impl, bl memcpy,
// then `stp x10, x9, [x8, #0x80]` (the consume) before the return.
const CHROME157_SSL_READ_WORDS = [
    0xa9bd57f6, 0xa9014ff4, 0xa9027bfd, 0x910083fd, 0xf9404c08, 0xb5000608, 0xaa0203f3, 0xaa0103f5,
    0xaa0003f4, 0x94000035, 0x7100041f, 0x540004ab, 0x7100067f, 0x540003cb, 0xf9401a88, 0xf9404509,
    0x2a1303ea, 0xeb33413f, 0x9a8a3133, 0xb4000409, 0xf9404101, 0xaa1503e0, 0xaa1303e2, 0x95bf0dd4,
    0xf9401a88, 0xf9404509, 0xeb130129, 0x540002e3, 0xf940410a, 0x8b13014a, 0xa908250a, 0xf9401a94,
    0xf9404688, 0xb5000148, 0x7940b688, 0x35000108, 0xf9402a80, 0x91017a88, 0xeb08001f, 0x54000040,
    0x95bef8fc, 0xf805629f, 0xf805029f, 0xaa1303e0, 0xa9427bfd, 0xa9414ff4, 0xa8c357f6, 0xd65f03c0,
    0xaa0003f3, 0x17fffffa, 0x95c04ecf, 0x52800013, 0x17fffff7, 0xf00673a3, 0x910e9463, 0x52800200,
    0x52800001, 0x52800842, 0x528074c4, 0x940009ff, 0x12800013, 0x17ffffee,
];
const CHROME157_COPY_INDEX = 23;  // bl memcpy

test("macOS Chrome 157: the leading reader's real body consumes, so it stays SSL_read", () => {
    const peekShaped = [
        { func: 0x1046920, callees: new Set([CHROME157_IMPL, 0x10, 0x20, 0x30, 0x40]) },
        { func: 0x109ccfc, callees: new Set([0x5f3c0, CHROME157_IMPL, 0x10, 0x50, 0x60, 0x70]) },
    ];
    assert.equal(copyVerdict(CHROME157_SSL_READ_WORDS, 0x1046920, CHROME157_IMPL), true);
    const verdict = (f: number) => (f === 0x1046920 ? copyVerdict(CHROME157_SSL_READ_WORDS, f, CHROME157_IMPL) : null);
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => [], verdict), 0x1046920);
});

test("several readers: a leading bare SSL_peek (returns after the copy) is rejected", () => {
    const LDP_FP_LR = 0xa9427bfd;
    const peekBody = [...CHROME157_SSL_READ_WORDS.slice(0, CHROME157_COPY_INDEX + 1), 0xaa1303e0, LDP_FP_LR, RET];
    assert.equal(copyVerdict(peekBody, 0x1046920, CHROME157_IMPL), false);
    const peekShaped = [
        { func: 0x1046920, callees: new Set([CHROME157_IMPL, 0x10]) },                  // bare SSL_peek
        { func: 0x109ccfc, callees: new Set([0x5f3c0, CHROME157_IMPL, 0x50]) },
    ];
    const verdict = (f: number) => (f === 0x1046920 ? copyVerdict(peekBody, f, CHROME157_IMPL) : null);
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => [], verdict), null);
});

test("several readers: a leading candidate with an undeterminable consume is not guessed SSL_read", () => {
    const peekShaped = [
        { func: 0x1046920, callees: new Set([CHROME157_IMPL, 0x10]) },                  // maybe a bare SSL_peek
        { func: 0x109ccfc, callees: new Set([0x5f3c0, CHROME157_IMPL, 0x50]) },
    ];
    assert.equal(copyVerdict([], 0x1046920, CHROME157_IMPL), null);
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => [], () => null), null);
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => []), null);
});

test("first-call fallback: a standalone SSL_peek resolves to its unique wrapper", () => {
    const peekShaped = [
        { func: 0x2000, callees: new Set([CHROME157_IMPL, 0x10]) },             // SSL_peek
        { func: 0x9000, callees: new Set([0x5f3c0, CHROME157_IMPL, 0x50]) },
    ];
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, (peek) => (peek === 0x2000 ? [0x1f00] : [])), 0x1f00);
});

test("first-call fallback: two readers calling ssl_read_impl first stay unresolved", () => {
    const peekShaped = [
        { func: 0x2000, callees: new Set([CHROME157_IMPL, 0x10]) },
        { func: 0x9000, callees: new Set([CHROME157_IMPL, 0x50]) },
    ];
    assert.equal(resolveSslRead(peekShaped, CHROME157_IMPL, () => []), null);
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

// ---- Flutter libflutter.so: 4-argument ERR_put_error copy + outlined stub ----

const movW = (reg: number, imm: number) => (0x52800000 | (imm << 5) | reg) >>> 0;
const RET = 0xd65f03c0;
const BL_FWD = 0x94000010;            // bl .+0x40
const B_FWD = 0x14000010;             // b .+0x40
// Words read from libflutter.so (BoringSSL c7eb007f): the shared stub at
// 0xaa50f8 and SSL_read's / SSL_write's `bl stub; mov w1; mov w3; bl ERR_put_error`.
const FLUTTER_STUB = [0xf0ffb922, 0x912b3042, 0x52800200, 0xd65f03c0];   // adrp x2; add x2,x2,#0xacc; mov w0,#0x10; ret
const FLUTTER_READ_CALL = [0x940c9bff, 0x52800841, 0x52807463, 0x97ff2b5a]; // @0x77e0fc: reason 0x42, line 931
const FLUTTER_WRITE_CALL = [0x940c99ff, 0x52800841, 0x52807723, 0x97ff295a]; // @0x77e8fc: reason 0x42, line 953
const FLUTTER_UNINIT_CALL = [0x940c9a61, 0x52801c41, 0x528068a3, 0x17fffe62]; // @0x77e774: reason 0xe2, then `b`

test("5-argument form (x3 file): reason w2 through the original decoder", () => {
    const window = [NOP, NOP, NOP, NOP, NOP, NOP, ADRP_X3, ADD_X3, MOV_W0_SSL, MOV_W1_WZR,
                    movW2(0xe2), MOV_W4_LINE, NOP];
    assert.deepEqual(fileLoadAt(window, 6), { reg: 3, end: 7 });
    assert.deepEqual(decodeFileLoad(window, 6), { kind: "site", reason: 0xe2 });
});

test("4-argument form (x2 file): reason w1, line w3", () => {
    const ADRP_X2 = 0xf0ffb922, ADD_X2 = 0x912b3042;
    const window = [NOP, NOP, NOP, NOP, NOP, NOP, ADRP_X2, ADD_X2, MOV_W0_SSL, movW(1, 0xd7), movW(3, 870), BL_FWD];
    assert.deepEqual(fileLoadAt(window, 6), { reg: 2, end: 7 });
    assert.deepEqual(decodeArgsAfter(window, 8, 2, false), { reason: 0xd7, line: 870 });
    assert.deepEqual(decodeFileLoad(window, 6), { kind: "site", reason: 0xd7 });
    // mov w0, #ERR_LIB_SSL scheduled before the adrp still counts.
    const early = [NOP, MOV_W0_SSL, NOP, NOP, NOP, NOP, ADRP_X2, ADD_X2, movW(1, 0x42), movW(3, 1), BL_FWD];
    assert.deepEqual(decodeFileLoad(early, 6), { kind: "site", reason: 0x42 });
});

test("no SSL error site when w0 is not ERR_LIB_SSL", () => {
    const ADRP_X2 = 0xf0ffb922, ADD_X2 = 0x912b3042;
    const window = [NOP, NOP, NOP, NOP, NOP, NOP, ADRP_X2, ADD_X2, movW(0, 0x0e), movW(1, 0xd7), movW(3, 870), BL_FWD];
    assert.equal(decodeArgsAfter(window, 8, 2, false), null);
    assert.equal(decodeFileLoad(window, 6), null);
    const stubLike = [0xf0ffb922, 0x912b3042, movW(0, 0x0e), RET];
    assert.equal(isOutlinedErrorStub(stubLike, fileLoadAt(stubLike, 0)!), false);
});

test("args are not taken from past the error call", () => {
    assert.equal(decodeArgsAfter([MOV_W0_SSL, BL_FWD, movW(1, 0x42)], 0, 2, false), null);
    assert.equal(decodeArgsAfter([MOV_W0_SSL, B_FWD, movW(1, 0x42)], 0, 2, false), null);
    assert.equal(decodeArgsAfter([movW(1, 0x42)], 0, 1, true), null); // w0 can not be the reason
});

test("libflutter: the outlined stub is detected and its callers decoded", () => {
    const load = fileLoadAt(FLUTTER_STUB, 0)!;
    assert.deepEqual(load, { reg: 2, end: 1 });
    assert.equal(isOutlinedErrorStub(FLUTTER_STUB, load), true);
    assert.deepEqual(decodeFileLoad(FLUTTER_STUB, 0), { kind: "stub", fileReg: 2 });
    const stubs = new Map([[0xaa50f8, 2]]);
    assert.deepEqual(decodeStubCall(0x77e0fc, FLUTTER_READ_CALL, stubs), { reason: 0x42, line: 931 });
    assert.deepEqual(decodeStubCall(0x77e8fc, FLUTTER_WRITE_CALL, stubs), { reason: 0x42, line: 953 });
    assert.deepEqual(decodeStubCall(0x77e774, FLUTTER_UNINIT_CALL, stubs), { reason: 0xe2, line: 837 });
    // A BL to anything else is not an error site.
    assert.equal(decodeStubCall(0x77e100, FLUTTER_READ_CALL, stubs), null);
    assert.equal(decodeStubCall(0x77e0fc, FLUTTER_READ_CALL, new Map()), null);
});

// libflutter.so: (function, reason) of every stub-call site (reference simulator output).
const FLUTTER_SITES: ErrorSite[] = [
    [0x77dd08, 0x86], [0x77e0d8, 0x42], [0x77e0d8, 0xe2], [0x77e0d8, 0xd7], [0x77e0d8, 0xb6],
    [0x77e0d8, 0x6e], [0x77e0d8, 0xb6], [0x77e0d8, 0x42], [0x77e0d8, 0xb6], [0x77e0d8, 0x44],
    [0x77e8d8, 0x42], [0x77e8d8, 0xe2], [0x77e8d8, 0x6f], [0x77e8d8, 0xd7],
].map(([func, reason]) => ({ func, reason }));

test("libflutter: SSL_read with peek and read_impl inlined is picked by its reason set", () => {
    const groups = reasonsByFunction(FLUTTER_SITES);
    assert.equal(pickSslWrite(groups), 0x77e8d8);
    assert.equal(pickSslReadImpl(groups), null);
    assert.equal(pickInlinedSslRead(groups), 0x77e0d8);
});

test("inlined-read fallback refuses SSL_write and ambiguous sets", () => {
    const writeOnly = reasonsByFunction(FLUTTER_SITES.filter((s) => s.func === 0x77e8d8));
    assert.equal(pickInlinedSslRead(writeOnly), null);
    const twice = reasonsByFunction([...FLUTTER_SITES, ...[0x42, 0xe2, 0xd7].map((reason) => ({ func: 0x9000, reason }))]);
    assert.equal(pickInlinedSslRead(twice), null);
    assert.equal(pickInlinedSslRead(reasonsByFunction(CRONET_SITES)), null);
});

/** `words` (first two) match a masked scan pattern. */
const matchesPattern = (pattern: string, words: number[]) => {
    const bytes = new Uint8Array(new Uint32Array(words.slice(0, 2)).buffer);
    const [needle, mask] = pattern.split(" : ").map((h) => h.split(" ").map((b) => parseInt(b, 16)));
    return needle.every((n, i) => (bytes[i] & mask[i]) === n);
};

test("the stub-caller scan pattern is `bl <any>` then `movz w1, #imm` (Flutter's reason register)", () => {
    assert.equal(blThenMovzPattern(1), "00 00 00 94 01 00 80 52 : 00 00 00 fc 1f 00 e0 ff");
    for (const call of [FLUTTER_READ_CALL, FLUTTER_WRITE_CALL, FLUTTER_UNINIT_CALL]) {
        assert.ok(matchesPattern(blThenMovzPattern(1), call));
    }
    // `bl; mov w3, #line` (or any other register) is no longer a hit.
    assert.equal(matchesPattern(blThenMovzPattern(1), [FLUTTER_READ_CALL[0], movW(3, 931)]), false);
});

test("the stub-caller scan runs only as a fallback when inline sites are incomplete", () => {
    const flutter = reasonsByFunction(FLUTTER_SITES);
    assert.equal(needsStubCallerScan(flutter, 0), false);                    // no stub: nothing to scan for
    assert.equal(needsStubCallerScan(flutter, 1), false);                    // write + inlined read already found
    assert.equal(needsStubCallerScan(reasonsByFunction(MONOCHROME_SITES), 1), false); // write + ssl_read_impl
    assert.equal(needsStubCallerScan(new Map(), 1), true);                   // inline decode found nothing
    const writeOnly = reasonsByFunction(FLUTTER_SITES.filter((s) => s.func === 0x77e8d8));
    assert.equal(needsStubCallerScan(writeOnly, 1), true);                   // read candidate missing
});

test("the inlined-read fallback is used only when outlined stubs were found", () => {
    const groups = reasonsByFunction(FLUTTER_SITES);
    assert.equal(pickSslReadWithoutImpl(groups, 1), 0x77e0d8);
    assert.equal(pickSslReadWithoutImpl(groups, 0), null);
});

test("the ERR_LIB_SSL lookback stops at a call, branch or return", () => {
    const ADRP_X2 = 0xf0ffb922, ADD_X2 = 0x912b3042, BLR_X8 = 0xd63f0100;
    assert.equal(libLoadedBefore([NOP, MOV_W0_SSL, NOP, NOP, NOP, NOP, ADRP_X2], 6), true);
    for (const flow of [BL_FWD, B_FWD, BLR_X8, RET]) {
        const window = [NOP, MOV_W0_SSL, flow, NOP, NOP, NOP, ADRP_X2, ADD_X2, movW(1, 0x42), movW(3, 1), BL_FWD];
        assert.equal(libLoadedBefore(window, 6), false, flow.toString(16));
        assert.equal(decodeFileLoad(window, 6), null, flow.toString(16));
    }
});

// Signal's libsignal_jni.so (Rust `boring`, BoringSSL 2025+, LTO): every ssl_lib.cc site.
// ssl_read_impl has post-handshake/renegotiation inlined; SSL_read has SSL_peek inlined
// and is called only from far-away Rust code, so no wrapper is in range.
const LIBSIGNAL_SITES: ErrorSite[] = [
    [0x88f4b8, 0xba], [0x88f4b8, 0x44], [0x890020, 0xb9], [0x890d30, 0x86], [0x891564, 0x42],
    [0x891654, 0xe2], [0x891654, 0xd7], [0x891654, 0xb6], [0x891654, 0x6e], [0x891654, 0x42], [0x891654, 0x44],
    [0x891f5c, 0x42], [0x891f5c, 0xe2], [0x891f5c, 0x6f], [0x891f5c, 0xd7], [0x8920b4, 0xe2], [0x8920b4, 0x123],
    [0x892370, 0xd5], [0x892408, 0x13b], [0x892528, 0xef], [0x892528, 0x14a],
].map(([func, reason]) => ({ func, reason }));
const LIBSIGNAL_READ_IMPL = 0x891654, LIBSIGNAL_MEMCPY = 0x8b7990, LIBSIGNAL_ERR = 0x8386fc;
// libsignal_jni.so @0x891564: SSL_read (peek inlined) through `stp x10, x9, [x8, #0x80]` (consume).
const LIBSIGNAL_SSL_READ_WORDS = [
    0xa9bd7bfd, 0xf9000bf5, 0xa9024ff4, 0x910003fd, 0xf9404c08, 0xb40001a8, 0x90ffc082, 0x913cdc42,
    0x52800200, 0x52800841, 0x528075e3, 0x97fe9c5b, 0x12800013, 0x2a1303e0, 0xa9424ff4, 0xf9400bf5,
    0xa8c37bfd, 0xd65f03c0, 0x2a0203f3, 0xaa0003f4, 0xaa0103f5, 0x94000027, 0x7100041f, 0x5400044b,
    0x7100067f, 0x54fffe8b, 0xf9401a88, 0x2a1303ea, 0xf9404509, 0xeb33413f, 0x9a8a3133, 0xb40000a9,
    0xf9404101, 0xaa1503e0, 0xaa1303e2, 0x940098e8, 0x34fffd33, 0xf9401a88, 0xf9404509, 0xeb130129,
    0x54000263, 0xf940410a, 0x8b13014a, 0xa908250a,
];
const LIBSIGNAL_COPY_INDEX = 35;  // bl memcpy
const libsignalPeekShaped = () => [
    { func: 0x891564, callees: new Set([LIBSIGNAL_ERR, LIBSIGNAL_READ_IMPL, LIBSIGNAL_MEMCPY, 0x8b79e0, 0x8b7d10]) },
];

test("libsignal: ssl_read_impl with extra inlined reasons is found through its peek-shaped caller", () => {
    const groups = reasonsByFunction(LIBSIGNAL_SITES);
    assert.equal(pickSslWrite(groups), 0x891f5c);
    assert.equal(pickSslReadImpl(groups), null);           // not the exact {UNINITIALIZED, HANDSHAKE_FAILURE}
    assert.deepEqual(peekShapedFunctions(groups), [0x891564]);
    assert.equal(chooseSslReadImpl(groups, libsignalPeekShaped()), LIBSIGNAL_READ_IMPL);
    // Without the call relation nothing is picked (SSL_shutdown also calls it but is not peek-shaped).
    assert.equal(pickCalledSslReadImpl(groups, []), null);
    // No outlined stubs: the inlined-read fallback, which would pick ssl_read_impl, stays off.
    assert.equal(pickInlinedSslRead(groups), LIBSIGNAL_READ_IMPL);
    assert.equal(pickSslReadWithoutImpl(groups, 0), null);
});

test("libsignal: the lone reader with no wrapper in range is SSL_read when it consumes after the copy", () => {
    const consumes = (func: number) => func === 0x891564 &&
        copyVerdict(LIBSIGNAL_SSL_READ_WORDS, func, LIBSIGNAL_READ_IMPL) === true;
    const read = resolveSslRead(libsignalPeekShaped(), LIBSIGNAL_READ_IMPL, () => [], consumes);
    assert.equal(read, 0x891564);
    assert.notEqual(read, 0x891f5c);                       // never SSL_write
    assert.notEqual(read, 0x8920b4);                       // never SSL_shutdown
});

test("a bare SSL_peek (returns after the copy) is not taken as SSL_read", () => {
    const MOV_W0_W19 = 0x2a1303e0, LDP_X20_X19 = 0xa9424ff4, STR_X21_SP = 0xf9000bf5;
    const peekBody = [...LIBSIGNAL_SSL_READ_WORDS.slice(0, LIBSIGNAL_COPY_INDEX + 1), STR_X21_SP, MOV_W0_W19, LDP_X20_X19, RET];
    assert.equal(copyVerdict(peekBody, 0x891564, LIBSIGNAL_READ_IMPL), false);
    // A store before the ssl_read_impl call (or with no copy) does not count either.
    assert.notEqual(copyVerdict(LIBSIGNAL_SSL_READ_WORDS.slice(0, 22), 0x891564, LIBSIGNAL_READ_IMPL), true);
    assert.notEqual(copyVerdict(LIBSIGNAL_SSL_READ_WORDS, 0x891564, 0x1234), true);
    const notConsuming = resolveSslRead(libsignalPeekShaped(), LIBSIGNAL_READ_IMPL, () => [], () => false);
    assert.equal(notConsuming, null);
});

test("a frame-pointer spill after the copy is not a consume", () => {
    const STUR_X8_FP_M18 = 0xf81e83a8, MOV_W0_W19 = 0x2a1303e0, LDP_X20_X19 = 0xa9424ff4;
    const spillBody = [...LIBSIGNAL_SSL_READ_WORDS.slice(0, LIBSIGNAL_COPY_INDEX + 1), STUR_X8_FP_M18, MOV_W0_W19, LDP_X20_X19, RET];
    assert.equal(copyVerdict(spillBody, 0x891564, LIBSIGNAL_READ_IMPL), false);
});

test("existing builds keep their ssl_read_impl pick (exact set first)", () => {
    assert.equal(chooseSslReadImpl(reasonsByFunction(MONOCHROME_SITES), []), 0x5151258);
    assert.equal(chooseSslReadImpl(reasonsByFunction(CRONET_SITES), []), 0x4cb18);
    // Flutter: the superset function has no peek-shaped caller, so no impl; the stub fallback still picks SSL_read.
    const flutter = reasonsByFunction(FLUTTER_SITES);
    assert.equal(chooseSslReadImpl(flutter, peekShapedFunctions(flutter).map((func) => ({ func, callees: new Set<number>() }))), null);
    assert.equal(pickSslReadWithoutImpl(flutter, 1), 0x77e0d8);
    // Chrome's wrapper path wins over the consume fallback.
    const peekShaped = [{ func: 0x51511b0, callees: new Set([0x5151258]) }];
    assert.equal(resolveSslRead(peekShaped, 0x5151258, () => [0x515113c], () => true), 0x515113c);
});

// ---- Electron Framework (arm64): ssl_read_impl inlined into both SSL_read and SSL_peek ----

const ELECTRON_SITES: ErrorSite[] = [
    [0x36bedc, 0xd7], [0x36bedc, 0x42], [0x36bedc, 0x6f], [0x36bedc, 0xe2],
    [0x966c38, 0x42], [0x966c38, 0xd7], [0x966c38, 0xe2], [0xc64430, 0x42], [0xc64430, 0xd7], [0xc64430, 0xe2],
    [0x5457578, 0x42], [0x5457694, 0xe2], [0x5457694, 0xd7],
].map(([func, reason]) => ({ func, reason }));
const ELECTRON_MEMCPY = 0x8007774, ELECTRON_ERRNO = 0x8014450;
const blTo = (pc: number, target: number) => (0x94000000 | (((target - pc) >> 2) & 0x3ffffff)) >>> 0;
const STR_WZR_X0 = 0xb900001f;
// SSL_read @0x96708c: `bl memcpy` then `stp x10, x9, [x8, #0x80]` (consume).
const ELECTRON_READ_COPY = [0xf9404101, 0xaa1403e0, 0xaa1603e2, 0x95da81b7, 0xf9401a68, 0xf9404509, 0xeb160129,
                            0x54001823, 0xf940410a, 0x8b16014a, 0xa908250a];
// SSL_peek @0xc64584: `bl memcpy`, then the epilogue and ret.
const ELECTRON_PEEK_COPY = [0xf9404101, 0xaa1303e0, 0xaa1603e2, 0x95ce8c79, 0xaa1603e0, 0xa9497bfd, 0xa9484ff4,
                            0xa94757f6, 0xa9465ff8, 0xa94567fa, 0x910283ff, RET];
/** `copy` at `at`, preceded by `bl errno; str wzr, [x0]` (a shared callee followed by a store in both). */
const withErrnoPrefix = (at: number, copy: number[]) =>
    ({ func: at - 8, words: [blTo(at - 8, ELECTRON_ERRNO), STR_WZR_X0, ...copy] });

test("Electron: SSL_read is the inlined-read function that consumes after the shared copy", () => {
    const groups = reasonsByFunction(ELECTRON_SITES);
    assert.equal(pickSslWrite(groups), 0x36bedc);
    assert.deepEqual(inlinedReadShapedFunctions(groups), [0x966c38, 0xc64430]);
    assert.equal(pickInlinedSslRead(groups), null);
    const read = withErrnoPrefix(0x96708c, ELECTRON_READ_COPY), peek = withErrnoPrefix(0xc64584, ELECTRON_PEEK_COPY);
    assert.deepEqual(afterCallsTo(read.words, read.func, ELECTRON_MEMCPY), { consumes: true, returns: false });
    assert.deepEqual(afterCallsTo(peek.words, peek.func, ELECTRON_MEMCPY), { consumes: false, returns: true });
    assert.equal(pickConsumingReader([read, peek]), 0x96708c - 8);
    assert.equal(pickConsumingReader([peek, read]), 0x96708c - 8);
});

test("Electron: no pick without a peek that returns after the copy, or with two consumers", () => {
    const read = withErrnoPrefix(0x96708c, ELECTRON_READ_COPY), peek = withErrnoPrefix(0xc64584, ELECTRON_PEEK_COPY);
    assert.equal(pickConsumingReader([read]), null);
    assert.equal(pickConsumingReader([peek, { ...peek, func: peek.func }]), null);
    // Same code at another address: no shared callee once the BL targets differ.
    const elsewhere = { func: read.func + 0x1000, words: read.words };
    assert.equal(pickConsumingReader([elsewhere, peek]), null);
    const twoReads = [read, peek, { func: read.func, words: read.words }];
    assert.equal(pickConsumingReader(twoReads), null);
});

test("Claude.app Electron: out-of-line SSL_read and SSL_peek both lead with ssl_read_impl; SSL_read consumes", () => {
    const impl = 0x90e8e0;
    const peekShaped = [
        { func: 0x90e5b8, callees: new Set([impl, 0x8002170, 0x90e698, 0xa6c6c0]) },   // SSL_read
        { func: 0x1017288, callees: new Set([impl, 0x8707c70, 0xa6c6c0]) },            // SSL_peek
        { func: 0x559fcf8, callees: new Set([0x90e454, 0xa6c6c0]) },
    ];
    assert.equal(resolveSslRead(peekShaped, impl, () => [], (f) => f === 0x90e5b8), 0x90e5b8);
    assert.equal(resolveSslRead(peekShaped, impl, () => [], () => false), null);
    assert.equal(resolveSslRead(peekShaped, impl, () => [], () => true), null);
});
