// Unit tests for the pure decoders in boringssl_anchor_locator.ts (tier 4, the
// last-resort BoringSSL keylog installer for stripped Android binaries).
//
// Run: npm run test:agent
//
// Two pure functions are pinned here — no Frida runtime, no device:
//   decodeCtxKeylogOffsets() — decodes ssl->ctx / ctx->keylog_callback offsets
//     out of ssl_log_secret's prologue (the ldr/ldr/cbz shape). A wrong answer
//     would write a function pointer into the wrong struct field and crash the
//     target (the Apple #65 failure mode), so the decode must be strict.
//   pickAgreedCallee() — the >=2-labels-agree rule that accepts an ssl_log_secret
//     candidate only when multiple keylog labels' xrefs converge on it.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines the Frida globals the module graph touches at load
// (the locator self-registers with boringssl_keylog_outcome on import).
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

import {
    decodeCtxKeylogOffsets,
    decodeSslLogSecretLayout,
    pickAgreedCallee,
    collectLabelVotes,
    BORINGSSL_KEYLOG_LABELS,
} from "./boringssl_anchor_locator.js";

// ---- arm64 instruction-word builders (little pieces, verified below) --------

/** LDR Xt, [Xn, #byteOff] (unsigned offset, 64-bit). byteOff must be a multiple of 8. */
function ldr64(rt: number, rn: number, byteOff: number): number {
    assert.equal(byteOff % 8, 0, "LDR64 offset must be a multiple of 8");
    return (0xf9400000 | ((byteOff / 8) << 10) | (rn << 5) | rt) >>> 0;
}
/** CBZ Xt, <label> (64-bit). */
function cbz64(rt: number): number {
    return (0xb4000000 | rt) >>> 0;
}
/** CBNZ Xt, <label> (64-bit). */
function cbnz64(rt: number): number {
    return (0xb5000000 | rt) >>> 0;
}
const NOP = 0xd503201f;
const PACIASP = 0xd503233f;

test("the example prologue bytes encode exactly the documented loads", () => {
    // From the plan: `08 34 40 F9` = ldr x8,[x0,#0x68]; `08 29 41 F9` = ldr x8,[x8,#0x250].
    assert.equal(ldr64(8, 0, 0x68), 0xf9403408);
    assert.equal(ldr64(8, 8, 0x250), 0xf9412908);
});

test("decodes the ctx offsets from a B4 (cbz) prologue", () => {
    const words = [
        PACIASP,
        ldr64(8, 0, 0x68),   // x8 = ssl->ctx
        ldr64(8, 8, 0x250),  // x8 = ctx->keylog_callback
        cbz64(8),            // if (x8 == NULL) return
    ];
    assert.deepEqual(decodeCtxKeylogOffsets(words), { ctxOff: 0x68, cbOff: 0x250 });
});

test("decodes the ctx offsets from a B5 (cbnz) prologue", () => {
    const words = [
        ldr64(8, 0, 0x68),
        ldr64(8, 8, 0x250),
        cbnz64(8),
    ];
    assert.deepEqual(decodeCtxKeylogOffsets(words), { ctxOff: 0x68, cbOff: 0x250 });
});

test("tolerates instructions interleaved between the two loads and the branch", () => {
    const words = [
        NOP,
        ldr64(3, 0, 0x88),   // x3 = ssl->ctx (different regs / offsets)
        NOP,
        ldr64(9, 3, 0x1a8),  // x9 = ctx->keylog_callback
        NOP,
        cbz64(9),
    ];
    assert.deepEqual(decodeCtxKeylogOffsets(words), { ctxOff: 0x88, cbOff: 0x1a8 });
});

test("rejects a garbage prologue (no load from x0)", () => {
    const words = [NOP, PACIASP, ldr64(8, 3, 0x10), cbz64(8), NOP, NOP];
    assert.equal(decodeCtxKeylogOffsets(words), null);
});

test("rejects when the keylog_callback null-check branch is absent", () => {
    const words = [ldr64(8, 0, 0x68), ldr64(8, 8, 0x250), NOP, NOP];
    assert.equal(decodeCtxKeylogOffsets(words), null);
});

test("rejects when the branch tests a different register than the second load", () => {
    const words = [ldr64(8, 0, 0x68), ldr64(8, 8, 0x250), cbz64(2)];
    assert.equal(decodeCtxKeylogOffsets(words), null);
});

test("rejects the ctx load into x0 (would alias the ssl argument)", () => {
    const words = [ldr64(0, 0, 0x68), ldr64(8, 0, 0x250), cbz64(8)];
    assert.equal(decodeCtxKeylogOffsets(words), null);
});

test("rejects an implausibly large offset", () => {
    const words = [ldr64(8, 0, 0x8000), ldr64(8, 8, 0x250), cbz64(8)];
    assert.equal(decodeCtxKeylogOffsets(words), null);
});

// ---- the agreement rule ----------------------------------------------------

test("accepts a callee that >=2 different labels agree on", () => {
    const agreed = pickAgreedCallee([
        { label: "CLIENT_RANDOM", callee: "0x1000" },
        { label: "EXPORTER_SECRET", callee: "0x1000" },
        { label: "CLIENT_TRAFFIC_SECRET_0", callee: "0x1000" },
    ]);
    assert.equal(agreed, "0x1000");
});

test("picks the most-agreed callee over an outlier", () => {
    const agreed = pickAgreedCallee([
        { label: "CLIENT_RANDOM", callee: "0xA" },
        { label: "EXPORTER_SECRET", callee: "0xA" },
        { label: "SERVER_TRAFFIC_SECRET_0", callee: "0xB" },
    ]);
    assert.equal(agreed, "0xA");
});

test("rejects when every label resolves a different callee (disagreement)", () => {
    const agreed = pickAgreedCallee([
        { label: "CLIENT_RANDOM", callee: "0x1" },
        { label: "EXPORTER_SECRET", callee: "0x2" },
        { label: "CLIENT_TRAFFIC_SECRET_0", callee: "0x3" },
    ]);
    assert.equal(agreed, null);
});

test("fails closed on a tie for the most votes (no insertion-order tie-break)", () => {
    const tie = [
        { label: "CLIENT_RANDOM", callee: "0xA" },
        { label: "EXPORTER_SECRET", callee: "0xA" },
        { label: "CLIENT_TRAFFIC_SECRET_0", callee: "0xB" },
        { label: "SERVER_TRAFFIC_SECRET_0", callee: "0xB" },
    ];
    assert.equal(pickAgreedCallee(tie), null);
    assert.equal(pickAgreedCallee([...tie].reverse()), null);
});

test("a tie below the winner does not block it", () => {
    const agreed = pickAgreedCallee([
        { label: "CLIENT_RANDOM", callee: "0xA" },
        { label: "EXPORTER_SECRET", callee: "0xA" },
        { label: "CLIENT_TRAFFIC_SECRET_0", callee: "0xA" },
        { label: "SERVER_TRAFFIC_SECRET_0", callee: "0xB" },
        { label: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", callee: "0xB" },
        { label: "SERVER_HANDSHAKE_TRAFFIC_SECRET", callee: "0xC" },
        { label: "CLIENT_EARLY_TRAFFIC_SECRET", callee: "0xC" },
    ]);
    assert.equal(agreed, "0xA");
});

test("rejects a single label (no corroboration)", () => {
    assert.equal(pickAgreedCallee([{ label: "CLIENT_RANDOM", callee: "0x1000" }]), null);
});

test("a duplicated label counts once, not twice", () => {
    const agreed = pickAgreedCallee([
        { label: "CLIENT_RANDOM", callee: "0x1000" },
        { label: "CLIENT_RANDOM", callee: "0x1000" },
    ]);
    assert.equal(agreed, null);
});

test("the label set covers the BoringSSL keylog labels", () => {
    for (const l of ["CLIENT_RANDOM", "EXPORTER_SECRET", "CLIENT_TRAFFIC_SECRET_0"]) {
        assert.ok(BORINGSSL_KEYLOG_LABELS.includes(l), `missing label ${l}`);
    }
});

// ---- single-pass multi-label grouping -> votes ----------------------------

test("collectLabelVotes takes each label's first site that reaches a call", () => {
    const P = (s: string) => ({ toString: () => s }) as unknown as NativePointer;
    const callees: Record<string, string | null> = { s1: null, s2: "0xA", s3: "0xB", s4: "0xA" };
    const votes = collectLabelVotes(
        ["CLIENT_RANDOM", "EXPORTER_SECRET", "SERVER_TRAFFIC_SECRET_0"],
        [[P("s1"), P("s2"), P("s3")], [P("s4")], []],
        (site) => { const c = callees[site.toString()]; return c === null ? null : P(c); },
    );
    assert.deepEqual(votes, [
        { label: "CLIENT_RANDOM", callee: "0xA" },   // s1 had no call, s2 wins, s3 unused
        { label: "EXPORTER_SECRET", callee: "0xA" },
    ]);
    assert.equal(pickAgreedCallee(votes), "0xA");
});

// ---- ssl->s3 / s3->client_random layout (decodeSslLogSecretLayout) ---------

/** MOV Xd, Xm (ORR Xd, XZR, Xm). */
function mov64(rd: number, rm: number): number {
    return (0xaa0003e0 | (rm << 16) | rd) >>> 0;
}
/** ADD Xd, Xn, #imm12 (64-bit, no shift). */
function add64(rd: number, rn: number, imm: number): number {
    return (0x91000000 | (imm << 10) | (rn << 5) | rd) >>> 0;
}
/** MOV Wd, #imm16 (32-bit MOVZ). */
function movW(rd: number, imm: number): number {
    return (0x52800000 | (imm << 5) | rd) >>> 0;
}
/** CBNZ Wt, +wordsAhead (32-bit). */
function cbnzW(rt: number, wordsAhead: number): number {
    return (0x35000000 | (wordsAhead << 5) | rt) >>> 0;
}
const BL = 0x94000010;
const RET = 0xd65f03c0;
const MOV_W19_WZR = 0x2a1f03f3;
const CTX_OFF = 0x68;
/** The ssl_log_secret head every synthetic body starts with: ctx/keylog_callback check. */
const HEAD = [PACIASP, ldr64(8, 0, CTX_OFF), ldr64(8, 8, 0x250), cbz64(8)];

test("layout builders encode the documented words", () => {
    assert.equal(mov64(19, 0), 0xaa0003f3);       // mov x19, x0
    assert.equal(add64(1, 8, 0x30), 0x9100c101);  // add x1, x8, #0x30
    assert.equal(movW(2, 0x20), 0x52800402);      // mov w2, #0x20
});

test("decodes s3/client_random loaded straight from x0", () => {
    const words = [...HEAD, ldr64(9, 0, 0x30), add64(1, 9, 0x30), movW(2, 0x20), BL, RET];
    assert.deepEqual(decodeSslLogSecretLayout(words, CTX_OFF), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: true });
});

test("follows ssl through `mov x19, x0` across calls that clobber x0", () => {
    const words = [...HEAD, mov64(19, 0), BL, BL, ldr64(8, 19, 0x38), NOP, add64(1, 8, 0x40), BL, RET];
    assert.deepEqual(decodeSslLogSecretLayout(words, CTX_OFF), { s3Off: 0x38, crOff: 0x40, lengthArgSeen: false });
});

test("rejects a load from an alias that was overwritten first", () => {
    const words = [...HEAD, mov64(19, 0), mov64(19, 1), BL, ldr64(8, 19, 0x30), add64(1, 8, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("rejects a load from x0 after a call clobbered it", () => {
    const words = [...HEAD, BL, ldr64(8, 0, 0x30), add64(1, 8, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("rejects two different (s3Off, crOff) pairs", () => {
    const words = [...HEAD, mov64(19, 0),
        ldr64(8, 19, 0x30), add64(1, 8, 0x30), BL,
        ldr64(9, 19, 0x38), add64(1, 9, 0x40), BL, RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("accepts the same pair seen twice", () => {
    const words = [...HEAD, mov64(19, 0),
        ldr64(8, 19, 0x30), add64(1, 8, 0x30), BL,
        ldr64(9, 19, 0x30), add64(1, 9, 0x30), BL, RET];
    assert.deepEqual(decodeSslLogSecretLayout(words, CTX_OFF), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: false });
});

test("never takes the ssl->ctx load as the s3 load", () => {
    const words = [mov64(19, 0), ldr64(8, 19, CTX_OFF), add64(1, 8, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
    assert.deepEqual(decodeSslLogSecretLayout(words, 0x70), { s3Off: CTX_OFF, crOff: 0x30, lengthArgSeen: false });
});

test("ignores an add whose base is not the s3 register", () => {
    const words = [...HEAD, mov64(19, 0), ldr64(8, 19, 0x30), add64(1, 9, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("rejects when the s3 register is overwritten before the add", () => {
    const words = [...HEAD, mov64(19, 0), ldr64(8, 19, 0x30), mov64(8, 2), add64(1, 8, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("rejects out-of-range offsets", () => {
    const farS3 = [...HEAD, mov64(19, 0), ldr64(8, 19, 0x408), add64(1, 8, 0x30), RET];
    const farCr = [...HEAD, mov64(19, 0), ldr64(8, 19, 0x30), add64(1, 8, 0x208), RET];
    const nearCr = [...HEAD, mov64(19, 0), ldr64(8, 19, 0x30), add64(1, 8, 0x8), RET];
    for (const words of [farS3, farCr, nearCr]) assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("an error path that clobbers the alias does not hide a branch-reached s3 load", () => {
    // cbnz jumps over `mov w19, wzr; ret` straight to the s3 load (libmonochrome's shape).
    const words = [mov64(19, 0), BL, cbnzW(0, 3), MOV_W19_WZR, RET, ldr64(8, 19, 0x30), add64(1, 8, 0x30), RET];
    assert.deepEqual(decodeSslLogSecretLayout(words, CTX_OFF), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: false });
});

test("a path on which the alias was clobbered makes the merged load unusable", () => {
    // Same as above but the clobbering block falls through into the load (must-alias).
    const words = [mov64(19, 0), BL, cbnzW(0, 3), MOV_W19_WZR, NOP, ldr64(8, 19, 0x30), add64(1, 8, 0x30), RET];
    assert.equal(decodeSslLogSecretLayout(words, CTX_OFF), null);
});

test("returns null for an empty or load-free body", () => {
    assert.equal(decodeSslLogSecretLayout([], CTX_OFF), null);
    assert.equal(decodeSslLogSecretLayout([...HEAD, mov64(19, 0), BL, RET], CTX_OFF), null);
});

// ---- real ssl_log_secret bodies (Chromium 148, arm64) ----------------------

// ssl_log_secret from research/monochrome/lib/arm64-v8a/libmonochrome_64.so
// (Chrome 148.0.7778.167, @0x47aa274, 89 words up to the next function). Found
// offline by the same label-xref vote tier 4 runs on device. The s3 load sits
// AFTER an error path that zeroes w19 (the ssl alias), reached only by a branch.
const MONOCHROME_SSL_LOG_SECRET: number[] = [
    0xd503233f, 0xd10203ff, 0xa9047bfd, 0xf9002bf7, 0xa90657f6, 0xa9074ff4, 0x910103fd, 0xf9403408,
    0xf9412908, 0xb40005c8, 0xaa0003f3, 0x910043e0, 0xaa0303f4, 0xaa0203f5, 0xaa0103f6, 0x948c61ab,
    0xa9007fff, 0xb40008f6, 0xaa1603e0, 0x95b2b854, 0xaa0003f7, 0xaa1603e0, 0x95b2b851, 0x8b140408,
    0x910043e0, 0x91010d01, 0x9495cc86, 0x34000140, 0x910043e0, 0xaa1603e1, 0xaa1703e2, 0x9495cec7,
    0x340000a0, 0x910043e0, 0x52800401, 0x97fe9f5c, 0x350002a0, 0xaa1f03e1, 0x2a1f03f3, 0xf94007e8,
    0xcb0103e9, 0xeb09011f, 0x540005c8, 0xaa0103e0, 0x94adea9a, 0x910043e0, 0x94af0e88, 0x2a1303e0,
    0xa9474ff4, 0xa94657f6, 0xf9402bf7, 0xa9447bfd, 0x910203ff, 0xd50323bf, 0xd65f03c0, 0x52800033,
    0x17fffff7, 0xf9401a68, 0x910043e0, 0x52800402, 0x9100c101, 0x9400001c, 0x3607fce0, 0x910043e0,
    0x52800401, 0x97fe9f3e, 0x34fffc60, 0x910043e0, 0xaa1503e1, 0xaa1403e2, 0x94000013, 0x3607fbc0,
    0x910043e0, 0x2a1f03e1, 0x97fe9f35, 0x34fffb40, 0x910043e0, 0x910003e1, 0x97fea0dd, 0xf94003e1,
    0x3607fac0, 0xf9403668, 0xaa1303e0, 0xf9412908, 0xd63f0100, 0xf94003e1, 0x52800033, 0x17ffffd0,
    0xd4200020,
];

// ssl_log_secret from research/weather/lib/arm64-v8a/libcronet.148.0.7778.120.so
// (@0x4e9e34, 167 words). cbb_add_hex is inlined here: `ldr x23,[x19,#0x30]`
// then `add x9, x23, #0x30` seven words later, with a call in between and no
// `mov w2, #0x20`.
const CRONET_SSL_LOG_SECRET: number[] = [
    0xd503233f, 0xd10243ff, 0xa9057bfd, 0xa9065ff8, 0xa90757f6, 0xa9084ff4, 0x910143fd, 0xf9403408,
    0xf9412908, 0xb4001128, 0xaa0003f3, 0x910063e0, 0xaa0303f4, 0xaa0203f5, 0xaa0103f7, 0x97f65aa7,
    0xa900ffff, 0xb4001157, 0xaa1703e0, 0x9405d6ce, 0xaa0003f8, 0xaa1703e0, 0x9405d6cb, 0xd37ffa96,
    0x8b0002c8, 0x910063e0, 0x91010d01, 0x97ff18aa, 0x34000d20, 0x910063e0, 0xaa1703e1, 0xaa1803e2,
    0x97ff1b00, 0x34000c80, 0x910063e0, 0x52800401, 0x97ff1aec, 0x34000c00, 0xf9401a77, 0x910063e0,
    0xd10023a1, 0x52800802, 0x97ff1b0b, 0x34000b40, 0xaa1f03e8, 0x9100c2e9, 0x52801fea, 0x3868692b,
    0xf85f83ad, 0x91000508, 0x53047d6c, 0x7102817f, 0x9a9f314e, 0x321c058f, 0x11015d8c, 0x0a0e01ef,
    0x0a2e018c, 0x910005ae, 0xf81f83ae, 0x2a0c01ec, 0x12000d6e, 0x390001ac, 0x5280060c, 0x710029df,
    0x33000d6c, 0x9a9f314b, 0xf85f83ad, 0x11015dce, 0xf100811f, 0x0a0b018c, 0x0a2b01cb, 0x910005ae,
    0x2a0b018b, 0xf81f83ae, 0x390001ab, 0x54fffc81, 0x910063e0, 0x52800401, 0x97ff1ac2, 0x340006c0,
    0x910063e0, 0xd10023a1, 0xaa1603e2, 0x97ff1ae2, 0x34000620, 0xb40003d4, 0x52801fe8, 0x384016a9,
    0xf85f83ab, 0x53047d2a, 0x7102813f, 0x9a9f310c, 0x321c054d, 0x11015d4a, 0x0a0c01ad, 0x0a2c014a,
    0x9100056c, 0xf81f83ac, 0x2a0a01aa, 0x12000d2c, 0x3900016a, 0x5280060a, 0x7100299f, 0x33000d2a,
    0x9a9f3109, 0xf85f83ab, 0x11015d8c, 0xf1000694, 0x0a09014a, 0x0a290189, 0x9100056c, 0x2a090149,
    0xf81f83ac, 0x39000169, 0x54fffca1, 0x910063e0, 0x2a1f03e1, 0x97ff1a9b, 0x340001e0, 0x910063e0,
    0x910023e1, 0x97ff1d3f, 0xf94007e1, 0x36000160, 0xf9403668, 0xaa1303e0, 0xf9412908, 0xd63f0100,
    0xf94007e1, 0x52800033, 0xf9400be8, 0xb50000c8, 0x14000009, 0xaa1f03e1, 0x2a1f03f3, 0xf9400be8,
    0xb40000a8, 0xcb0103e9, 0xd1000508, 0xeb09011f, 0x540001e2, 0xaa0103e0, 0x97ff9b65, 0x910063e0,
    0x97ff185d, 0x14000002, 0x52800033, 0x2a1303e0, 0xa9484ff4, 0xa94757f6, 0xa9465ff8, 0xa9457bfd,
    0x910243ff, 0xd50323bf, 0xd65f03c0, 0xd4200020, 0xd503245f, 0xf9403010, 0xb5000090, 0xf9403408,
    0xf9407910, 0xb4000050, 0xd61f0200, 0xd65f03c0, 0xd503245f, 0xf9402010, 0xb4000230,
];

// ssl_log_secret from libhttpengine.so (Pixel 5 device dump, @0x50d6cc, 94
// words up to the next paciasp). `movi v0.2d, #0` (word 0x13) sits one word
// before `mov x19, x0`; it writes a SIMD register, so the ssl alias survives
// to `ldr x8,[x19,#0x30]` / `add x1,x8,#0x30`. `str q0`/`stp q0,q0` follow.
const HTTPENGINE_SSL_LOG_SECRET: number[] = [
    0xd503233f, 0xd10203ff, 0xa9047bfd, 0xf9002bf7, 0xa90657f6, 0xa9074ff4, 0x910103fd, 0xf9403408,
    0xf9412908, 0xb5000148, 0x52800033, 0x2a1303e0, 0xa9474ff4, 0xa94657f6, 0xf9402bf7, 0xa9447bfd,
    0x910203ff, 0xd50323bf, 0xd65f03c0, 0x6f00e400, 0xaa0003f3, 0x910043e0, 0xaa0303f4, 0xaa0203f5,
    0xaa0103f6, 0xad0103e0, 0x3d8007e0, 0x9402dd2e, 0xa9007fff, 0xb5000056, 0xd4200020, 0xaa1603e0,
    0x9402d9b9, 0xaa0003f7, 0xaa1603e0, 0x9402d9b6, 0x8b140408, 0x910043e0, 0x91010d01, 0x9402dd2a,
    0x350001c0, 0xaa1f03e1, 0x2a1f03f3, 0xf94007e8, 0xb40000a8, 0xcb0103e9, 0xd1000508, 0xeb09011f,
    0x54fffdc2, 0xaa0103e0, 0x9402ddeb, 0x910043e0, 0x9402dd19, 0x17ffffd6, 0x910043e0, 0xaa1603e1,
    0xaa1703e2, 0x9402de70, 0x34fffde0, 0x910043e0, 0x52800401, 0x9402de84, 0x34fffd60, 0xf9401a68,
    0x910043e0, 0x52800402, 0x9100c101, 0x9400001b, 0x3607fca0, 0x910043e0, 0x52800401, 0x9402de7a,
    0x34fffc20, 0x910043e0, 0xaa1503e1, 0xaa1403e2, 0x94000012, 0x3607fb80, 0x910043e0, 0x2a1f03e1,
    0x9402de71, 0x34fffb00, 0x910043e0, 0x910003e1, 0x9402e009, 0xf94003e1, 0x3607fa80, 0xf9403668,
    0xaa1303e0, 0xf9412908, 0xd63f0100, 0xf94003e1, 0x52800033, 0x17ffffce,
];

function decodeRealLayout(words: number[]) {
    const ctx = decodeCtxKeylogOffsets(words.slice(0, 12));
    assert.deepEqual(ctx, { ctxOff: 0x68, cbOff: 0x250 });
    return decodeSslLogSecretLayout(words, ctx!.ctxOff);
}

test("real libmonochrome_64.so ssl_log_secret decodes s3=0x30, client_random=0x30", () => {
    assert.deepEqual(decodeRealLayout(MONOCHROME_SSL_LOG_SECRET), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: true });
});

test("real libcronet ssl_log_secret (inlined hex writer) decodes s3=0x30, client_random=0x30", () => {
    assert.deepEqual(decodeRealLayout(CRONET_SSL_LOG_SECRET), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: false });
});

test("real libhttpengine ssl_log_secret (movi before the ssl alias) decodes s3=0x30, client_random=0x30", () => {
    assert.deepEqual(decodeRealLayout(HTTPENGINE_SSL_LOG_SECRET), { s3Off: 0x30, crOff: 0x30, lengthArgSeen: true });
});

// ---- readInstructionWords: one readability walk + one readByteArray --------

import { readInstructionWords, readableByteCount } from "./boringssl_anchor_locator.js";

/** BigInt-backed pointer over a fake little-endian memory image. */
function memPtr(addr: bigint, memory: Map<bigint, number>, reads: { count: number }): any {
    const p: any = {
        value: addr,
        add: (n: any) => memPtr(addr + BigInt(typeof n === "number" ? n : n.value), memory, reads),
        sub: (n: any) => memPtr(addr - BigInt(typeof n === "number" ? n : n.value), memory, reads),
        compare: (o: any) => (addr < o.value ? -1 : addr > o.value ? 1 : 0),
        toUInt32: () => Number(addr & 0xffffffffn),
        toString: () => "0x" + addr.toString(16),
        readU32: () => { throw new Error("per-word readU32 must not be used"); },
        readByteArray: (len: number) => {
            reads.count++;
            const out = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                const b = memory.get(addr + BigInt(i));
                if (b === undefined) throw new Error("access violation");
                out[i] = b;
            }
            return out.buffer;
        },
    };
    return p;
}

/** Install BigInt-aware ptr() and findRangeByAddress() for `ranges`, run fn, restore. */
function withRanges(ranges: { base: bigint; size: bigint; protection: string }[], fn: (mem: Map<bigint, number>, reads: { count: number }) => void): void {
    const savedPtr = G.ptr;
    const savedFind = G.Process.findRangeByAddress;
    const memory = new Map<bigint, number>();
    const reads = { count: 0 };
    for (const r of ranges) for (let i = 0n; i < r.size; i++) memory.set(r.base + i, Number((r.base + i) & 0xffn));
    G.ptr = (v: any) => memPtr(BigInt(v), memory, reads);
    G.Process.findRangeByAddress = (a: any) => {
        const r = ranges.find((x) => a.value >= x.base && a.value < x.base + x.size);
        return r === undefined ? null : { base: memPtr(r.base, memory, reads), size: Number(r.size), protection: r.protection };
    };
    try { fn(memory, reads); } finally { G.ptr = savedPtr; G.Process.findRangeByAddress = savedFind; }
}

test("readInstructionWords reads all words with ONE readByteArray, little-endian like readU32", () => {
    withRanges([{ base: 0x1000n, size: 0x100n, protection: "r-x" }], (mem, reads) => {
        const at = G.ptr(0x1010);
        const words = readInstructionWords(at, 4);
        assert.equal(reads.count, 1);
        assert.deepEqual(words, [0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c]);
        assert.equal(mem.size, 0x100);
    });
});

test("readInstructionWords stops at the first unmapped word", () => {
    withRanges([{ base: 0x1000n, size: 0x10n, protection: "r-x" }], (_mem, reads) => {
        assert.deepEqual(readInstructionWords(G.ptr(0x1008), 8).length, 2);
        assert.deepEqual(readInstructionWords(G.ptr(0x2000), 8), []);
        assert.equal(reads.count, 1, "nothing read when the start is unmapped");
    });
});

test("readInstructionWords follows adjacent readable mappings but not a non-readable one", () => {
    withRanges([
        { base: 0x1000n, size: 0x8n, protection: "r-x" },
        { base: 0x1008n, size: 0x8n, protection: "r--" },
        { base: 0x1010n, size: 0x8n, protection: "---" },
    ], () => {
        assert.equal(readableByteCount(G.ptr(0x1004), 64), 0xc);
        assert.equal(readInstructionWords(G.ptr(0x1004), 16).length, 3);
    });
});
