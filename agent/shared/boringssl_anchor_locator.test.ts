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
