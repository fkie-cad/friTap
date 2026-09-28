// Unit tests for the pure AArch64 helpers in arm64.ts.
//
// Run: npm run test:agent   (node --import tsx --test agent/shared/arm64.test.ts)
//
// These need no Frida runtime — arm64.ts is pure number math. The suite exists
// because the signedness footgun these helpers contain previously hid in
// on-device-only code for an entire debugging session: a masked compare against
// a bit-31-set opcode was always false, so ARM64 discovery/prologue checks
// silently never matched.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
    isADRP, isADDimm64, isLDRimmU64, isSTRimmU64, isRET, isBL, isBLR, isFunctionPrologueWord,
    decodeADRPImm, decodeADDImm12, decodeLDRU64Imm, decodeSTRU64Imm, decodeBLImm, regRd, regRn,
    IMM12_OPERAND_MASK, addImm64WordForImm12, ldrU64WordForImm12, maskedWordScanPattern,
    addImm64ScanPattern, ldrU64ScanPattern,
    isADR, decodeADRImm, adrTopByteForTarget, regRt2, regRs,
    isUnconditionalB, isAnyReturn, isIndirectBranch, isBLRAuth, isTrap, endsFallThrough, writesReg,
} from "./arm64.js";

// Real instruction words read out of Apple's /usr/lib/libboringssl.dylib on
// macOS 26.3.1 (arm64). These are the two-instruction setter bodies whose
// immediates ARE the SSL_CTX field offsets friTap needs, so decoding them wrong
// means writing a function pointer into the wrong struct field and killing the
// target (fkie-cad/friTap#65).
const APPLE_SET_INFO_CALLBACK_BODY = 0xf900c401;   // str x1, [x0, #0x188]
const APPLE_RET = 0xd65f03c0;                      // ret

test("decodes Apple's real SSL_CTX setter body (the #65 offsets)", () => {
    // The signedness footgun bites hardest here: a naive masked compare against
    // 0xf9000000 is always false, so the decoder would silently refuse every
    // real setter and fall back to a guessed offset table.
    assert.equal((APPLE_SET_INFO_CALLBACK_BODY & 0xffc00000) === 0xf9000000, false);
    assert.equal(isSTRimmU64(APPLE_SET_INFO_CALLBACK_BODY), true);
    assert.equal(regRd(APPLE_SET_INFO_CALLBACK_BODY), 1);   // Rt = x1 (the callback arg)
    assert.equal(regRn(APPLE_SET_INFO_CALLBACK_BODY), 0);   // Rn = x0 (the SSL_CTX arg)
    assert.equal(decodeSTRU64Imm(APPLE_SET_INFO_CALLBACK_BODY), 0x188);
    assert.equal(isRET(APPLE_RET), true);
});

test("STR/RET predicates reject near-misses", () => {
    assert.equal(isSTRimmU64(0xf9400400), false);  // ldr (load, not store)
    assert.equal(isSTRimmU64(0xb9000000), false);  // 32-bit str w0
    assert.equal(isRET(0xd65f0000), false);        // ret to a register other than x30
    assert.equal(isRET(0xd503201f), false);        // nop
});

test("STR and LDR share the scaled imm12 encoding", () => {
    // decodeSTRU64Imm delegates to the LDR decoder; pin that they agree so a
    // future divergence cannot silently change one of them.
    for (const imm12 of [0, 1, 0x31, 0x61, 0x62, 0xfff]) {
        const str = (0xf9000000 | (imm12 << 10)) >>> 0;
        const ldr = (0xf9400000 | (imm12 << 10)) >>> 0;
        assert.equal(decodeSTRU64Imm(str), imm12 * 8);
        assert.equal(decodeSTRU64Imm(str), decodeLDRU64Imm(ldr));
    }
    // The two offsets that actually matter on Apple platforms.
    assert.equal(decodeSTRU64Imm((0xf9000000 | (0x61 << 10)) >>> 0), 0x308);
    assert.equal(decodeSTRU64Imm((0xf9000000 | (0x62 << 10)) >>> 0), 0x310);
});

test("the signedness footgun this module guards against", () => {
    // The naive compare is ALWAYS false for a bit-31-set opcode (JS `&` is signed
    // int32). This is exactly the bug the helpers fix with `>>> 0`.
    assert.equal((0x90000000 & 0x9f000000) === 0x90000000, false);
    // The helper does the unsigned coercion and gets it right.
    assert.equal(isADRP(0x90000000), true);
});

test("opcode predicates accept real (bit-31-set) words", () => {
    assert.equal(isADRP(0x90000000), true);   // adrp x0, .
    assert.equal(isADRP(0xb0000001), true);   // adrp x1, . (immlo set)
    assert.equal(isADRP(0xd503233f), false);  // paciasp, not adrp

    assert.equal(isADDimm64(0x91000400), true);  // add x0, x0, #1
    assert.equal(isADDimm64(0x8b000000), false); // add (shifted reg), not imm

    assert.equal(isLDRimmU64(0xf9400400), true);  // ldr x0, [x0, #8]
    assert.equal(isLDRimmU64(0xb9400000), false); // 32-bit ldr w0

    assert.equal(isBL(0x94000000), true);   // bl +0
    assert.equal(isBL(0x97ffffff), true);   // bl -4 (negative imm26)
    assert.equal(isBL(0x14000000), false);  // b (not bl)

    assert.equal(isBLR(0xd63f0000), true);  // blr x0
    assert.equal(isBLR(0xd61f0000), false); // br x0 (not blr)
});

test("isFunctionPrologueWord recognizes the union of prologue forms", () => {
    assert.equal(isFunctionPrologueWord(0xd503233f), true); // paciasp
    assert.equal(isFunctionPrologueWord(0xd503237f), true); // pacibsp
    assert.equal(isFunctionPrologueWord(0xd50324df), true); // bti c
    assert.equal(isFunctionPrologueWord(0xa9bf7bfd), true); // stp x29,x30,[sp,#-16]! (broad pre-index)
    assert.equal(isFunctionPrologueWord(0xa9017bfd), true); // stp x29,x30,[sp,#16]   (offset form)
    assert.equal(isFunctionPrologueWord(0xd10043ff), true); // sub sp, sp, #16
    // The mined libsignal_jni TLS keylog prologue (sub sp, sp, #0xa0) — a form
    // the old inline check wrongly rejected.
    assert.equal(isFunctionPrologueWord(0xd10283ff), true);
    // Not a prologue word.
    assert.equal(isFunctionPrologueWord(0x8b010020), false); // add x0, x1, x1
    assert.equal(isFunctionPrologueWord(0x00000000), false);
});

test("immediate decoders", () => {
    // ADD #imm12 (no shift) and with LSL #12.
    assert.equal(decodeADDImm12(0x91000400), 1);          // #1
    assert.equal(decodeADDImm12(0x91400400), 1 << 12);    // #1, LSL #12

    // LDR unsigned offset is scaled by 8 for the 64-bit form.
    assert.equal(decodeLDRU64Imm(0xf9400400), 8);         // [x0, #8]

    // ADRP page immediate is sign-extended and << 12.
    assert.equal(decodeADRPImm(0x90000000), 0);
    assert.equal(decodeADRPImm(0x90000020), 0x4000);       // immhi=1 -> 4 pages
    assert.equal(decodeADRPImm(0x90800000), -0x100000000);  // sign bit set -> negative

    // BL byte offset is signed, << 2.
    assert.equal(decodeBLImm(0x94000000), 0);
    assert.equal(decodeBLImm(0x94000001), 4);
    assert.equal(decodeBLImm(0x97ffffff), -4);
});

test("register-field extractors", () => {
    // word with Rd=5, Rn=3 in the low bits.
    assert.equal(regRd(0x00000065), 5);
    assert.equal(regRn(0x00000065), 3);
});

// ---- scan-pattern builders (native xref search) ---------------------------

/** Apply a Frida "pattern : mask" to a little-endian word, as Memory.scan would. */
function patternMatchesWord(pattern: string, word: number): boolean {
    const [n, m] = pattern.split(":").map((h) => h.trim().split(/\s+/).map((b) => parseInt(b, 16)));
    for (let i = 0; i < 4; i++) {
        const byte = (word >>> (8 * i)) & 0xff;
        if ((byte & m[i]) !== (n[i] & m[i])) return false;
    }
    return true;
}
const addImm = (rd: number, rn: number, imm: number, shift = 0) =>
    (0x91000000 | (shift << 22) | (imm << 10) | (rn << 5) | rd) >>> 0;

test("ADD-imm search word: fixed imm12, zero registers, decodes back", () => {
    assert.equal(addImm64WordForImm12(0x40), 0x91010000);
    assert.equal(isADDimm64(addImm64WordForImm12(0x40)), true);
    assert.equal(decodeADDImm12(addImm64WordForImm12(0xabc)), 0xabc);
    assert.equal(addImm64WordForImm12(0x1abc), addImm64WordForImm12(0xabc)); // imm12 is masked to 12 bits
    assert.equal(IMM12_OPERAND_MASK >>> 0, 0xfffffc00);
});

test("ADD-imm scan pattern is little-endian with a register-ignoring mask", () => {
    assert.equal(addImm64ScanPattern(0x40), "00 00 01 91 : 00 fc ff ff");
    assert.equal(maskedWordScanPattern(0x91010123, 0xfffffc00), "00 00 01 91 : 00 fc ff ff");
});

test("ADD-imm scan pattern matches every register choice but only its imm12 and no shift", () => {
    const pat = addImm64ScanPattern(0x5d8);
    for (const [rd, rn] of [[0, 0], [1, 1], [8, 8], [31, 17], [30, 2]]) {
        assert.equal(patternMatchesWord(pat, addImm(rd, rn, 0x5d8)), true, `x${rd},x${rn}`);
    }
    assert.equal(patternMatchesWord(pat, addImm(1, 1, 0x5d0)), false);        // other imm12
    assert.equal(patternMatchesWord(pat, addImm(1, 1, 0x5d8, 1)), false);     // LSL #12
    assert.equal(patternMatchesWord(pat, (addImm(1, 1, 0x5d8) & 0x7fffffff) >>> 0), false); // 32-bit ADD
});

test("LDR-u64 scan pattern matches any Rt/Rn with its scaled imm12", () => {
    assert.equal(ldrU64WordForImm12(0x10), 0xf9404000);
    assert.equal(decodeLDRU64Imm(ldrU64WordForImm12(0x10)), 0x80);
    const pat = ldrU64ScanPattern(0x10);
    assert.equal(pat, "00 40 40 f9 : 00 fc ff ff");
    assert.equal(patternMatchesWord(pat, (0xf9400000 | (0x10 << 10) | (2 << 5) | 2) >>> 0), true);
    assert.equal(patternMatchesWord(pat, (0xf9400000 | (0x11 << 10) | (2 << 5) | 2) >>> 0), false);
});

// ---- ADR (lld's relaxed ADRP+ADD) ------------------------------------------
// Words below are the output of `clang -arch arm64 -march=armv8.5-a+pauth`
// (objdump), so they are ground truth, not re-derived from our own encoder.

test("isADR accepts ADR and rejects ADRP / ADD / nop", () => {
    assert.equal(isADR(0x10000005), true);   // adr x5, .
    assert.equal(isADR(0x10000745), true);   // adr x5, .+0xe8
    assert.equal(isADR(0x30ffffc2), true);   // adr x2, .-7  (immlo = 1, bit 29 set)
    assert.equal(isADR(0x90000001), false);  // adrp x1, .
    assert.equal(isADR(0x910100a1), false);  // add x1, x5, #0x40
    assert.equal(isADR(0xd503201f), false);  // nop
});

test("decodeADRImm is the signed, UNshifted byte offset", () => {
    assert.equal(decodeADRImm(0x10000005), 0);
    assert.equal(decodeADRImm(0x10000745), 0xe8);  // at pc 4 -> 0xec
    assert.equal(decodeADRImm(0x30ffffc2), -7);    // at pc 8 -> 0x1
    // Reach limits: imm = +0xFFFFF and -0x100000 (±1 MB).
    const adr = (imm: number) => (0x10000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5)) >>> 0;
    assert.equal(decodeADRImm(adr(0xfffff)), 0xfffff);
    assert.equal(decodeADRImm(adr(-0x100000)), -0x100000);
});

test("adrTopByteForTarget is the ADR word's top byte, fixed by the target's low 2 bits", () => {
    assert.equal(adrTopByteForTarget(0), 0x10);                      // 0x10000745 >>> 24
    assert.equal(adrTopByteForTarget(1), 0x30);                      // 0x30ffffc2 >>> 24
    assert.equal(adrTopByteForTarget(2), 0x50);
    assert.equal(adrTopByteForTarget(3), 0x70);
    for (let low2 = 0; low2 < 4; low2++) {
        assert.equal(isADR(adrTopByteForTarget(low2) << 24), true);
    }
});

// ---- control-flow terminators (forward-walk stop set) -----------------------

test("fall-through terminators: B, every RET form, BR forms, BRK/UDF", () => {
    assert.equal(isUnconditionalB(0x14000038), true);  // b l1
    assert.equal(isUnconditionalB(0x9400002c), false); // bl l1
    assert.equal(isUnconditionalB(0x540001e0), false); // b.eq l1
    for (const w of [0xd65f03c0, 0xd65f0020, 0xd65f0bff, 0xd65f0fff]) {
        assert.equal(isAnyReturn(w), true, w.toString(16)); // ret, ret x1, retaa, retab
    }
    for (const w of [0xd61f0200, 0xd61f0a1f, 0xd71f0a11]) {
        assert.equal(isIndirectBranch(w), true, w.toString(16)); // br x16, braaz x16, braa x16,x17
    }
    assert.equal(isTrap(0xd4200020), true);   // brk #1
    assert.equal(isTrap(0x00000000), true);   // udf #0 / zero padding
    for (const w of [0x14000038, 0xd65f03c0, 0xd65f0bff, 0xd61f0200, 0xd4200020, 0]) {
        assert.equal(endsFallThrough(w), true, w.toString(16));
    }
});

test("calls, conditional branches and ordinary code do NOT end fall-through", () => {
    for (const w of [0x9400002c, 0xd63f0100, 0xd63f091f, 0xd73f0909, // bl, blr, blraaz, blraa
        0x540001e0, 0xb4000221, 0x37180201,                          // b.eq, cbz, tbnz
        0xd503201f, 0xd503233f, 0x910100a1, 0x10000005]) {           // nop, paciasp, add, adr
        assert.equal(endsFallThrough(w), false, w.toString(16));
    }
    assert.equal(isBLRAuth(0xd63f091f), true);  // blraaz x8
    assert.equal(isBLRAuth(0xd73f0909), true);  // blraa x8, x9
    assert.equal(isBLRAuth(0xd63f0100), false); // plain blr (isBLR's job)
});

// ---- writesReg (conservative) ----------------------------------------------

test("register fields Rt2 and Rs", () => {
    assert.equal(regRt2(0xa94008a1), 2);  // ldp x1, x2, [x5]
    assert.equal(regRs(0xc8017ca2), 1);   // stxr w1, x2, [x5]
});

test("writesReg: every writer of x1 is detected", () => {
    const writersOfX1: [number, string][] = [
        [0xaa0503e1, "mov x1, x5"], [0xd28000a1, "movz x1, #5"], [0xf2a000a1, "movk x1, #5, lsl #16"],
        [0xaa0303e1, "orr x1, xzr, x3"], [0xd1002021, "sub x1, x1, #8"], [0x910100a1, "add x1, x5, #0x40"],
        [0x9a830041, "csel x1, x2, x3, eq"], [0x10000005 & ~0x1f | 1, "adr x1, ."], [0x90000001, "adrp x1, ."],
        [0xf94004a1, "ldr x1, [x5, #8]"], [0xf84084a1, "ldr x1, [x5], #8"], [0xf8408425, "ldr x5, [x1], #8 (wb)"],
        [0xf8408c25, "ldr x5, [x1, #8]! (wb)"], [0xa94008a1, "ldp x1, x2, [x5]"], [0xa94004a2, "ldp x2, x1, [x5]"],
        [0xa8c11023, "ldp x3, x4, [x1], #16 (wb)"], [0xa9811023, "stp x3, x4, [x1, #16]! (wb)"],
        [0xf8008c25, "str x5, [x1, #8]! (wb)"], [0xf85f80a1, "ldur x1, [x5, #-8]"], [0xb86668a1, "ldr w1, [x5, x6]"],
        [0x58000001, "ldr x1, <literal>"], [0x394000a1, "ldrb w1, [x5]"], [0xb98000a1, "ldrsw x1, [x5]"],
        [0xd53bd041, "mrs x1, tpidr_el0"], [0xc85f7ca1, "ldxr x1, [x5]"], [0xc8017ca2, "stxr w1, x2, [x5] (status)"],
        [0xc8a17ca2, "cas x1, x2, [x5]"], [0xf82300a1, "ldadd x3, x1, [x5]"], [0x4cdf7020, "ld1 {v0}, [x1], #16 (wb)"],
        [0x9e660001, "fmov x1, d0"], [0x0e013c01, "umov w1, v0.b[0]"], [0xf82004a1, "ldraa x1, [x5]"],
        [0xf8201c25, "ldraa x5, [x1, #8]! (wb)"],
    ];
    for (const [w, what] of writersOfX1) assert.equal(writesReg(w >>> 0, 1), true, what);
});

test("writesReg: calls write x30 only", () => {
    for (const w of [0x9400002c, 0xd63f0100, 0xd63f091f, 0xd73f0909]) {
        assert.equal(writesReg(w, 30), true, w.toString(16));
        assert.equal(writesReg(w, 8), false, w.toString(16));
    }
});

test("writesReg: non-writers of x1 are allowed through", () => {
    const nonWritersOfX1: [number, string][] = [
        [0xd503201f, "nop"], [0xd503233f, "paciasp"], [0xf90000a1, "str x1, [x5]"],
        [0xa9010be1, "stp x1, x2, [sp, #16]"], [0xf100103f, "cmp x1, #4"], [0xb4000221, "cbz x1"],
        [0x37180201, "tbnz w1, #3"], [0x540001e0, "b.eq"], [0x14000038, "b"], [0xd65f03c0, "ret"],
        [0x9400002c, "bl"], [0xf94004a2, "ldr x2, [x5, #8]"], [0x910100a2, "add x2, x5, #0x40"],
        [0xf8008c25 & ~0x3e0 | (5 << 5), "str x5, [x5, #8]! (wb x5)"], [0x4c4070a1, "ld1 {v1}, [x5]"],
        [0xa94008a3, "ldp x3, x2, [x5]"], [0xf82300a2, "ldadd x3, x2, [x5]"],
    ];
    for (const [w, what] of nonWritersOfX1) assert.equal(writesReg(w >>> 0, 1), false, what);
});
