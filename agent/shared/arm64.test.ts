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
    isADRP, isADDimm64, isLDRimmU64, isBL, isBLR, isFunctionPrologueWord,
    decodeADRPImm, decodeADDImm12, decodeLDRU64Imm, decodeBLImm, regRd, regRn,
} from "./arm64.js";

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
