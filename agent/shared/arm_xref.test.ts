// Unit tests for the pure Thumb-2 decoders of arm_xref.ts, on real Fenix 160.0.1
// armeabi-v7a libnss3.so bytes where possible (static fixtures, no device).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import {
    addImmediate, addPcRegister, directBranch, endsFallThrough, findPcRelativeRefs, firstThumbCallTarget,
    itBlockLength, ldrLiteral, moveWide, pcRelativeRefsAt, registerMove, thumbDirectCallTargets,
    thumbExpandImm, thumbFunctionEnd, thumbInsnAt, thumbInsnSize, writtenRegisters, PC, type WordReader32,
} from "./arm_xref.js";
import {
    CLIENT_RANDOM_ADD_PC, CLIENT_RANDOM_LDR, CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, CLIENT_RANDOM_STR,
    ECH_CONFIG_ADD_PC, ECH_CONFIG_STR, ECH_SECRET_ADD_PC, ECH_SECRET_STR, ECH_TAIL_FN, ECH_TAIL_FN_VADDR,
    WRITER, WRITER_CODE_END, WRITER_VADDR,
} from "./__fixtures__/nss_fenix160_arm.js";

function hex(text: string): Uint8Array {
    return Uint8Array.from(text.match(/../g)!.map((b) => parseInt(b, 16)));
}

/** The single instruction encoded by `bytes` (hex, little-endian halfwords) at `address`. */
function insn(bytes: string, address = 0x1000) {
    return thumbInsnAt(hex(bytes), address, 0)!;
}

/** u32 reader over one fixture slice. */
function wordsOf(bytes: Uint8Array, base: number): WordReader32 {
    return (addr) => {
        const at = addr - base;
        if (at < 0 || at + 4 > bytes.length) return null;
        return (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0;
    };
}

// ---- lengths ------------------------------------------------------------------------

test("instruction length: 16-bit unless the top five bits are 11101/11110/11111", () => {
    assert.equal(thumbInsnSize(0x4846), 2);   // mov r0, sb
    assert.equal(thumbInsnSize(0xe7da), 2);   // b (T2)
    assert.equal(thumbInsnSize(0xe8bd), 4);   // pop.w
    assert.equal(thumbInsnSize(0xf7fa), 4);   // bl
    assert.equal(thumbInsnSize(0xf85f), 4);   // ldr.w literal
});

// ---- literals ---------------------------------------------------------------------------

test("ldr literal T1 uses Align(PC, 4): CLIENT_RANDOM pool word @0x1c036c", () => {
    assert.deepEqual(ldrLiteral(insn("0549", CLIENT_RANDOM_LDR)), { rt: 1, address: 0x1c036c });
    assert.deepEqual(ldrLiteral(insn("2848", 0x1bb3d0)), { rt: 0, address: 0x1bb474 });
});

test("ldr.w literal T2: +imm12 and -imm12", () => {
    assert.deepEqual(ldrLiteral(insn("dff80021", 0x1002)), { rt: 2, address: 0x1104 });
    assert.deepEqual(ldrLiteral(insn("5ff80021", 0x1002)), { rt: 2, address: 0xf04 });
    assert.equal(ldrLiteral(insn("d2f800a0")), null); // ldr.w sl, [r2]
});

test("add Rdn, pc decodes low and high registers only", () => {
    assert.equal(addPcRegister(insn("7944")), 1);
    assert.equal(addPcRegister(insn("7844")), 0);
    assert.equal(addPcRegister(insn("f844")), 8);
    assert.equal(addPcRegister(insn("2046")), null); // mov r0, r4
});

test("movw / movt immediates (the writer's 0xffffe013 error code)", () => {
    assert.deepEqual(moveWide(insn("4ef21300")), { rd: 0, imm16: 0xe013, top: false });
    assert.deepEqual(moveWide(insn("cff6ff70")), { rd: 0, imm16: 0xffff, top: true });
    assert.equal(moveWide(insn("04f58563")), null);
});

test("pcRelativeRefsAt resolves the real CLIENT_RANDOM ldr + add pc", () => {
    const refs = pcRelativeRefsAt(CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, CLIENT_RANDOM_ADD_PC,
        wordsOf(CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR));
    assert.ok(refs.some((r) => r.value === CLIENT_RANDOM_STR && r.loadAt === CLIENT_RANDOM_LDR));
});

test("pcRelativeRefsAt resolves movw + movt + add pc", () => {
    // 0x2000: movw r3, #0x1234 ; movt r3, #0x0001 ; add r3, pc
    const bytes = hex("41f23423" + "c0f20103" + "7b44");
    const refs = pcRelativeRefsAt(bytes, 0x2000, 0x2008, () => null);
    assert.deepEqual(refs.map((r) => r.value), [(0x11234 + 0x2008 + 4) >>> 0]);
});

test("an intervening write of Rx breaks the materialisation", () => {
    // ldr r1, [pc, #0] ; movs r1, #0 ; add r1, pc
    const bytes = hex("0049" + "0021" + "7944" + "0000" + "44332211");
    assert.deepEqual(pcRelativeRefsAt(bytes, 0x3000, 0x3004, wordsOf(bytes, 0x3000)), []);
});

test("findPcRelativeRefs finds both ECH label references of fn 0x1d8b4c", () => {
    const found = findPcRelativeRefs(ECH_TAIL_FN, ECH_TAIL_FN_VADDR, [ECH_SECRET_STR, ECH_CONFIG_STR, 0x12345],
        wordsOf(ECH_TAIL_FN, ECH_TAIL_FN_VADDR));
    assert.deepEqual(found.map((refs) => refs.map((r) => r.addPcAt)), [[ECH_SECRET_ADD_PC], [ECH_CONFIG_ADD_PC], []]);
});

// ---- immediates and moves -------------------------------------------------------------------

test("ThumbExpandImm: all four replication forms and a rotation", () => {
    assert.equal(thumbExpandImm(0x0ab), 0xab);
    assert.equal(thumbExpandImm(0x1ab), 0x00ab00ab);
    assert.equal(thumbExpandImm(0x2ab), 0xab00ab00);
    assert.equal(thumbExpandImm(0x3ab), 0xabababab);
    assert.equal(thumbExpandImm(0xe85), 0x428);     // the writer's add.w r3, r4, #0x428
    assert.equal(thumbExpandImm(0x4ff), 0x7f800000);
});

test("add.w T3 and addw T4 immediates; cmn is not an add", () => {
    assert.deepEqual(addImmediate(insn("04f58563")), { rd: 3, rn: 4, imm: 0x428 });
    assert.deepEqual(addImmediate(insn("00f6a442")), { rd: 2, rn: 0, imm: 0xca4 });  // addw r2, r0, #0xca4
    assert.deepEqual(addImmediate(insn("10f14308")), { rd: 8, rn: 0, imm: 0x43 });   // adds.w r8, r0, #0x43
    assert.equal(addImmediate(insn("10f1010f")), null);                              // cmn.w r0, #1
    assert.equal(addImmediate(insn("a0f12000")), null);                              // sub.w r0, r0, #0x20
});

test("register moves: mov T1 (high regs), movs T2, mov.w", () => {
    assert.deepEqual(registerMove(insn("0446")), { rd: 4, rm: 0 });
    assert.deepEqual(registerMove(insn("8146")), { rd: 9, rm: 0 });   // mov sb, r0
    assert.deepEqual(registerMove(insn("0400")), { rd: 4, rm: 0 });   // movs r4, r0
    assert.deepEqual(registerMove(insn("4fea0004")), { rd: 4, rm: 0 });
    assert.equal(registerMove(insn("4fea1515")), null);              // lsr.w r5, r5, #4
});

// ---- branches -----------------------------------------------------------------------------

test("bl / blx / b.w / b / b<cond> / cbz targets from the real writer and its callers", () => {
    assert.deepEqual(directBranch(insn("faf7f5ff", 0x1c035e)), { kind: "bl", target: 0x1bb34c });
    assert.deepEqual(directBranch(insn("22f022eb", 0x1bb388)), { kind: "blx", target: 0x1dd9d0 });
    assert.deepEqual(directBranch(insn("e2f7ddbb", 0x1d8b8e)), { kind: "b", target: 0x1bb34c });
    assert.deepEqual(directBranch(insn("21f00dbf", 0x1bb36e)), { kind: "b", target: 0x1dd18c });
    assert.deepEqual(directBranch(insn("dae7", 0x1bb46e)), { kind: "b", target: 0x1bb426 });
    assert.deepEqual(directBranch(insn("e3d4", 0x1bb396)), { kind: "bcond", target: 0x1bb360 });
    assert.deepEqual(directBranch(insn("aab3", 0x1bb3fe)), { kind: "cbz", target: 0x1bb46c });
    assert.deepEqual(directBranch(insn("01f00080", 0x1000)), { kind: "bcond", target: 0x2004 }); // beq.w (T3)
    assert.equal(directBranch(insn("2046")), null);
});

test("IT block lengths", () => {
    assert.equal(itBlockLength(insn("1ebf")), 3);  // ittt ne
    assert.equal(itBlockLength(insn("98bf")), 1);  // it ls
    assert.equal(itBlockLength(insn("04bf")), 2);  // itt eq
    assert.equal(itBlockLength(insn("00bf")), 0);  // nop
});

test("register writes: loads, stores, writeback, compares, pop", () => {
    assert.equal(writtenRegisters(insn("dc5d")), 1 << 4);              // ldrb r4, [r3, r7]
    assert.equal(writtenRegisters(insn("02f8010b")), 1 << 2);          // strb r0, [r2], #1 (writeback)
    assert.equal(writtenRegisters(insn("c6e90f10")), 0);               // strd r1, r0, [r6, #0x3c]
    assert.equal(writtenRegisters(insn("002a")), 0);                   // cmp r2, #0
    assert.equal(writtenRegisters(insn("b8f1010f")), 0);               // cmp.w r8, #1
    assert.equal(writtenRegisters(insn("19f80020")), 1 << 2);          // ldrb.w r2, [sb, r0]
    assert.ok((writtenRegisters(insn("bde8f087")) & (1 << PC)) !== 0); // pop.w {…, pc}
    assert.equal(writtenRegisters(insn("00eb4100")), 1 << 0);          // add.w r0, r0, r1, lsl #1
});

test("dead ends: bx lr, pop {pc}, b.w; not pop {lr}, bl or a conditional branch", () => {
    assert.ok(endsFallThrough(insn("7047")));
    assert.ok(endsFallThrough(insn("10bd")));
    assert.ok(endsFallThrough(insn("e2f7ddbb", 0x1d8b8e)));
    assert.ok(!endsFallThrough(insn("bde8f047")));
    assert.ok(!endsFallThrough(insn("faf7f5ff")));
    assert.ok(!endsFallThrough(insn("e3d4")));
});

// ---- function extent and calls ----------------------------------------------------------------

test("the writer's swept end is its last `b` back, before the literal pool", () => {
    assert.equal(thumbFunctionEnd(WRITER, WRITER_VADDR), WRITER_CODE_END);
});

test("CLIENT_RANDOM site: the first call after the add pc is `bl` to the writer", () => {
    assert.equal(firstThumbCallTarget(CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, CLIENT_RANDOM_ADD_PC), WRITER_VADDR);
});

test("ECH sites: `bl` for ECH_SECRET, tail `b.w` after pop.w {…, lr} for ECH_CONFIG", () => {
    assert.equal(firstThumbCallTarget(ECH_TAIL_FN, ECH_TAIL_FN_VADDR, ECH_SECRET_ADD_PC), WRITER_VADDR);
    assert.equal(firstThumbCallTarget(ECH_TAIL_FN, ECH_TAIL_FN_VADDR, ECH_CONFIG_ADD_PC), WRITER_VADDR);
});

test("a return before any call yields no callee", () => {
    // add r1, pc ; bx lr ; bl …
    assert.equal(firstThumbCallTarget(hex("7944" + "7047" + "faf7f5ff"), 0x1000, 0x1000), null);
});

test("an intra-function `b` before the call is followed", () => {
    // 0x1000: add r1, pc ; b 0x1006 ; udf ; bl 0x1bb34c (at 0x1006, bytes of the real bl re-based)
    const bl = directBranch(insn("faf7f5ff", 0x1006))!.target;
    assert.equal(firstThumbCallTarget(hex("7944" + "00e0" + "00de" + "faf7f5ff"), 0x1000, 0x1000), bl);
});

test("direct call targets: bl and tail b.w, blx (A32 PLT) skipped, deduplicated", () => {
    assert.deepEqual(thumbDirectCallTargets(ECH_TAIL_FN.subarray(0, 0x46), ECH_TAIL_FN_VADDR), [WRITER_VADDR]);
});
