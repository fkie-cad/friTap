// agent/shared/arm64.ts
//
// Pure AArch64 instruction-word helpers: opcode predicates, immediate decoders,
// and register-field extractors. Everything here operates on a single 32-bit
// instruction word as a plain JS number (as produced by NativePointer.readU32(),
// i.e. unsigned 0..0xFFFFFFFF) and returns plain numbers/booleans. There are NO
// imports and NO Frida dependencies on purpose, so this module is unit-testable
// under plain Node (see arm64.test.ts).
//
// WHY THIS MODULE EXISTS — the unsigned-coercion footgun it contains:
//   JavaScript evaluates `&` on signed int32 operands, so `(insn & 0x9f000000)`
//   is NEGATIVE whenever bit 31 is set, while the hex literal `0x90000000` is a
//   positive double. So the natural-looking `(insn & MASK) === OP` is ALWAYS
//   FALSE for every AArch64 opcode (their top bit is set). The fix is to coerce
//   the masked value back to unsigned with `>>> 0` before comparing. `maskEq()`
//   does that once, so callers can never reintroduce the bug.

/** ((insn & mask) >>> 0) === op — the unsigned-safe masked compare. */
function maskEq(insn: number, mask: number, op: number): boolean {
    return ((insn & mask) >>> 0) === (op >>> 0);
}

// ---- register fields ----------------------------------------------------

/** Rd / Rt — bits[4:0]. */
export function regRd(insn: number): number {
    return insn & 0x1f;
}

/** Rn — bits[9:5]. */
export function regRn(insn: number): number {
    return (insn >>> 5) & 0x1f;
}

// ---- opcode predicates --------------------------------------------------

/** ADRP Xd, imm. */
export function isADRP(insn: number): boolean {
    return maskEq(insn, 0x9f000000, 0x90000000);
}

/** ADD (immediate, 64-bit): ADD Xd, Xn, #imm{, LSL #12}. */
export function isADDimm64(insn: number): boolean {
    return maskEq(insn, 0xff000000, 0x91000000);
}

/** LDR (immediate, unsigned offset, 64-bit): LDR Xt, [Xn, #imm12*8]. */
export function isLDRimmU64(insn: number): boolean {
    return maskEq(insn, 0xffc00000, 0xf9400000);
}

/** BL (direct, PC-relative call). */
export function isBL(insn: number): boolean {
    return maskEq(insn, 0xfc000000, 0x94000000);
}

/** BLR (indirect register call). */
export function isBLR(insn: number): boolean {
    return maskEq(insn, 0xfffffc1f, 0xd63f0000);
}

/**
 * True if `insn` looks like a function-entry word. This is the union (superset)
 * of every prologue encoding previously hand-rolled in signal_libsignal.ts
 * (_looksLikePrologue) and tls/shared/pattern_based_hooking.ts
 * (isLikelyArm64Prologue), so migrating both to this predicate never rejects a
 * prologue either of them already (intended to) accept. It is a heuristic
 * entry-point filter, not a proof.
 *
 * Accepted: paciasp / pacibsp PAC landing pads; BTI {c|j|jc}; STP x29,x30 frame
 * setup (signed-offset form); any STP-to-sp pre-index store (broad form, covers
 * x29,x30 pre-index and callee-saved pairs); SUB sp, sp, #imm (any LSL).
 */
export function isFunctionPrologueWord(insn: number): boolean {
    // PAC landing pads — exact words (no mask needed; safe against the footgun).
    if ((insn >>> 0) === 0xd503233f) return true; // paciasp
    if ((insn >>> 0) === 0xd503237f) return true; // pacibsp
    // BTI {c|j|jc}.
    if (maskEq(insn, 0xffffff1f, 0xd503241f)) return true;
    // STP x29, x30, [sp, #imm] — signed offset, no writeback.
    if (maskEq(insn, 0xffc07fff, 0xa9007bfd)) return true;
    // STP <pair>, [sp, #-imm]! — broad pre-index region (any Rt/Rt2 to sp).
    if (maskEq(insn, 0xffc00000, 0xa9800000)) return true;
    // SUB sp, sp, #imm{, LSL #12} — Rd == Rn == sp(31).
    if (maskEq(insn, 0xff000000, 0xd1000000) && regRd(insn) === 31 && regRn(insn) === 31) return true;
    return false;
}

// ---- immediate decoders (pure; return JS numbers) -----------------------

/**
 * ADRP page immediate, already shifted << 12 and SIGN-EXTENDED. The targeted
 * page is `(pc & ~0xFFF) + decodeADRPImm(insn)`. immlo = bits[30:29],
 * immhi = bits[23:5] (19 bits) → 21-bit signed value. Uses `*` (not `<<`)
 * because the shifted result exceeds 32 bits.
 */
export function decodeADRPImm(insn: number): number {
    const immlo = (insn >>> 29) & 0x3;
    const immhi = (insn >>> 5) & 0x7ffff; // 19 bits
    let imm = (immhi << 2) | immlo;       // 21-bit value
    if (imm & 0x100000) imm -= 0x200000;  // sign-extend 21 bits
    return imm * 0x1000;                  // << 12
}

/** ADD-immediate 12-bit value, honoring the LSL #12 shift bit (bits[23:22]). */
export function decodeADDImm12(insn: number): number {
    const imm12 = (insn >>> 10) & 0xfff;
    const shift = (insn >>> 22) & 0x3; // 1 => LSL #12
    return shift === 1 ? imm12 << 12 : imm12;
}

/** LDR (unsigned offset, 64-bit) byte displacement: imm12 scaled by 8. */
export function decodeLDRU64Imm(insn: number): number {
    return ((insn >>> 10) & 0xfff) * 8;
}

/** BL byte offset, SIGNED: imm26 sign-extended then << 2. */
export function decodeBLImm(insn: number): number {
    let imm26 = insn & 0x03ffffff;
    if (imm26 & 0x02000000) imm26 -= 0x04000000; // sign-extend 26 bits
    return imm26 * 4;                             // << 2
}
