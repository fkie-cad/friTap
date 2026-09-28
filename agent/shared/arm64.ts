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

/** Rt2 — bits[14:10] (second register of a load/store pair). */
export function regRt2(insn: number): number {
    return (insn >>> 10) & 0x1f;
}

/** Rs — bits[20:16] (status / compare register of exclusives and atomics). */
export function regRs(insn: number): number {
    return (insn >>> 16) & 0x1f;
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

/** STR (immediate, unsigned offset, 64-bit): STR Xt, [Xn, #imm12*8]. */
export function isSTRimmU64(insn: number): boolean {
    return maskEq(insn, 0xffc00000, 0xf9000000);
}

/** RET (to x30) — the exact word; no mask needed. */
export function isRET(insn: number): boolean {
    return (insn >>> 0) === 0xd65f03c0;
}

/** BL (direct, PC-relative call). */
export function isBL(insn: number): boolean {
    return maskEq(insn, 0xfc000000, 0x94000000);
}

/** BLR (indirect register call). */
export function isBLR(insn: number): boolean {
    return maskEq(insn, 0xfffffc1f, 0xd63f0000);
}

/** ADR Xd, label (op=0): PC-relative byte address, ±1 MB. */
export function isADR(insn: number): boolean {
    return maskEq(insn, 0x9f000000, 0x10000000);
}

/** B label (unconditional, PC-relative; same imm26 encoding as BL). */
export function isUnconditionalB(insn: number): boolean {
    return maskEq(insn, 0xfc000000, 0x14000000);
}

/** Any return: RET Xn (any register, incl. x30) and the PAC forms RETAA / RETAB. */
export function isAnyReturn(insn: number): boolean {
    const w = insn >>> 0;
    return maskEq(insn, 0xfffffc1f, 0xd65f0000) || w === 0xd65f0bff || w === 0xd65f0fff;
}

/** Indirect jump: BR Xn, BRAAZ / BRABZ Xn, BRAA / BRAB Xn, Xm. */
export function isIndirectBranch(insn: number): boolean {
    return maskEq(insn, 0xfffffc1f, 0xd61f0000)  // BR
        || maskEq(insn, 0xfffff81f, 0xd61f081f)  // BRAAZ / BRABZ
        || maskEq(insn, 0xfffff800, 0xd71f0800); // BRAA / BRAB
}

/** Authenticated indirect call: BLRAAZ / BLRABZ Xn, BLRAA / BLRAB Xn, Xm. */
export function isBLRAuth(insn: number): boolean {
    return maskEq(insn, 0xfffff81f, 0xd63f081f)  // BLRAAZ / BLRABZ
        || maskEq(insn, 0xfffff800, 0xd73f0800); // BLRAA / BLRAB
}

/** BRK #imm16 or UDF #imm16 (also what zero padding between functions decodes as). */
export function isTrap(insn: number): boolean {
    return maskEq(insn, 0xffe0001f, 0xd4200000) || maskEq(insn, 0xffff0000, 0x00000000);
}

/**
 * True if execution never falls through to the next word: an unconditional B,
 * any return, an indirect jump, or a trap. A linear forward walk that models
 * "the code that runs after this instruction" must stop here — the next word
 * belongs to another basic block or, typically, to the next function.
 */
export function endsFallThrough(insn: number): boolean {
    return isUnconditionalB(insn) || isAnyReturn(insn) || isIndirectBranch(insn) || isTrap(insn);
}

/** CBZ Xt, label (compare-and-branch-if-zero, 64-bit, sf=1). */
export function isCBZ64(insn: number): boolean {
    return maskEq(insn, 0xff000000, 0xb4000000);
}

/** CBNZ Xt, label (compare-and-branch-if-nonzero, 64-bit, sf=1). */
export function isCBNZ64(insn: number): boolean {
    return maskEq(insn, 0xff000000, 0xb5000000);
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

// ---- register-write analysis (conservative, fail-closed) ------------------
//
// writesReg() answers "may this instruction overwrite general-purpose register
// `reg`?". It is used to prove that nothing between an ADRP and its ADD/LDR
// clobbered the ADRP's register. A false "yes" only drops a candidate xref
// (fail closed); a false "no" could accept a wrong one. So every class that is
// not fully understood answers "yes" whenever ANY of its register fields is
// `reg`. Writes to SIMD/FP registers with the same number count as writes too
// (harmless over-rejection).

/** Instruction-set top-level groups (op0 = bits[28:25]). */
function isBranchOrSystemGroup(insn: number): boolean {
    return maskEq(insn, 0x1c000000, 0x14000000); // op0 = 101x
}
function isLoadStoreGroup(insn: number): boolean {
    return maskEq(insn, 0x0a000000, 0x08000000); // op0 = x1x0
}

/** Branches / exceptions / system: only calls (x30), MRS and SYSL (Rt) write a GPR. */
function branchOrSystemWritesReg(insn: number, reg: number): boolean {
    if (isBL(insn) || isBLR(insn) || isBLRAuth(insn)) return reg === 30;
    if (maskEq(insn, 0xfff00000, 0xd5300000)) return regRd(insn) === reg; // MRS
    if (maskEq(insn, 0xfff80000, 0xd5280000)) return regRd(insn) === reg; // SYSL
    return false; // B, B.cond, CBZ/CBNZ, TBZ/TBNZ, BR, RET, hints, barriers, MSR, SVC/BRK
}

/** Every register field of a load/store word — the fail-closed fallback set. */
function anyLoadStoreField(insn: number, reg: number): boolean {
    const rt = regRd(insn), rs = regRs(insn);
    return [rt, (rt + 1) & 0x1f, regRt2(insn), regRn(insn), rs, (rs + 1) & 0x1f].includes(reg);
}

/** LDP/STP (bits[29:27] = 101): writeback writes Rn; loads write Rt and Rt2. */
function pairWritesReg(insn: number, reg: number): boolean {
    const index = (insn >>> 23) & 0x3; // 01 post-index, 11 pre-index (both write back)
    if ((index === 1 || index === 3) && regRn(insn) === reg) return true;
    const isLoad = ((insn >>> 22) & 1) === 1;
    return isLoad && (regRd(insn) === reg || regRt2(insn) === reg);
}

/** LDR/STR single register (bits[29:27] = 111), all addressing modes and atomics. */
function singleRegisterWritesReg(insn: number, reg: number): boolean {
    const rt = regRd(insn);
    const isLoad = ((insn >>> 22) & 0x3) !== 0; // opc 00 = store (STR Q counts as load: fail closed)
    const mode = (insn >>> 10) & 0x3;
    if (((insn >>> 24) & 1) === 1) return isLoad && rt === reg;              // unsigned offset
    if (((insn >>> 21) & 1) === 0) {                                          // imm9 forms
        if ((mode === 1 || mode === 3) && regRn(insn) === reg) return true;   // post/pre-index
        return isLoad && rt === reg;
    }
    if (mode === 0) return rt === reg;                                        // atomics (LDADD, SWP, ...)
    if (mode === 2) return isLoad && rt === reg;                              // register offset
    return rt === reg || (((insn >>> 11) & 1) === 1 && regRn(insn) === reg);  // LDRAA/LDRAB {!}
}

/** Load/store group dispatcher; unknown sub-classes fall back to every field. */
function loadStoreWritesReg(insn: number, reg: number): boolean {
    const cls = (insn >>> 27) & 0x7; // bits[29:27]
    const simd = ((insn >>> 26) & 1) === 1;
    if (cls === 0b101) return pairWritesReg(insn, reg);
    if (cls === 0b111) return singleRegisterWritesReg(insn, reg);
    if (cls === 0b011 && ((insn >>> 24) & 1) === 0) return regRd(insn) === reg; // LDR (literal)
    if (cls === 0b001 && simd && (insn >>> 31) === 0) {                         // LD1..LD4 / ST1..ST4
        return ((insn >>> 23) & 1) === 1 && regRn(insn) === reg;                // post-index writeback
    }
    return anyLoadStoreField(insn, reg); // exclusives, CAS/CASP, LDAPR/STLUR, MTE, ...
}

/**
 * Conservative: true if `insn` may write general-purpose register `reg` (0..30).
 * Data-processing (immediate, register, SIMD/FP, SVE, and anything unallocated)
 * writes only its Rd = bits[4:0], so that is the answer there.
 */
export function writesReg(insn: number, reg: number): boolean {
    if (isBranchOrSystemGroup(insn)) return branchOrSystemWritesReg(insn, reg);
    if (isLoadStoreGroup(insn)) return loadStoreWritesReg(insn, reg);
    return regRd(insn) === reg;
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

/**
 * STR (unsigned offset, 64-bit) byte displacement. The imm12 field sits in the
 * same bits and uses the same scaling as the LDR form, so this delegates — it
 * exists so call sites read as what they decode.
 */
export function decodeSTRU64Imm(insn: number): number {
    return decodeLDRU64Imm(insn);
}

/**
 * ADR byte offset, SIGNED: the target is `pc + decodeADRImm(insn)` (no page
 * masking, unlike ADRP). Same immhi:immlo fields as ADRP, NOT shifted → ±1 MB.
 */
export function decodeADRImm(insn: number): number {
    const immlo = (insn >>> 29) & 0x3;
    const immhi = (insn >>> 5) & 0x7ffff; // 19 bits
    let imm = (immhi << 2) | immlo;       // 21-bit value
    if (imm & 0x100000) imm -= 0x200000;  // sign-extend 21 bits
    return imm;
}

/** BL byte offset, SIGNED: imm26 sign-extended then << 2. */
export function decodeBLImm(insn: number): number {
    let imm26 = insn & 0x03ffffff;
    if (imm26 & 0x02000000) imm26 -= 0x04000000; // sign-extend 26 bits
    return imm26 * 4;                             // << 2
}

// ---- scan-pattern builders (for native Memory.scan "pattern : mask") ----
//
// A Memory.scan over a 187 MB code segment is native speed; a JS readU32() walk
// over the same range is ~10 minutes. These builders turn "an instruction word
// with this immediate, any registers" into a Frida match pattern so the xref
// search can run natively (see arm64_xref.ts findStringLoadSitesAsync).

/** Keeps opcode + shift + imm12 (bits[31:10]); ignores Rn (bits[9:5]) and Rd/Rt (bits[4:0]). */
export const IMM12_OPERAND_MASK = 0xfffffc00;

/** ADD Xd, Xn, #imm12 (64-bit, no shift) with Rd = Rn = 0 — the register-free search word. */
export function addImm64WordForImm12(imm12: number): number {
    return (0x91000000 | ((imm12 & 0xfff) << 10)) >>> 0;
}

/** LDR Xt, [Xn, #imm12*8] (unsigned offset, 64-bit) with Rt = Rn = 0 — the register-free search word. */
export function ldrU64WordForImm12(imm12: number): number {
    return (0xf9400000 | ((imm12 & 0xfff) << 10)) >>> 0;
}

/** One 32-bit value as four little-endian, space-separated hex bytes ("00 04 00 91"). */
function wordToLEHex(word: number): string {
    const bytes: string[] = [];
    for (let i = 0; i < 4; i++) bytes.push(((word >>> (8 * i)) & 0xff).toString(16).padStart(2, "0"));
    return bytes.join(" ");
}

/**
 * Frida "pattern : mask" string matching `word` under `mask` (little-endian, as
 * AArch64 code is stored). Frida AND-s the mask into needle and haystack alike.
 * Matches are NOT guaranteed 4-byte aligned; callers must check alignment.
 */
export function maskedWordScanPattern(word: number, mask: number): string {
    return `${wordToLEHex((word & mask) >>> 0)} : ${wordToLEHex(mask >>> 0)}`;
}

/**
 * The most-significant byte (byte 3 in memory) of every `ADR Xd, T` word, for
 * any pc: op=0 (bit 31), immlo (bits[30:29]) and 10000 (bits[28:24]). Because
 * pc is 4-aligned, immlo = (T - pc) & 3 = T & 3, so the byte depends on the
 * target alone — a 1-byte exact scan needle that pins the opcode.
 */
export function adrTopByteForTarget(targetLow2: number): number {
    return 0x10 | ((targetLow2 & 0x3) << 5);
}

/** Scan pattern for "ADD Xd, Xn, #imm12 (no shift), any Xd/Xn". */
export function addImm64ScanPattern(imm12: number): string {
    return maskedWordScanPattern(addImm64WordForImm12(imm12), IMM12_OPERAND_MASK);
}

/** Scan pattern for "LDR Xt, [Xn, #imm12*8], any Xt/Xn". */
export function ldrU64ScanPattern(imm12: number): string {
    return maskedWordScanPattern(ldrU64WordForImm12(imm12), IMM12_OPERAND_MASK);
}
