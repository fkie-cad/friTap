// agent/shared/arm_xref.ts
//
// Pure Thumb-2 (T32) decoders for 32-bit ARM code, plus the scans built on them:
// resolving PC-relative literal materialisations (`ldr Rx, [pc, #i]` or
// `movw/movt Rx` followed by `add Rx, pc`) and walking from a label load site
// to the first direct call. Everything here works on plain bytes and numeric
// addresses (module offsets), so it is unit-tested on real libnss3.so bytes
// without Frida. ARM (A32) mode is not decoded: Android arm32 libraries are
// Thumb-2, and the A32 code in them is PLT stubs reached by `blx`.
//
// Register write sets are CONSERVATIVE: an encoding this file does not model
// reports "writes every register" (ALL_REGISTERS), so a tracker built on it can
// only lose a value, never keep a stale one.

/** One decoded Thumb instruction: first and second halfword (0 for 16-bit). */
export interface ThumbInsn {
    address: number;
    hw1: number;
    hw2: number;
    size: 2 | 4;
}

const ALL_REGISTERS = 0xffff;
export const SP = 13;
export const LR = 14;
export const PC = 15;
/** AAPCS: a call may clobber r0-r3, r12 and lr. */
export const CALL_CLOBBERED = 0b0101_0000_0000_1111;

const bit = (reg: number) => 1 << reg;

function sext(value: number, bits: number): number {
    const shift = 32 - bits;
    return (value << shift) >> shift;
}

function align4(value: number): number {
    return value - (value % 4);
}

// ---- instruction stream ---------------------------------------------------------

/** 4 when `hw1` opens a 32-bit Thumb-2 instruction (top five bits 0b11101/0b11110/0b11111). */
export function thumbInsnSize(hw1: number): 2 | 4 {
    return (hw1 >>> 11) >= 0b11101 ? 4 : 2;
}

function readU16(bytes: Uint8Array, at: number): number {
    return bytes[at] | (bytes[at + 1] << 8);
}

/** The instruction at byte index `at` of `bytes` (mapped at `base`), or null past the end. */
export function thumbInsnAt(bytes: Uint8Array, base: number, at: number): ThumbInsn | null {
    if (at < 0 || at + 2 > bytes.length) return null;
    const hw1 = readU16(bytes, at);
    const size = thumbInsnSize(hw1);
    if (at + size > bytes.length) return null;
    return { address: base + at, hw1, hw2: size === 4 ? readU16(bytes, at + 2) : 0, size };
}

/** Linear decode of `bytes` (mapped at `base`) from address `from` up to (not including) `end`. */
export function decodeThumb(bytes: Uint8Array, base: number, from: number = base,
                            end: number = base + bytes.length): ThumbInsn[] {
    const insns: ThumbInsn[] = [];
    for (let at = from - base; base + at < end;) {
        const insn = thumbInsnAt(bytes, base, at);
        if (insn === null) break;
        insns.push(insn);
        at += insn.size;
    }
    return insns;
}

// ---- immediates -------------------------------------------------------------------

/** ThumbExpandImm (ARM ARM A6.3.2): the 32-bit value of a modified 12-bit immediate. */
export function thumbExpandImm(imm12: number): number {
    const imm8 = imm12 & 0xff;
    if ((imm12 >>> 10) === 0) {
        switch ((imm12 >>> 8) & 3) {
            case 0: return imm8;
            case 1: return ((imm8 << 16) | imm8) >>> 0;
            case 2: return ((imm8 << 24) | (imm8 << 8)) >>> 0;
            default: return (imm8 * 0x01010101) >>> 0;
        }
    }
    const unrotated = 0x80 | (imm12 & 0x7f);
    const rotation = (imm12 >>> 7) & 0x1f;
    return ((unrotated >>> rotation) | (unrotated << (32 - rotation))) >>> 0;
}

/** The i:imm3:imm8 field of a 32-bit data-processing (immediate) instruction. */
function imm12Of(insn: ThumbInsn): number {
    return (((insn.hw1 >>> 10) & 1) << 11) | (((insn.hw2 >>> 12) & 7) << 8) | (insn.hw2 & 0xff);
}

function isDataProcessingImm(insn: ThumbInsn): boolean {
    return insn.size === 4 && (insn.hw1 & 0xf800) === 0xf000 && (insn.hw2 & 0x8000) === 0;
}

// ---- PC-relative literals ------------------------------------------------------------

export interface LiteralLoad { rt: number; address: number; }

/** `ldr Rt, [pc, #imm]`: T1 (16-bit, imm8*4) or T2 (`ldr.w`, ±imm12). Address = Align(PC+4, 4) ± imm. */
export function ldrLiteral(insn: ThumbInsn): LiteralLoad | null {
    const pc = align4(insn.address + 4);
    if (insn.size === 2 && (insn.hw1 & 0xf800) === 0x4800) {
        return { rt: (insn.hw1 >>> 8) & 7, address: pc + (insn.hw1 & 0xff) * 4 };
    }
    if (insn.size === 4 && (insn.hw1 & 0xff7f) === 0xf85f) {
        const imm = insn.hw2 & 0xfff;
        return { rt: insn.hw2 >>> 12, address: (insn.hw1 & 0x80) !== 0 ? pc + imm : pc - imm };
    }
    return null;
}

/** `add Rdn, pc` (16-bit T2): Rdn, else null. Rdn becomes Rdn + (address + 4). */
export function addPcRegister(insn: ThumbInsn): number | null {
    if (insn.size !== 2 || (insn.hw1 & 0xff78) !== 0x4478) return null;
    return (((insn.hw1 >>> 7) & 1) << 3) | (insn.hw1 & 7);
}

export interface MoveWide { rd: number; imm16: number; top: boolean; }

/** `movw Rd, #imm16` (top false) or `movt Rd, #imm16` (top true), else null. */
export function moveWide(insn: ThumbInsn): MoveWide | null {
    if (!isDataProcessingImm(insn)) return null;
    const masked = insn.hw1 & 0xfbf0;
    if (masked !== 0xf240 && masked !== 0xf2c0) return null;
    const imm16 = ((insn.hw1 & 0xf) << 12) | (((insn.hw1 >>> 10) & 1) << 11) |
        (((insn.hw2 >>> 12) & 7) << 8) | (insn.hw2 & 0xff);
    return { rd: (insn.hw2 >>> 8) & 0xf, imm16, top: masked === 0xf2c0 };
}

// ---- arithmetic and moves ---------------------------------------------------------------

export interface AddImmediate { rd: number; rn: number; imm: number; }

/** `add(s).w Rd, Rn, #const` (T3, ThumbExpandImm) or `addw Rd, Rn, #imm12` (T4), else null (`cmn` excluded). */
export function addImmediate(insn: ThumbInsn): AddImmediate | null {
    if (!isDataProcessingImm(insn)) return null;
    const rd = (insn.hw2 >>> 8) & 0xf;
    const rn = insn.hw1 & 0xf;
    const setsFlags = (insn.hw1 & 0x10) !== 0;
    if ((insn.hw1 & 0xfbe0) === 0xf100 && !(rd === PC && setsFlags)) return { rd, rn, imm: thumbExpandImm(imm12Of(insn)) };
    if ((insn.hw1 & 0xfbf0) === 0xf200) return { rd, rn, imm: imm12Of(insn) };
    return null;
}

export interface RegisterMove { rd: number; rm: number; }

/** `mov Rd, Rm` (16-bit T1), `movs Rd, Rm` (T2, lsls #0) or `mov.w Rd, Rm` (unshifted), else null. */
export function registerMove(insn: ThumbInsn): RegisterMove | null {
    const { hw1, hw2 } = insn;
    if (insn.size === 2 && (hw1 & 0xff00) === 0x4600) return { rd: (((hw1 >>> 7) & 1) << 3) | (hw1 & 7), rm: (hw1 >>> 3) & 0xf };
    if (insn.size === 2 && (hw1 & 0xffc0) === 0x0000) return { rd: hw1 & 7, rm: (hw1 >>> 3) & 7 };
    if (insn.size === 4 && (hw1 & 0xffef) === 0xea4f && (hw2 & 0x70f0) === 0) return { rd: (hw2 >>> 8) & 0xf, rm: hw2 & 0xf };
    return null;
}

// ---- branches ------------------------------------------------------------------------

export type BranchKind = "bl" | "blx" | "b" | "bcond" | "cbz";

export interface DirectBranch {
    kind: BranchKind;
    /** Target address; for `blx` an A32 (ARM-mode) address. */
    target: number;
}

/** S:I1:I2:imm10:imm11:0 of a 32-bit T4 branch / BL (I = NOT(J XOR S)). */
function branchImm25(hw1: number, hw2: number): number {
    const s = (hw1 >>> 10) & 1;
    const i1 = 1 ^ (((hw2 >>> 13) & 1) ^ s);
    const i2 = 1 ^ (((hw2 >>> 11) & 1) ^ s);
    const raw = (s << 24) | (i1 << 23) | (i2 << 22) | ((hw1 & 0x3ff) << 12) | ((hw2 & 0x7ff) << 1);
    return sext(raw, 25);
}

/** S:J2:J1:imm6:imm11:0 of a 32-bit T3 conditional branch. */
function branchImm21(hw1: number, hw2: number): number {
    const raw = (((hw1 >>> 10) & 1) << 20) | (((hw2 >>> 11) & 1) << 19) | (((hw2 >>> 13) & 1) << 18) |
        ((hw1 & 0x3f) << 12) | ((hw2 & 0x7ff) << 1);
    return sext(raw, 21);
}

function directBranch16(hw: number, pc: number): DirectBranch | null {
    if ((hw & 0xf000) === 0xd000 && ((hw >>> 8) & 0xf) < 0xe) return { kind: "bcond", target: pc + sext(hw & 0xff, 8) * 2 };
    if ((hw & 0xf800) === 0xe000) return { kind: "b", target: pc + sext(hw & 0x7ff, 11) * 2 };
    if ((hw & 0xf500) === 0xb100) return { kind: "cbz", target: pc + ((((hw >>> 9) & 1) << 6) | (((hw >>> 3) & 0x1f) << 1)) };
    return null;
}

/** Target of an immediate branch: b (T2/T4), b<cond> (T1/T3), cbz/cbnz, bl, blx (to A32); else null. */
export function directBranch(insn: ThumbInsn): DirectBranch | null {
    const pc = insn.address + 4;
    if (insn.size === 2) return directBranch16(insn.hw1, pc);
    const { hw1, hw2 } = insn;
    if ((hw1 & 0xf800) !== 0xf000 || (hw2 & 0x8000) === 0) return null;
    switch (hw2 & 0xd000) {
        case 0xd000: return { kind: "bl", target: pc + branchImm25(hw1, hw2) };
        case 0x9000: return { kind: "b", target: pc + branchImm25(hw1, hw2) };
        case 0xc000: return (hw2 & 1) === 0 ? { kind: "blx", target: align4(pc) + branchImm25(hw1, hw2) } : null;
        case 0x8000: return ((hw1 >>> 7) & 7) === 7 ? null : { kind: "bcond", target: pc + branchImm21(hw1, hw2) };
        default: return null;
    }
}

/** `blx Rm` / `bx Rm` (16-bit): the register-branch kind, else null. */
function registerBranch(insn: ThumbInsn): "blx" | "bx" | null {
    if (insn.size !== 2 || (insn.hw1 & 0xff07) !== 0x4700) return null;
    return (insn.hw1 & 0x80) !== 0 ? "blx" : "bx";
}

/** bl, blx (immediate or register): a call that clobbers CALL_CLOBBERED. */
export function isCall(insn: ThumbInsn): boolean {
    const kind = directBranch(insn)?.kind;
    return kind === "bl" || kind === "blx" || registerBranch(insn) === "blx";
}

/** Number of instructions an `IT` makes conditional (1..4), or 0 for anything else. */
export function itBlockLength(insn: ThumbInsn): number {
    if (insn.size !== 2 || (insn.hw1 & 0xff00) !== 0xbf00 || (insn.hw1 & 0xf) === 0) return 0;
    const mask = insn.hw1 & 0xf;
    let trailingZeros = 0;
    while (((mask >>> trailingZeros) & 1) === 0) trailingZeros++;
    return 4 - trailingZeros;
}

// ---- register writes ---------------------------------------------------------------------

function writes16Misc(hw: number): number {
    if ((hw & 0xff00) === 0xb000) return bit(SP);                         // add/sub sp, #imm
    if ((hw & 0xf500) === 0xb100) return 0;                               // cbz/cbnz
    if ((hw & 0xff00) === 0xb200 || (hw & 0xff00) === 0xba00) return bit(hw & 7); // sxt*/uxt*, rev*
    if ((hw & 0xfe00) === 0xb400) return bit(SP);                         // push
    if ((hw & 0xfe00) === 0xbc00) return (hw & 0xff) | ((hw & 0x100) !== 0 ? bit(PC) : 0) | bit(SP); // pop
    if ((hw & 0xff00) === 0xbf00 || (hw & 0xff00) === 0xbe00 || (hw & 0xffe0) === 0xb660) return 0; // IT/hints, bkpt, cps
    return ALL_REGISTERS;
}

function writes16DataOrSpecial(hw: number): number {
    if ((hw & 0xfc00) === 0x4000) {                                       // data processing (register)
        const op = (hw >>> 6) & 0xf;
        return op === 8 || op === 10 || op === 11 ? 0 : bit(hw & 7);      // tst/cmp/cmn write nothing
    }
    const op = (hw >>> 8) & 3;
    const rdn = (((hw >>> 7) & 1) << 3) | (hw & 7);
    if (op === 1) return 0;                                               // cmp (high regs)
    if (op === 3) return (hw & 0x80) !== 0 ? bit(LR) : 0;                 // blx / bx Rm
    return bit(rdn);                                                      // add / mov (high regs)
}

function writes16(hw: number): number {
    if ((hw & 0xf800) === 0x2800) return 0;                               // cmp Rn, #imm8
    if ((hw & 0xe000) === 0x2000) return bit((hw >>> 8) & 7);             // movs/adds/subs #imm8
    if ((hw & 0xe000) === 0x0000) return bit(hw & 7);                     // shifts, add/sub reg/imm3
    if ((hw & 0xf800) === 0x4000) return writes16DataOrSpecial(hw);
    if ((hw & 0xf800) === 0x4800) return bit((hw >>> 8) & 7);             // ldr literal
    if ((hw & 0xf000) === 0x5000) return ((hw >>> 9) & 7) <= 2 ? 0 : bit(hw & 7); // ld/st register offset
    if ((hw & 0xe000) === 0x6000 || (hw & 0xf000) === 0x8000) return (hw & 0x800) !== 0 ? bit(hw & 7) : 0;
    if ((hw & 0xf000) === 0x9000) return (hw & 0x800) !== 0 ? bit((hw >>> 8) & 7) : 0; // ldr/str sp-relative
    if ((hw & 0xf000) === 0xa000) return bit((hw >>> 8) & 7);             // adr, add Rd, sp, #imm
    if ((hw & 0xf000) === 0xb000) return writes16Misc(hw);
    if ((hw & 0xf000) === 0xc000) return bit((hw >>> 8) & 7) | ((hw & 0x800) !== 0 ? hw & 0xff : 0); // stm/ldm
    if ((hw & 0xff00) === 0xdf00) return bit(0);                          // svc returns in r0
    if ((hw & 0xf000) === 0xd000 || (hw & 0xf800) === 0xe000) return 0;   // b<cond>, udf, b
    return ALL_REGISTERS;
}

function writesLoadStoreMultipleOrDual(hw1: number, hw2: number): number {
    const rn = hw1 & 0xf;
    const writeback = (hw1 & 0x20) !== 0 ? bit(rn) : 0;
    const load = (hw1 & 0x10) !== 0;
    if ((hw1 & 0xfe40) === 0xe800) return writeback | (load ? hw2 : 0);   // ldm/stm/push.w/pop.w
    if ((hw1 & 0xfff0) === 0xe8d0 && (hw2 & 0xffe0) === 0xf000) return 0; // tbb/tbh
    if ((hw1 & 0x0120) !== 0) return writeback | (load ? bit(hw2 >>> 12) | bit((hw2 >>> 8) & 0xf) : 0); // ldrd/strd
    return bit(hw2 >>> 12) | bit((hw2 >>> 8) & 0xf) | bit(hw2 & 0xf);     // exclusives: over-approximate
}

function writesCoprocessor(hw1: number, hw2: number): number {
    const load = (hw1 & 0x10) !== 0;
    if ((hw1 & 0xef00) === 0xef00) return 0;                              // Advanced SIMD data processing
    if ((hw1 & 0xef00) === 0xee00) {                                      // mcr/mrc, vmov core<->s, vmrs, cdp
        const rt = hw2 >>> 12;
        return (hw2 & 0x10) !== 0 && load && rt !== PC ? bit(rt) : 0;
    }
    if ((hw1 & 0xefe0) === 0xec40) return load ? bit(hw2 >>> 12) | bit(hw1 & 0xf) : 0; // mcrr/mrrc
    return (hw1 & 0x20) !== 0 ? bit(hw1 & 0xf) : 0;                       // ldc/stc/vldm/vstm writeback
}

function writesLoadStoreSingle(hw1: number, hw2: number): number {
    const rn = hw1 & 0xf;
    if ((hw1 & 0xff10) === 0xf900) return (hw2 & 0xf) !== PC ? bit(rn) : 0; // SIMD element ld/st writeback
    const writeback = (hw1 & 0x80) === 0 && rn !== PC && (hw2 & 0x900) === 0x900 ? bit(rn) : 0;
    const load = (hw1 & 0x10) !== 0;
    const rt = hw2 >>> 12;
    const isHint = rt === PC && ((hw1 >>> 5) & 3) !== 2;                   // pld/pli (byte/halfword "loads" of pc)
    return writeback | (load && !isHint ? bit(rt) : 0);
}

function writes32(hw1: number, hw2: number): number {
    const rd = (hw2 >>> 8) & 0xf;
    if ((hw1 & 0xfe00) === 0xe800) return writesLoadStoreMultipleOrDual(hw1, hw2);
    if ((hw1 & 0xfe00) === 0xea00) return rd === PC && (hw1 & 0x10) !== 0 ? 0 : bit(rd); // shifted register
    if ((hw1 & 0xec00) === 0xec00) return writesCoprocessor(hw1, hw2);
    if ((hw1 & 0xf800) === 0xf000 && (hw2 & 0x8000) === 0) {             // data processing (immediate)
        const isTest = (hw1 & 0x200) === 0 && rd === PC && (hw1 & 0x10) !== 0;
        return isTest ? 0 : bit(rd);
    }
    if ((hw1 & 0xf800) === 0xf000) {                                      // branches, misc control
        if ((hw2 & 0xc000) === 0xc000) return bit(LR);                   // bl / blx
        return (hw1 & 0xffe0) === 0xf3e0 ? bit(rd) : 0;                  // mrs
    }
    if ((hw1 & 0xfe00) === 0xf800 || (hw1 & 0xff10) === 0xf900) return writesLoadStoreSingle(hw1, hw2);
    if ((hw1 & 0xff00) === 0xfa00) return bit(rd);                        // data processing (register)
    if ((hw1 & 0xff80) === 0xfb00) return bit(rd);                        // multiply
    if ((hw1 & 0xff80) === 0xfb80) return bit(rd) | bit(hw2 >>> 12);      // long multiply, divide
    return ALL_REGISTERS;
}

/**
 * Bit mask of the core registers `insn` may write (bit 15 = pc). Writeback
 * base registers count; a call's clobbers do NOT (see isCall / CALL_CLOBBERED).
 * Unmodelled encodings return ALL_REGISTERS.
 */
export function writtenRegisters(insn: ThumbInsn): number {
    return insn.size === 2 ? writes16(insn.hw1) : writes32(insn.hw1, insn.hw2);
}

/**
 * True when execution never falls through `insn` (outside an IT block): `b`,
 * `b.w`, `bx Rm`, `tbb/tbh`, `udf`, and any non-call write of pc
 * (`pop {…, pc}`, `ldr pc, …`, `mov pc, …`).
 */
export function endsFallThrough(insn: ThumbInsn): boolean {
    if (directBranch(insn)?.kind === "b" || registerBranch(insn) === "bx") return true;
    if (insn.size === 2 && (insn.hw1 & 0xff00) === 0xde00) return true;   // udf
    if (insn.size === 4 && (insn.hw1 & 0xfff0) === 0xe8d0 && (insn.hw2 & 0xffe0) === 0xf000) return true;
    return !isCall(insn) && (writtenRegisters(insn) & bit(PC)) !== 0;
}

// ---- function extent ----------------------------------------------------------------------

/** A non-call write of lr: the epilogue reload (`pop.w {…, lr}`, `ldr lr, …`) before a tail call. */
function restoresLinkRegister(insn: ThumbInsn): boolean {
    return !isCall(insn) && (writtenRegisters(insn) & bit(LR)) !== 0;
}

/**
 * End of the function starting at `base` (linear sweep, no unwind tables):
 * just after the first dead end (outside an IT block) that no earlier branch
 * jumps past. Branch targets count only inside `bytes`, and an unconditional
 * `b` right after an lr reload is a tail call, so neither extends the function.
 * Stops before the trailing literal pool.
 */
export function thumbFunctionEnd(bytes: Uint8Array, base: number): number {
    const limit = base + bytes.length;
    let furthestTarget = base;
    let conditional = 0;
    let previous: ThumbInsn | null = null;
    for (const insn of decodeThumb(bytes, base)) {
        const inIt = conditional > 0;
        conditional = inIt ? conditional - 1 : itBlockLength(insn);
        const branch = directBranch(insn);
        const tailCall = branch?.kind === "b" && previous !== null && restoresLinkRegister(previous);
        const intraFunction = branch !== null && branch.kind !== "bl" && branch.kind !== "blx" && !tailCall;
        if (intraFunction && branch!.target < limit) furthestTarget = Math.max(furthestTarget, branch!.target);
        const next = insn.address + insn.size;
        if (!inIt && endsFallThrough(insn) && next > furthestTarget) return next;
        previous = insn;
    }
    return limit;
}

// ---- PC-relative value tracking ------------------------------------------------------------

/** Reads the little-endian u32 at numeric address `addr`, or null when unreadable. */
export type WordReader32 = (addr: number) => number | null;

interface PendingValue { value: number; movwOnly: boolean; }

/**
 * Tracks registers loaded with a pc-relative offset (`ldr Rx, [pc, #i]` from a
 * literal pool, or `movw`[+`movt`]) and resolves them at `add Rx, pc`. Any
 * other write of Rx (or a call, for caller-saved registers) forgets it.
 */
export class PcRelativeTracker {
    private readonly pending = new Map<number, PendingValue>();

    constructor(private readonly readU32: WordReader32) {}

    /** Feed one instruction; returns the absolute address an `add Rx, pc` materialises, else null. */
    step(insn: ThumbInsn): number | null {
        const addPc = addPcRegister(insn);
        if (addPc !== null) {
            const value = this.pending.get(addPc);
            this.pending.delete(addPc);
            return value === undefined ? null : (value.value + insn.address + 4) >>> 0;
        }
        const wide = moveWide(insn);
        const before = wide === null ? undefined : this.pending.get(wide.rd);
        this.forgetWritten(insn);
        const literal = ldrLiteral(insn);
        if (literal !== null) {
            const word = this.readU32(literal.address);
            if (word !== null) this.pending.set(literal.rt, { value: word >>> 0, movwOnly: false });
        }
        if (wide !== null && !wide.top) this.pending.set(wide.rd, { value: wide.imm16, movwOnly: true });
        if (wide !== null && wide.top && before?.movwOnly) {
            this.pending.set(wide.rd, { value: ((wide.imm16 << 16) | (before.value & 0xffff)) >>> 0, movwOnly: false });
        }
        return null;
    }

    private forgetWritten(insn: ThumbInsn): void {
        const written = writtenRegisters(insn) | (isCall(insn) ? CALL_CLOBBERED : 0);
        for (const reg of [...this.pending.keys()]) if ((written & bit(reg)) !== 0) this.pending.delete(reg);
    }
}

/** Halfwords searched back from an `add Rx, pc` for the load that opens it. */
export const PCREL_WINDOW_HALFWORDS = 12;

function opensMaterialisationOf(insn: ThumbInsn | null, reg: number): boolean {
    if (insn === null) return false;
    return ldrLiteral(insn)?.rt === reg || moveWide(insn)?.rd === reg;
}

export interface PcRelativeRef {
    /** Address of the `ldr`/`movw` that opens the sequence. */
    loadAt: number;
    /** Address of the `add Rx, pc`. */
    addPcAt: number;
    /** The absolute address it materialises. */
    value: number;
}

/**
 * Every value an `add Rx, pc` at `addPcAt` can materialise: for each window
 * start up to PCREL_WINDOW_HALFWORDS back that opens a load of Rx AND decodes
 * forward to exactly `addPcAt` (instruction boundaries agree), the tracked
 * value. Several starts can decode (Thumb is variable length); callers match
 * the values against exact targets, so a garbage decode cannot fake one.
 */
export function pcRelativeRefsAt(bytes: Uint8Array, base: number, addPcAt: number, readU32: WordReader32,
                                 windowHalfwords: number = PCREL_WINDOW_HALFWORDS): PcRelativeRef[] {
    const addPc = thumbInsnAt(bytes, base, addPcAt - base);
    const reg = addPc === null ? null : addPcRegister(addPc);
    if (reg === null) return [];
    const refs: PcRelativeRef[] = [];
    for (let k = 1; k <= windowHalfwords; k++) {
        const start = addPcAt - 2 * k;
        if (start < base || !opensMaterialisationOf(thumbInsnAt(bytes, base, start - base), reg)) continue;
        const insns = decodeThumb(bytes, base, start, addPcAt + 2);
        const last = insns[insns.length - 1];
        if (last === undefined || last.address !== addPcAt) continue;
        const tracker = new PcRelativeTracker(readU32);
        let value: number | null = null;
        for (const insn of insns) value = tracker.step(insn);
        if (value !== null && !refs.some((r) => r.value === value)) refs.push({ loadAt: start, addPcAt, value });
    }
    return refs;
}

/** True when the halfword at byte index `at` is an `add Rx, pc`. */
export function isAddPcAt(bytes: Uint8Array, at: number): boolean {
    return at >= 0 && at + 2 <= bytes.length && (readU16(bytes, at) & 0xff78) === 0x4478;
}

/**
 * Pure scan of `bytes` (mapped at `base`): per target (index-aligned), the
 * pc-relative references that materialise exactly that address, ascending.
 */
export function findPcRelativeRefs(bytes: Uint8Array, base: number, targets: number[],
                                   readU32: WordReader32): PcRelativeRef[][] {
    const found: PcRelativeRef[][] = targets.map(() => []);
    for (let at = 0; at + 2 <= bytes.length; at += 2) {
        if (!isAddPcAt(bytes, at)) continue;
        for (const ref of pcRelativeRefsAt(bytes, base, base + at, readU32)) {
            targets.forEach((t, i) => { if (t === ref.value) found[i].push(ref); });
        }
    }
    return found;
}

// ---- calls ---------------------------------------------------------------------------------

/** Instructions walked after a label load before giving up on finding its call. */
const CALL_SEARCH_MAX_INSNS = 48;
/** Intra-function `b` hops followed while looking for the call. */
const CALL_SEARCH_MAX_HOPS = 4;

/**
 * First direct call reached by walking forward from `from` through `bytes`
 * (mapped at `base`), following the fall-through path: the target of the
 * first `bl`, or of an unconditional `b`/`b.w` taken after lr was restored
 * (an epilogue + tail call). An unconditional `b` before that is an
 * intra-function jump and is followed (inside `bytes` only). Returns null at
 * a return / indirect branch, at a `blx` (its target is A32 code, never the
 * Thumb function wanted here), or when the walk runs out.
 */
export function firstThumbCallTarget(bytes: Uint8Array, base: number, from: number): number | null {
    let at = from;
    let conditional = 0;
    let lrRestored = false;
    let hops = 0;
    for (let n = 0; n < CALL_SEARCH_MAX_INSNS; n++) {
        const insn = thumbInsnAt(bytes, base, at - base);
        if (insn === null) return null;
        const inIt = conditional > 0;
        conditional = inIt ? conditional - 1 : itBlockLength(insn);
        const branch = directBranch(insn);
        if (branch?.kind === "bl") return branch.target;
        if (branch?.kind === "blx" || registerBranch(insn) === "blx") return null;
        if (!inIt && branch?.kind === "b") {
            if (lrRestored) return branch.target;
            if (++hops > CALL_SEARCH_MAX_HOPS) return null;
            at = branch.target;
            continue;
        }
        if (!inIt && endsFallThrough(insn)) return null;
        if (restoresLinkRegister(insn)) lrRestored = true;
        at += insn.size;
    }
    return null;
}

/**
 * Direct Thumb call targets of the function in `bytes` (mapped at `base`,
 * already cut at its end), in order, deduplicated: every `bl` target plus every
 * unconditional `b`/`b.w` leaving the window (a tail call). `blx` targets are
 * A32 code (PLT stubs) and are skipped.
 */
export function thumbDirectCallTargets(bytes: Uint8Array, base: number): number[] {
    const end = base + bytes.length;
    const targets: number[] = [];
    for (const insn of decodeThumb(bytes, base)) {
        const branch = directBranch(insn);
        if (branch === null || (branch.kind !== "bl" && branch.kind !== "b")) continue;
        if (branch.kind === "b" && branch.target >= base && branch.target < end) continue;
        if (!targets.includes(branch.target)) targets.push(branch.target);
    }
    return targets;
}
