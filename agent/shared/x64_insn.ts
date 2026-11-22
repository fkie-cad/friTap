// agent/shared/x64_insn.ts
//
// Minimal x86-64 (long mode) instruction decoder: enough to walk a function
// from its entry at real instruction boundaries (never a byte scan) and to
// expose what the NSS keylog-writer locator needs per instruction: length,
// ModRM memory operand (base / index / scale / disp, RIP-relative), immediate,
// rel8/rel32 branch target, and a CONSERVATIVE set of general-purpose registers
// the instruction may write.
//
// Covered: legacy prefixes, REX, the one-byte map, 0F / 0F38 / 0F3A maps, VEX
// (C4/C5) and EVEX (62) encodings (lengths; EVEX disp8 is length-only). Opcodes
// invalid in 64-bit mode decode to null, which callers treat as "stop".
//
// Pure (Uint8Array + numeric address), so it is unit-testable under Node.

/** Register numbers in encoding order (rax=0 .. r15=15). */
export const X64 = {
    rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7,
    r8: 8, r9: 9, r10: 10, r11: 11, r12: 12, r13: 13, r14: 14, r15: 15,
} as const;
/** Base "register" of a RIP-relative memory operand. */
export const RIP = -1;
/** SysV caller-saved GPRs a call may clobber. */
const SYSV_CALLER_SAVED = [0, 1, 2, 6, 7, 8, 9, 10, 11];
const ALL_GPRS = Array.from({ length: 16 }, (_v, i) => i);
const MAX_INSN_LEN = 15;

export interface X64MemOperand {
    /** Base register (0..15), RIP for RIP-relative, null when absent (SIB disp32 only). */
    base: number | null;
    index: number | null;
    scale: number;
    disp: number;
}

export interface X64Insn {
    addr: number;
    length: number;
    /** 0 = one-byte map, 1 = 0F, 2 = 0F38, 3 = 0F3A. */
    map: number;
    opcode: number;
    /** VEX / EVEX encoded. */
    vex: boolean;
    /** REX bits W=8 R=4 X=2 B=1 (VEX/EVEX: the decoded R/X/B, plus W). */
    rex: number;
    rexW: boolean;
    /** Mandatory/legacy prefixes seen (0x66, 0xF2, 0xF3; VEX pp mapped to these). */
    prefix66: boolean; prefixF2: boolean; prefixF3: boolean; prefix67: boolean;
    /** ModRM fields (reg/rm with REX extension), null when the opcode has none. */
    mod: number | null; reg: number | null; rm: number | null;
    /** Memory operand when mod != 3. */
    mem: X64MemOperand | null;
    /** VEX/EVEX vvvv register (0..15), else null. */
    vvvv: number | null;
    /** Signed immediate (the first one; imm64 is truncated to a JS number). */
    imm: number | null;
    /** Absolute target of a rel8/rel32 jump or call. */
    target: number | null;
}

// ---- opcode tables (one-byte map) ---------------------------------------------

const LEGACY_PREFIXES = new Set([0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67]);
/** One-byte opcodes that are invalid in 64-bit mode (0x62/0xC4/0xC5 are EVEX/VEX). */
const INVALID_1 = new Set([0x06, 0x07, 0x0e, 0x16, 0x17, 0x1e, 0x1f, 0x27, 0x2f, 0x37, 0x3f, 0x60, 0x61,
    0x82, 0x9a, 0xce, 0xd4, 0xd5, 0xd6, 0xea]);

function oneByteHasModrm(op: number): boolean {
    if (op < 0x40) return (op & 7) < 4;
    return [0x63, 0x69, 0x6b, 0xc0, 0xc1, 0xc6, 0xc7, 0xf6, 0xf7, 0xfe, 0xff].includes(op) ||
        (op >= 0x80 && op <= 0x8f) || (op >= 0xd0 && op <= 0xd3) || (op >= 0xd8 && op <= 0xdf);
}

/** Immediate size of a one-byte opcode ("z" = 2 with 0x66 else 4); `reg` for F6/F7 groups. */
function oneByteImmSize(op: number, opSize16: boolean, rexW: boolean, reg: number | null): number {
    const z = opSize16 && !rexW ? 2 : 4;
    if (op < 0x40) return (op & 7) === 4 ? 1 : (op & 7) === 5 ? z : 0;
    if ([0x6a, 0x6b, 0x80, 0x83, 0xa8, 0xc0, 0xc1, 0xc6, 0xcd, 0xe4, 0xe5, 0xe6, 0xe7].includes(op)) return 1;
    if ((op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3) || op === 0xeb) return 1;
    if (op >= 0xb0 && op <= 0xb7) return 1;
    if ([0x68, 0x69, 0x81, 0xa9, 0xc7].includes(op)) return z;
    if (op === 0xe8 || op === 0xe9) return 4;
    if (op >= 0xb8 && op <= 0xbf) return rexW ? 8 : z;
    if (op === 0xc2 || op === 0xca) return 2;
    if (op === 0xc8) return 3;
    if (op === 0xf6 && (reg! & 7) < 2) return 1;
    if (op === 0xf7 && (reg! & 7) < 2) return z;
    return 0;
}

// ---- opcode tables (0F maps) ----------------------------------------------------

const NO_MODRM_0F = new Set([0x05, 0x06, 0x07, 0x08, 0x09, 0x0b, 0x0e, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x37,
    0x77, 0xa0, 0xa1, 0xa2, 0xa8, 0xa9, 0xaa]);
const INVALID_0F = new Set([0x04, 0x0a, 0x0c, 0x24, 0x25, 0x26, 0x27, 0x36, 0x39, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]);
const IMM8_0F = new Set([0x0f, 0x70, 0x71, 0x72, 0x73, 0xa4, 0xac, 0xba, 0xc2, 0xc4, 0xc5, 0xc6]);

function twoByteHasModrm(op: number): boolean {
    if (NO_MODRM_0F.has(op)) return false;
    if (op >= 0x80 && op <= 0x8f) return false; // jcc rel32
    if (op >= 0xc8 && op <= 0xcf) return false; // bswap
    return true;
}

// ---- byte reader ----------------------------------------------------------------

class Cursor {
    constructor(readonly code: Uint8Array, public pos: number, readonly end: number) {}
    has(n: number): boolean { return this.pos + n <= this.end; }
    u8(): number { return this.code[this.pos++]; }
    signed(size: number): number {
        const c = this.code;
        const p = this.pos;
        this.pos += size;
        if (size === 1) return (c[p] << 24) >> 24;
        if (size === 2) return ((c[p] | (c[p + 1] << 8)) << 16) >> 16;
        const lo = c[p] | (c[p + 1] << 8) | (c[p + 2] << 16) | (c[p + 3] << 24);
        if (size === 4) return lo;
        const hi = c[p + 4] | (c[p + 5] << 8) | (c[p + 6] << 16) | (c[p + 7] << 24);
        return hi * 0x100000000 + (lo >>> 0);
    }
}

interface ModrmFields { mod: number; reg: number; rm: number; mem: X64MemOperand | null; }

/** ModRM (+SIB, +disp). `rex` bits: R=4, X=2, B=1. null on truncation. */
function readModrm(cur: Cursor, rex: number): ModrmFields | null {
    if (!cur.has(1)) return null;
    const modrm = cur.u8();
    const mod = modrm >> 6;
    const reg = ((modrm >> 3) & 7) | ((rex & 4) << 1);
    const rmLow = modrm & 7;
    if (mod === 3) return { mod, reg, rm: rmLow | ((rex & 1) << 3), mem: null };
    let base: number | null = rmLow | ((rex & 1) << 3);
    let index: number | null = null;
    let scale = 1;
    let dispSize = mod === 1 ? 1 : mod === 2 ? 4 : 0;
    if (rmLow === 4) {
        if (!cur.has(1)) return null;
        const sib = cur.u8();
        scale = 1 << (sib >> 6);
        const idx = ((sib >> 3) & 7) | ((rex & 2) << 2);
        index = idx === 4 ? null : idx;
        if ((sib & 7) === 5 && mod === 0) { base = null; dispSize = 4; }
        else base = (sib & 7) | ((rex & 1) << 3);
    } else if (rmLow === 5 && mod === 0) {
        base = RIP;
        dispSize = 4;
    }
    if (!cur.has(dispSize)) return null;
    const disp = dispSize === 0 ? 0 : cur.signed(dispSize);
    return { mod, reg, rm: rmLow | ((rex & 1) << 3), mem: { base, index, scale, disp } };
}

function blank(addr: number): X64Insn {
    return {
        addr, length: 0, map: 0, opcode: 0, vex: false, rex: 0, rexW: false,
        prefix66: false, prefixF2: false, prefixF3: false, prefix67: false,
        mod: null, reg: null, rm: null, mem: null, vvvv: null, imm: null, target: null,
    };
}

function applyModrm(insn: X64Insn, m: ModrmFields): void {
    insn.mod = m.mod; insn.reg = m.reg; insn.rm = m.rm; insn.mem = m.mem;
}

/** VEX (C4/C5) or EVEX (62) encoded instruction after its legacy prefixes; cur sits on the escape byte. */
function decodeVex(cur: Cursor, insn: X64Insn): boolean {
    const esc = cur.u8();
    let rex = 0;
    let map = 1;
    let pp = 0;
    if (esc === 0xc5) {
        if (!cur.has(1)) return false;
        const b1 = cur.u8();
        rex = (b1 & 0x80) ? 0 : 4;
        insn.vvvv = (~b1 >> 3) & 15;
        pp = b1 & 3;
    } else {
        const extra = esc === 0x62 ? 3 : 2;
        if (!cur.has(extra)) return false;
        const b1 = cur.u8();
        const b2 = cur.u8();
        rex = (~b1 >> 5) & 7;
        map = b1 & (esc === 0x62 ? 7 : 31);
        insn.rexW = (b2 & 0x80) !== 0;
        insn.vvvv = (~b2 >> 3) & 15;
        pp = b2 & 3;
        if (esc === 0x62) cur.u8(); // EVEX P2; disp8*N compression changes a value, not the length
    }
    if (map < 1 || map > 3 || !cur.has(1)) return false;
    insn.vex = true;
    insn.map = map;
    insn.prefix66 = pp === 1; insn.prefixF3 = pp === 2; insn.prefixF2 = pp === 3;
    insn.opcode = cur.u8();
    const m = readModrm(cur, rex);
    if (m === null) return false;
    applyModrm(insn, m);
    insn.rex = rex | (insn.rexW ? 8 : 0);
    const imm8 = map === 3 || (map === 1 && IMM8_0F.has(insn.opcode));
    if (imm8) {
        if (!cur.has(1)) return false;
        insn.imm = cur.signed(1);
    }
    return true;
}

/** Legacy-encoded instruction from the opcode byte on; cur sits on the opcode. */
function decodeLegacy(cur: Cursor, insn: X64Insn, rex: number): boolean {
    let op = cur.u8();
    if (op === 0x0f) {
        if (!cur.has(1)) return false;
        op = cur.u8();
        insn.map = 1;
        if (op === 0x38 || op === 0x3a) {
            if (!cur.has(1)) return false;
            insn.map = op === 0x38 ? 2 : 3;
            op = cur.u8();
        }
    }
    insn.opcode = op;
    if (insn.map === 0 && INVALID_1.has(op)) return false;
    if (insn.map === 1 && INVALID_0F.has(op)) return false;
    const hasModrm = insn.map === 0 ? oneByteHasModrm(op) : insn.map > 1 || twoByteHasModrm(op);
    if (hasModrm) {
        const m = readModrm(cur, rex);
        if (m === null) return false;
        applyModrm(insn, m);
    }
    let immSize: number;
    if (insn.map === 0) immSize = oneByteImmSize(op, insn.prefix66, insn.rexW, insn.reg);
    else if (insn.map === 1) immSize = (op >= 0x80 && op <= 0x8f) ? 4 : IMM8_0F.has(op) ? 1 : 0;
    else immSize = insn.map === 3 ? 1 : 0;
    if (insn.map === 0 && op >= 0xa0 && op <= 0xa3) immSize = insn.prefix67 ? 4 : 8; // moffs
    if (!cur.has(immSize)) return false;
    if (immSize > 0) insn.imm = cur.signed(immSize);
    if (op === 0xc8 && insn.map === 0) insn.imm = null; // enter: two immediates, value unused
    return true;
}

function setBranchTarget(insn: X64Insn): void {
    const end = insn.addr + insn.length;
    const op = insn.opcode;
    const rel = insn.map === 0 && ((op >= 0x70 && op <= 0x7f) || (op >= 0xe0 && op <= 0xe3) ||
        op === 0xe8 || op === 0xe9 || op === 0xeb);
    if (rel || (insn.map === 1 && op >= 0x80 && op <= 0x8f && !insn.vex)) insn.target = end + insn.imm!;
}

/**
 * Decode the instruction at code[offset] (address `base + offset`), reading no
 * byte at or past `limit` (default: the buffer end). null when the bytes are not
 * a valid 64-bit instruction or the instruction is truncated.
 */
export function decodeX64Insn(code: Uint8Array, offset: number, base: number,
                              limit: number = code.length): X64Insn | null {
    const end = Math.min(limit, code.length);
    const cur = new Cursor(code, offset, end);
    const insn = blank(base + offset);
    let rex = 0;
    while (cur.has(1) && cur.pos - offset < MAX_INSN_LEN) {
        const b = code[cur.pos];
        if (LEGACY_PREFIXES.has(b)) {
            if (b === 0x66) insn.prefix66 = true;
            if (b === 0xf2) insn.prefixF2 = true;
            if (b === 0xf3) insn.prefixF3 = true;
            if (b === 0x67) insn.prefix67 = true;
            rex = 0; // a REX followed by a legacy prefix is ignored
            cur.pos++;
        } else if ((b & 0xf0) === 0x40) {
            rex = b & 0x0f;
            cur.pos++;
        } else break;
    }
    insn.rexW = (rex & 8) !== 0;
    insn.rex = rex;
    if (!cur.has(1)) return null;
    const op = code[cur.pos];
    const isVexEscape = op === 0xc4 || op === 0xc5 || op === 0x62;
    if (isVexEscape && rex !== 0) return null;
    const ok = isVexEscape ? decodeVex(cur, insn) : decodeLegacy(cur, insn, rex);
    if (!ok) return null;
    insn.length = cur.pos - offset;
    if (insn.length > MAX_INSN_LEN) return null;
    setBranchTarget(insn);
    return insn;
}

/**
 * Every instruction from code[0] in order (linear sweep from a real instruction
 * start), stopping before the first undecodable or truncated one. `complete` is
 * false only when undecodable bytes start more than MAX_INSN_LEN - 1 bytes
 * before the end: a failure closer to the end may be an instruction the window
 * cut off, which is expected when a fixed-size window is decoded.
 */
export function sweepX64(code: Uint8Array, base: number): { insns: X64Insn[]; complete: boolean } {
    const insns: X64Insn[] = [];
    let off = 0;
    while (off < code.length) {
        const insn = decodeX64Insn(code, off, base);
        if (insn === null) return { insns, complete: code.length - off < MAX_INSN_LEN };
        insns.push(insn);
        off += insn.length;
    }
    return { insns, complete: true };
}

// ---- semantics -------------------------------------------------------------------

const isOneByte = (i: X64Insn, op: number) => !i.vex && i.map === 0 && i.opcode === op;
const group = (i: X64Insn) => (i.reg ?? 0) & 7;

/** Direct `call rel32`. */
export function isX64DirectCall(i: X64Insn): boolean { return isOneByte(i, 0xe8); }
/** Any call (direct, indirect, far). */
export function isX64Call(i: X64Insn): boolean {
    return isOneByte(i, 0xe8) || (isOneByte(i, 0xff) && (group(i) === 2 || group(i) === 3));
}
/** Direct `jmp rel32` / `jmp rel8`. */
export function isX64DirectJmp(i: X64Insn): boolean { return isOneByte(i, 0xe9) || isOneByte(i, 0xeb); }

/** The next instruction is not reached from this one (ret, jmp, trap, hlt). */
export function endsX64FallThrough(i: X64Insn): boolean {
    if (i.vex) return false;
    if (i.map === 1) return i.opcode === 0x0b; // ud2
    if (i.map !== 0) return false;
    if ([0xc2, 0xc3, 0xca, 0xcb, 0xcf, 0xe9, 0xeb, 0xcc, 0xf4].includes(i.opcode)) return true;
    return i.opcode === 0xff && (group(i) === 4 || group(i) === 5);
}

/** Conditional or unconditional jump (a basic-block boundary; calls are not). */
export function isX64Branch(i: X64Insn): boolean {
    return endsX64FallThrough(i) || (i.target !== null && !isX64DirectCall(i));
}

/** `mov r64, r64` (REX.W 89/8B, register form) as [dest, src], else null. */
export function x64RegMove(i: X64Insn): [number, number] | null {
    if (i.vex || i.map !== 0 || !i.rexW || i.mod !== 3) return null;
    if (i.opcode === 0x89) return [i.rm!, i.reg!];
    if (i.opcode === 0x8b) return [i.reg!, i.rm!];
    return null;
}

const rmIfReg = (i: X64Insn): number[] => (i.mod === 3 ? [i.rm!] : []);
/** Register encoded in the opcode's low 3 bits (push/pop/mov-imm/xchg/bswap), REX.B-extended. */
const opReg = (i: X64Insn): number => (i.opcode & 7) | ((i.rex & 1) << 3);

/** One-byte opcodes with ModRM: GPRs written (conservative: unknown -> reg + rm). */
function writesOneByteModrm(i: X64Insn): number[] {
    const op = i.opcode;
    const g = group(i);
    if (op < 0x40) {
        if (op >= 0x38) return []; // cmp
        return (op & 7) < 2 ? rmIfReg(i) : [i.reg!];
    }
    if (op === 0x84 || op === 0x85 || op === 0x8e) return [];
    if (op === 0x86 || op === 0x87) return [i.reg!, ...rmIfReg(i)];
    if ([0x63, 0x69, 0x6b, 0x8a, 0x8b, 0x8d].includes(op)) return [i.reg!];
    if (op >= 0x80 && op <= 0x83) return g === 7 ? [] : rmIfReg(i);
    if ([0x88, 0x89, 0x8c, 0x8f, 0xc0, 0xc1, 0xc6, 0xc7, 0xd0, 0xd1, 0xd2, 0xd3].includes(op)) return rmIfReg(i);
    if (op === 0xf6 || op === 0xf7) return g < 2 ? [] : g < 4 ? rmIfReg(i) : [X64.rax, X64.rdx];
    if (op === 0xfe || op === 0xff) {
        if (g < 2) return rmIfReg(i);
        return g === 2 || g === 3 ? SYSV_CALLER_SAVED : [];
    }
    if (op >= 0xd8 && op <= 0xdf) return op === 0xdf && i.mod === 3 ? [X64.rax] : []; // x87 (fnstsw ax)
    return [i.reg!, ...rmIfReg(i)];
}

/** One-byte opcodes without ModRM. */
function writesOneByteNoModrm(i: X64Insn): number[] {
    const op = i.opcode;
    if (op < 0x40) return op >= 0x38 ? [] : [X64.rax];
    if (op >= 0x50 && op <= 0x57) return [];
    if ((op >= 0x58 && op <= 0x5f) || (op >= 0xb0 && op <= 0xbf)) return [opReg(i)];
    if (op >= 0x90 && op <= 0x97) return opReg(i) === X64.rax ? [] : [X64.rax, opReg(i)];
    if (op === 0x98 || op === 0x9f || op === 0xa0 || op === 0xa1 || op === 0xd7) return [X64.rax];
    if (op === 0x99) return [X64.rdx];
    if (op >= 0xa4 && op <= 0xaf) return op === 0xa8 || op === 0xa9 ? [] : [X64.rax, X64.rcx, X64.rsi, X64.rdi];
    if (op === 0xc8 || op === 0xc9) return [X64.rbp];
    if (op >= 0xe0 && op <= 0xe3) return [X64.rcx];
    if (op >= 0xe4 && op <= 0xef && op !== 0xe8 && op !== 0xe9 && op !== 0xeb) return [X64.rax];
    if (op === 0xe8) return SYSV_CALLER_SAVED;
    if ([0x68, 0x6a, 0x9b, 0x9c, 0x9d, 0x9e, 0xa2, 0xa3, 0xc2, 0xc3, 0xca, 0xcb, 0xcc, 0xe9, 0xeb, 0xf1, 0xf4, 0xf5,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd].includes(op) || (op >= 0x70 && op <= 0x7f)) return [];
    return ALL_GPRS;
}

/** 0F-map instructions (legacy encoded). SSE ops write XMM, except the GPR-destination ones listed. */
function writes0F(i: X64Insn): number[] {
    const op = i.opcode;
    if (op === 0x05) return [X64.rax, X64.rcx, X64.r11];
    if (op === 0x31) return [X64.rax, X64.rdx];
    if (op === 0xa2) return [X64.rax, X64.rbx, X64.rcx, X64.rdx];
    if (op === 0x1e && i.prefixF3 && group(i) === 1) return rmIfReg(i); // rdssp
    // ud2, prefetch, hint nops incl. endbr64 (F3 0F 1E FA), emms, jcc
    if (op === 0x0b || op === 0x0d || (op >= 0x18 && op <= 0x1f) || op === 0x77 || (op >= 0x80 && op <= 0x8f)) return [];
    if ((op >= 0x40 && op <= 0x4f) || [0x2c, 0x2d, 0x50, 0xaf, 0xb6, 0xb7, 0xb8, 0xbc, 0xbd, 0xbe, 0xbf, 0xc5, 0xd7].includes(op)) {
        return [i.reg!];
    }
    if ((op >= 0x90 && op <= 0x9f) || [0xa4, 0xa5, 0xab, 0xac, 0xad, 0xb3, 0xbb, 0xae].includes(op)) return rmIfReg(i);
    if (op === 0x7e) return i.prefixF3 ? [] : rmIfReg(i); // movd/movq r/m, xmm
    if (op === 0xa3) return [];
    if (op === 0xba) return group(i) === 4 ? [] : rmIfReg(i);
    if (op === 0xb0 || op === 0xb1) return [X64.rax, ...rmIfReg(i)];
    if (op === 0xc0 || op === 0xc1) return [i.reg!, ...rmIfReg(i)];
    if (op >= 0xc8 && op <= 0xcf) return [opReg(i)];
    const sse = (op >= 0x10 && op <= 0x17) || (op >= 0x28 && op <= 0x2f) || (op >= 0x51 && op <= 0x7f) ||
        (op >= 0xc2 && op <= 0xc6) || op >= 0xd0;
    return sse ? [] : ALL_GPRS;
}

/** 0F38 / 0F3A (legacy or VEX) and VEX 0F: vector ops write XMM, except these GPR-destination ones. */
function writesVectorMaps(i: X64Insn): number[] {
    const op = i.opcode;
    if (i.map === 2 && op >= 0xf0 && op <= 0xf7) return [i.reg!, ...(i.vvvv !== null ? [i.vvvv] : []), ...rmIfReg(i)];
    if (i.map === 3 && op === 0xf0) return [i.reg!];
    if (i.map === 3 && op >= 0x14 && op <= 0x17) return rmIfReg(i);
    if (i.map === 1 && [0x2c, 0x2d, 0x50, 0xc5, 0xd7].includes(op)) return [i.reg!];
    if (i.map === 1 && op === 0x7e) return i.prefixF3 ? [] : rmIfReg(i);
    return [];
}

/**
 * General-purpose registers (0..15) this instruction may write. Conservative:
 * an instruction whose effect is not modelled reports every register. A call
 * reports the SysV caller-saved set.
 */
export function x64RegsWritten(i: X64Insn): number[] {
    if (i.vex || i.map >= 2) return writesVectorMaps(i);
    if (i.map === 1) return writes0F(i);
    return i.mod !== null ? writesOneByteModrm(i) : writesOneByteNoModrm(i);
}
