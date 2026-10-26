// agent/shared/x64_xref.ts
//
// x86-64 counterparts of the arm64_xref helpers used by the BoringSSL tier-4
// anchor locator: find the code sites that materialise a string's address and
// the first direct call after each one, plus a decoder for ssl_log_secret's
// ctx->keylog_callback prologue check.
//
// x86-64 code references rodata with RIP-relative LEAs
//     REX.W 8D /r  modrm(mod=00, rm=101)  disp32      ; lea reg, [rip+disp32]
// whose disp32 depends on the site, so (unlike arm64's ADRP/ADD) there is no
// fixed byte pattern to Memory.scan for. Instead each code chunk is copied once
// and walked as a typed array; that is a single linear pass and fast enough for
// a 200 MB libcef.dll in background chunks.
//
// The pure functions take a Uint8Array plus the virtual address of its first
// byte (as a JS number — user-space addresses stay below 2^53), so they are
// unit-testable under Node without Frida.

/** One RIP-relative LEA hitting a target: site address, target, dest register. */
export interface RipLeaRef {
    site: number;
    target: number;
    reg: number;
}

/**
 * Native Memory.scan prefix of `lea <arg1 register>, [rip+disp32]`: the label is
 * ssl_log_secret's second argument, so it is usually materialised straight into
 * rdx (Win64) or rsi (SysV). Scanning for this exact prefix touches ~1/10 as
 * many sites as walking every LEA.
 */
export const LEA_ARG1_PREFIX: { [abi: string]: string } = {
    win64: "48 8d 15",
    sysv: "48 8d 35",
};

/** Bytes after a LEA site searched for the call that consumes the string. */
export const CALL_SEARCH_WINDOW = 64;

/** Encoded length of `REX.W 8D modrm disp32`. */
const LEA_RIP_LEN = 7;

/**
 * Every `lea reg, [rip+disp32]` (REX.W, i.e. 48/4C prefix) in `code` whose
 * target is in `targets`. `codeVa` is the address of code[0]. Scans offsets
 * [0, scanEnd) only (default: the whole buffer), so chunked callers can let a
 * LEA that starts before the overlap tail be reported by exactly one chunk.
 */
export function findRipLeaRefs(
    code: Uint8Array,
    codeVa: number,
    targets: Set<number>,
    scanEnd: number = code.length,
): RipLeaRef[] {
    const out: RipLeaRef[] = [];
    const end = Math.min(scanEnd, code.length - LEA_RIP_LEN + 1);
    // Jump between 0x8D opcode bytes with the native indexOf instead of a
    // per-byte JS loop (~2% of code bytes; this is the hot loop on 200 MB).
    for (let k = code.indexOf(0x8d, 1); k !== -1 && k - 1 < end; k = code.indexOf(0x8d, k + 1)) {
        const i = k - 1;
        const rex = code[i];
        if (rex !== 0x48 && rex !== 0x4c) continue;
        const modrm = code[i + 2];
        if ((modrm & 0xc7) !== 0x05) continue; // mod=00, rm=101 => [rip+disp32]
        const disp = code[i + 3] | (code[i + 4] << 8) | (code[i + 5] << 16) | (code[i + 6] << 24);
        const site = codeVa + i;
        const target = site + LEA_RIP_LEN + disp;
        if (!targets.has(target)) continue;
        const reg = ((modrm >> 3) & 7) + (rex === 0x4c ? 8 : 0);
        out.push({ site, target, reg });
    }
    return out;
}

/**
 * Target of the first `call rel32` (E8) within `window` bytes after the LEA at
 * code offset `leaOff` whose target lies in [lo, hi). A heuristic byte search
 * (no full instruction decode): a stray E8 inside another instruction can hit,
 * which is why the locator only accepts a callee that >= 2 labels agree on.
 */
export function firstCallAfter(
    code: Uint8Array,
    codeVa: number,
    leaOff: number,
    lo: number,
    hi: number,
    window: number = CALL_SEARCH_WINDOW,
): number | null {
    const start = leaOff + LEA_RIP_LEN;
    const end = Math.min(start + window, code.length - 5);
    for (let j = start; j < end; j++) {
        if (code[j] !== 0xe8) continue;
        const rel = code[j + 1] | (code[j + 2] << 8) | (code[j + 3] << 16) | (code[j + 4] << 24);
        const callee = codeVa + j + 5 + rel;
        if (callee >= lo && callee < hi) return callee;
    }
    return null;
}

/** Register numbers (x86-64 encoding order). */
export const X64_REG = { rax: 0, rcx: 1, rdx: 2, rbx: 3, rsp: 4, rbp: 5, rsi: 6, rdi: 7 } as const;

// ssl->ctx sits early in SSL; keylog_callback deep in SSL_CTX. Observed:
// ctx 0x68, keylog_callback 0x1f0 (Chromium 120) / 0x238 (Chromium 156).
const MIN_FIELD_OFFSET = 0x8;
const MAX_CTX_OFFSET = 0x400;
const MAX_CB_OFFSET = 0x4000;

/** Decoded `[base + disp]` memory operand of a ModRM (no SIB, no RIP). */
interface MemOperand { reg: number; base: number; disp: number; len: number; }

/**
 * Decode `REX.W <op> modrm [disp8|disp32]` at code[i] where the ModRM is a
 * register-indirect memory operand with displacement. Returns the ModRM reg
 * field, base register, displacement and total encoded length; null if the
 * bytes do not have that shape (or use SIB / RIP-relative addressing).
 */
function decodeMemOperand(code: Uint8Array, i: number, opcode: number): MemOperand | null {
    if (i + 3 > code.length) return null;
    const rex = code[i];
    if ((rex & 0xf8) !== 0x48 || (rex & 0x02) !== 0) return null; // REX.W, no REX.X
    if (code[i + 1] !== opcode) return null;
    const modrm = code[i + 2];
    const mod = modrm >> 6;
    const rm = modrm & 7;
    if (mod === 0 || mod === 3 || rm === 4) return null; // need disp, no SIB
    const reg = ((modrm >> 3) & 7) + ((rex & 0x04) ? 8 : 0);
    const base = rm + ((rex & 0x01) ? 8 : 0);
    let disp: number;
    let len: number;
    if (mod === 1) {
        if (i + 4 > code.length) return null;
        disp = (code[i + 3] << 24) >> 24;
        len = 4;
    } else {
        if (i + 7 > code.length) return null;
        disp = code[i + 3] | (code[i + 4] << 8) | (code[i + 5] << 16) | (code[i + 6] << 24);
        len = 7;
    }
    return { reg, base, disp, len };
}

/** `mov dst, src` (REX.W 89/8B, register form) at code[i]: [dst, src, len]. */
function decodeMovRegReg(code: Uint8Array, i: number): [number, number, number] | null {
    if (i + 3 > code.length) return null;
    const rex = code[i];
    if ((rex & 0xf8) !== 0x48) return null;
    const op = code[i + 1];
    const modrm = code[i + 2];
    if (modrm >> 6 !== 3 || (op !== 0x89 && op !== 0x8b)) return null;
    const r = ((modrm >> 3) & 7) + ((rex & 0x04) ? 8 : 0);
    const m = (modrm & 7) + ((rex & 0x01) ? 8 : 0);
    return op === 0x89 ? [m, r, 3] : [r, m, 3];
}

/**
 * Decode the ssl->ctx and ctx->keylog_callback offsets from ssl_log_secret's
 * prologue bytes. Pure, so it is unit-testable without Frida.
 *
 * BoringSSL opens ssl_log_secret with an early return when no keylog callback
 * is set. clang-cl (libcef.dll, Chromium 120/156) emits, after the push /
 * stack-cookie preamble:
 *     mov  rax, [rcx+0x68]              ; ssl->ctx
 *     cmp  qword [rax+0x1f0], 0         ; ctx->keylog_callback
 *     jne  ...
 * and other compilers load-then-test:
 *     mov  rax, [rdi+0x68]
 *     mov  rax, [rax+0x250]
 *     test rax, rax
 *
 * `sslReg` is the register carrying the first argument (rcx on Win64, rdi on
 * SysV); simple `mov rX, sslReg` copies are followed. Bytes are matched at every
 * offset (no full decoder), so both offsets must be plausible and the second
 * access must use the register the first one loaded. Returns null otherwise —
 * a wrong answer would write a pointer into the wrong struct field.
 */
export function decodeX64CtxKeylogOffsets(
    code: Uint8Array,
    sslReg: number,
): { ctxOff: number; cbOff: number } | null {
    const sslRegs = new Set<number>([sslReg]);
    for (let i = 0; i + 3 <= code.length; i++) {
        const mv = decodeMovRegReg(code, i);
        if (mv !== null && sslRegs.has(mv[1])) sslRegs.add(mv[0]);

        const load = decodeMemOperand(code, i, 0x8b);
        if (load === null || !sslRegs.has(load.base)) continue;
        if (load.disp < MIN_FIELD_OFFSET || load.disp > MAX_CTX_OFFSET) continue;
        const ctxReg = load.reg;
        // Look for the keylog_callback access through ctxReg shortly after.
        const from = i + load.len;
        for (let j = from; j < Math.min(from + 24, code.length); j++) {
            // cmp qword [ctxReg+disp], imm8 0   (REX.W 83 /7 ib)
            const cmp = decodeMemOperand(code, j, 0x83);
            if (cmp !== null && cmp.reg % 8 === 7 && cmp.base === ctxReg &&
                j + cmp.len < code.length && code[j + cmp.len] === 0x00) {
                if (cmp.disp >= MIN_FIELD_OFFSET && cmp.disp <= MAX_CB_OFFSET) {
                    return { ctxOff: load.disp, cbOff: cmp.disp };
                }
            }
            // mov cbReg, [ctxReg+disp] ; test cbReg, cbReg   (REX.W 85 /r, mod=11)
            const ld2 = decodeMemOperand(code, j, 0x8b);
            if (ld2 !== null && ld2.base === ctxReg &&
                ld2.disp >= MIN_FIELD_OFFSET && ld2.disp <= MAX_CB_OFFSET) {
                const t = j + ld2.len;
                if (t + 3 <= code.length && (code[t] & 0xf8) === 0x48 && code[t + 1] === 0x85) {
                    const m = code[t + 2];
                    const rexT = code[t];
                    const r1 = ((m >> 3) & 7) + ((rexT & 0x04) ? 8 : 0);
                    const r2 = (m & 7) + ((rexT & 0x01) ? 8 : 0);
                    if (m >> 6 === 3 && r1 === ld2.reg && r2 === ld2.reg) {
                        return { ctxOff: load.disp, cbOff: ld2.disp };
                    }
                }
            }
        }
    }
    return null;
}
