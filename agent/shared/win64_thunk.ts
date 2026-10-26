// agent/shared/win64_thunk.ts
//
// Win64 -> System V call thunk, so Win64 code (a PE module under Wine) can call
// a Frida NativeCallback created by Linux-host Frida.
//
// Frida's Linux build has no "win64" NativeCallback ABI ("invalid abi
// specified"), but planting a callback that PE code calls — e.g. BoringSSL's
// ctx->keylog_callback in libcef.dll under Wine — needs exactly that. The thunk
// adapts the convention:
//   * moves the integer arguments rcx, rdx, r8, r9 -> rdi, rsi, rdx, rcx;
//   * preserves what Win64 treats as callee-saved but System V does not:
//     rdi, rsi and xmm6..xmm15 (the JS callback freely clobbers the latter);
//   * keeps rsp 16-byte aligned at the inner call.
// Return values pass through rax unchanged.

const XMM_SAVE_BYTES = 10 * 16;
// 8 more so that entry (rsp = 8 mod 16) + two pushes + this = 0 mod 16.
const FRAME_BYTES = XMM_SAVE_BYTES + 8;

function u32le(v: number): number[] {
    return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
}

/** `movdqu [rsp+off], xmmN` (store) or `movdqu xmmN, [rsp+off]` (load), disp32. */
function movdquRsp(n: number, off: number, store: boolean): number[] {
    const modrm = 0x84 | ((n & 7) << 3); // mod=10 (disp32), rm=100 (SIB)
    const rex = n >= 8 ? [0x44] : [];    // REX.R for xmm8..15
    return [0xf3, ...rex, 0x0f, store ? 0x7f : 0x6f, modrm, 0x24, ...u32le(off)];
}

/**
 * Machine code of the thunk calling `target` (64-bit address as a hex string,
 * e.g. "0x7f00deadbeef") with `nargs` (0..4) integer arguments. Pure, so it is
 * unit-testable without Frida.
 */
export function win64ToSysvThunkBytes(target: string, nargs: number): number[] {
    if (nargs < 0 || nargs > 4) throw new Error(`win64 thunk supports 0..4 args, got ${nargs}`);
    const out: number[] = [];
    out.push(0x57, 0x56);                                    // push rdi ; push rsi
    out.push(0x48, 0x81, 0xec, ...u32le(FRAME_BYTES));       // sub rsp, FRAME
    for (let n = 6; n <= 15; n++) out.push(...movdquRsp(n, (n - 6) * 16, true));
    // Argument moves, ordered so no source is overwritten before it is read.
    if (nargs > 0) out.push(0x48, 0x89, 0xcf);               // mov rdi, rcx
    if (nargs > 1) out.push(0x48, 0x89, 0xd6);               // mov rsi, rdx
    if (nargs > 2) out.push(0x4c, 0x89, 0xc2);               // mov rdx, r8
    if (nargs > 3) out.push(0x4c, 0x89, 0xc9);               // mov rcx, r9
    let t = BigInt(target);
    const imm: number[] = [];
    for (let i = 0; i < 8; i++) { imm.push(Number(t & 0xffn)); t >>= 8n; }
    out.push(0x48, 0xb8, ...imm);                            // mov rax, target
    out.push(0xff, 0xd0);                                    // call rax
    for (let n = 6; n <= 15; n++) out.push(...movdquRsp(n, (n - 6) * 16, false));
    out.push(0x48, 0x81, 0xc4, ...u32le(FRAME_BYTES));       // add rsp, FRAME
    out.push(0x5e, 0x5f, 0xc3);                              // pop rsi ; pop rdi ; ret
    return out;
}

// The thunks are called by native code for the life of the process: root them.
const rootedThunks: NativePointer[] = [];

/**
 * Executable Win64-callable entry point that forwards to the System V function
 * `target` (typically a NativeCallback). x64 only.
 */
export function makeWin64ToSysvThunk(target: NativePointer, nargs: number): NativePointer {
    const bytes = win64ToSysvThunkBytes(target.toString(), nargs);
    const mem = Memory.alloc(Process.pageSize);
    Memory.patchCode(mem, bytes.length, (code) => {
        code.writeByteArray(bytes);
    });
    rootedThunks.push(mem);
    return mem;
}
