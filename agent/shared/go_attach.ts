// agent/shared/go_attach.ts
//
// Attaching an onEnter-only hook to a Go function (on arm64: after its stack-guard check).
//
// Every stack-checked Go function on arm64 opens with the goroutine stack-guard check
//     ldr x16, [x28, #0x10]      ; g.stackguard0 (x28 = g)
//     [sub x17, sp, #frame]      ; larger frames
//     cmp sp|x17, x16
//     b.ls morestack             ; (huge frames add a b.lo overflow check)
// which uses BOTH of AArch64's intra-procedure scratch registers. When Frida cannot place
// its trampoline within B range it needs x16/x17 for the far branch, and attaching at the
// entry fails ("unable to intercept function ... please file a bug") — seen on Go 1.21
// binaries on Linux/arm64 and macOS/arm64 for writeKeyLog and writeRecordLocked. Right
// after the first conditional branch the argument registers, sp and lr are still untouched
// (the check only reads g/sp and writes x16/x17 and the flags), so an onEnter hook placed
// there sees exactly the entry state. Such functions are therefore ALWAYS hooked there (one
// deterministic hook site, independent of where Frida can place its trampoline). The
// morestack path re-enters at the function entry, never inside the patched bytes, so the
// hook fires once per call (an entry hook would fire again after a stack growth). Only
// onEnter hooks may use this: an onLeave/return hook needs the true entry. x64 entries
// (cmp rsp, [r14+0x10]; jbe) need no scratch register and are hooked at the entry.
//
// Goroutine stack headroom (arm64). A Frida JS onEnter runs on the hooked thread's stack —
// here the goroutine's own small stack — and needs ~6 KiB of it (measured: 5.8 KiB for a
// trivial callback on macOS/arm64), while Go guarantees only StackGuard (928 B) plus the
// function's frame below sp after the check. The callback then writes below the goroutine
// stack into whatever lies there (another goroutine's stack), and the process dies later with
// "unexpected return pc" / SIGBUS — seen on darwin/arm64 Go 1.24/1.25 at writeRecordLocked
// (9/10 runs with -p). Where the check reads `sub x17, sp, #frame` (every function with a
// frame beyond the small-frame limit, e.g. writeKeyLog, writeRecordLocked) its immediate is
// widened in place by GO_HOOK_STACK_HEADROOM: Go itself then grows the goroutine stack
// (morestack doubles it until the check passes) before our onEnter can run, so the callback
// always has that much stack. Small-frame checks (`cmp sp, x16`, e.g. (*Conn).Read) have no
// immediate to widen and keep the bare 928 B guarantee.

import { devlog } from "../util/log.js";

/** Instructions a stack-guard check may span before its first conditional branch. */
const MAX_STACK_CHECK_INSTRUCTIONS = 6;

/** The encoding of the g.stackguard0 load that opens a Go arm64 function: ldr x16, [x28, #0x10] (MOVD 16(R28), R16). */
const STACK_GUARD_LOAD_WORD = 0xf9400b90;

/** Whether the 32-bit instruction word is the stack-guard load that opens a Go arm64 function. */
export function isGoArm64StackGuardLoad(insn: number): boolean {
    return (insn >>> 0) === STACK_GUARD_LOAD_WORD;
}

/** Goroutine stack a hooked Go arm64 function demands beyond its frame (see the file comment). */
export const GO_HOOK_STACK_HEADROOM = 16 * 1024;

/** SUB (immediate, 64-bit) with Rn = sp, Rd = x17: 0xd1000000 | sh<<22 | imm12<<10 | 31<<5 | 17. */
const SUB_X17_SP_IMM_MASK = 0xff8003ff;
const SUB_X17_SP_IMM_BITS = 0xd10003f1;

/** The byte immediate of `sub x17, sp, #imm{, lsl #12}`, or null for any other instruction word. */
export function decodeSubX17SpImm(insn: number): number | null {
    const word = insn >>> 0;
    if (((word & SUB_X17_SP_IMM_MASK) >>> 0) !== SUB_X17_SP_IMM_BITS) return null;
    const imm12 = (word >>> 10) & 0xfff;
    return (word >>> 22) & 1 ? imm12 * 4096 : imm12;
}

/**
 * `sub x17, sp, #imm` widened by `headroom` bytes: encoded as imm12, lsl #12 (rounded up to
 * 4 KiB, so never less than asked), or null when `insn` is not that instruction or the
 * result does not fit.
 */
export function widenGoArm64StackCheck(insn: number, headroom: number = GO_HOOK_STACK_HEADROOM): number | null {
    const frame = decodeSubX17SpImm(insn);
    if (frame === null) return null;
    const pages = Math.ceil((frame + headroom) / 4096);
    if (pages > 0xfff) return null;
    return (SUB_X17_SP_IMM_BITS | (1 << 22) | (pages << 10)) >>> 0;
}

/** Functions whose stack check was already widened (patch once). */
const widenedStackChecks = new Set<string>();

/**
 * Widen the stack check of the Go arm64 function at `fn` (its `sub x17, sp, #frame` right after
 * the stack-guard load) by GO_HOOK_STACK_HEADROOM. Returns whether the check now demands the
 * headroom; false for small-frame checks, which have no immediate to widen.
 */
export function ensureGoArm64StackHeadroom(fn: NativePointer): boolean {
    const key = fn.toString();
    if (widenedStackChecks.has(key)) return true;
    const site = fn.add(4);
    const widened = widenGoArm64StackCheck(site.readU32());
    if (widened === null) return false;
    Memory.patchCode(site, 4, (code) => code.writeU32(widened));
    widenedStackChecks.add(key);
    devlog(`[go] ${fn}: stack check widened by ${GO_HOOK_STACK_HEADROOM} bytes for the hook`);
    return true;
}

/** Only these may run before the branch: they write x16/x17 or the flags, never arguments. */
function isStackCheckInstruction(instruction: Instruction): boolean {
    const { mnemonic, opStr } = instruction;
    if (mnemonic === "cmp") return true;
    return ["sub", "subs", "mov", "movz", "movk", "add"].includes(mnemonic) && /^x1[67],/.test(opStr);
}

/**
 * The address right after the stack-guard check of the Go arm64 function at `fn` (the
 * instruction following its first conditional branch), or null when `fn` does not open
 * with the Go stack-guard sequence.
 */
export function goArm64StackCheckEnd(fn: NativePointer): NativePointer | null {
    if (!opensWithGoStackGuardLoad(fn)) return null;
    let cursor = fn.add(4);
    for (let i = 1; i < MAX_STACK_CHECK_INSTRUCTIONS; i++) {
        let instruction: Instruction;
        try {
            instruction = Instruction.parse(cursor);
        } catch (e) {
            return null;
        }
        if (instruction.mnemonic.startsWith("b.")) return instruction.next;
        if (!isStackCheckInstruction(instruction)) return null;
        cursor = instruction.next;
    }
    return null;
}

/** Whether the code at `fn` starts with the Go arm64 stack-guard load (false when unreadable). */
function opensWithGoStackGuardLoad(fn: NativePointer): boolean {
    try {
        return isGoArm64StackGuardLoad(fn.readU32());
    } catch (e) {
        return false;
    }
}

/**
 * Interceptor.attach of an onEnter-only hook on the function at `address`: on arm64, a Go
 * function with the stack-guard prologue is hooked right after its check (see the file
 * comment); anything else — other architectures, non-Go code — at `address` itself.
 */
export function attachGoFunctionEntry(address: NativePointer, callbacks: { onEnter: (this: InvocationContext, args: InvocationArguments) => void },
                                      arch: string = Process.arch): InvocationListener {
    const afterCheck = arch === "arm64" ? goArm64StackCheckEnd(address) : null;
    if (afterCheck === null) return Interceptor.attach(address, callbacks);
    try {
        if (!ensureGoArm64StackHeadroom(address)) devlog(`[go] ${address}: small-frame stack check; no extra headroom for the hook`);
    } catch (e) {
        devlog(`[go] ${address}: could not widen the stack check (${e}); hooking without extra headroom`);
    }
    devlog(`[go] ${address}: hooking after its stack check at ${afterCheck}`);
    return Interceptor.attach(afterCheck, callbacks);
}
