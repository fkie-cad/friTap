// agent/shared/call_abi.ts
//
// Calling-convention-aware argument reading for hooks on code whose ABI is not
// necessarily the host's.
//
// Frida's `args[]` follows the ABI of the HOST process: System V on a Linux
// host, Win64 on Windows, AAPCS64 on arm64. That is wrong for PE code running
// under Wine — friTap injects Linux-host Frida, so `args[0]` reads rdi while the
// Win64 callee received its first argument in rcx. Hooks that may land in PE
// code therefore read registers from `this.context` under an explicit ABI.
//
// bssl::ssl_log_secret(const SSL*, const char* label, Span<const uint8_t>) adds
// a second ABI difference: the 16-byte Span is split across two registers on
// System V / AAPCS64 (data, size), but Win64 passes any aggregate larger than
// 8 bytes BY REFERENCE, so the third argument is a pointer to {data, size}.
// Confirmed on CEF/libcef.dll (Chromium 120 and 156): `mov rdi, r8` followed by
// `mov rax, [rdi+8]` reads the length.

export type CallAbi = "sysv" | "win64" | "aarch64";

// Explicit per-module ABI overrides (e.g. PE modules under Wine), keyed by
// lower-cased module name.
const moduleAbi = new Map<string, CallAbi>();

/** Pin `moduleName`'s hooks to `abi` (used for PE modules under Wine). */
export function setModuleCallAbi(moduleName: string, abi: CallAbi): void {
    moduleAbi.set(moduleName.toLowerCase(), abi);
}

/** The process's native ABI, or null where register reading is not modelled
 *  (ia32 / arm32 pass on the stack; those keep using Frida's args[]). */
export function hostCallAbi(): CallAbi | null {
    if (Process.arch === "arm64") return "aarch64";
    if (Process.arch === "x64") return Process.platform === "windows" ? "win64" : "sysv";
    return null;
}

/** The ABI to read `moduleName`'s hook arguments with: an explicit override,
 *  else the host ABI (null = fall back to Frida's args[]). */
export function callAbiForModule(moduleName: string): CallAbi | null {
    return moduleAbi.get(moduleName.toLowerCase()) ?? hostCallAbi();
}

/** Integer/pointer argument `idx` of the call at `ctx` under `abi`. */
export function argAt(ctx: CpuContext, abi: CallAbi, idx: number): NativePointer {
    if (abi === "aarch64") {
        const c = ctx as Arm64CpuContext;
        if (idx < 8) return [c.x0, c.x1, c.x2, c.x3, c.x4, c.x5, c.x6, c.x7][idx];
        return c.sp.add((idx - 8) * 8).readPointer();
    } else if (abi === "win64") {
        const c = ctx as X64CpuContext;
        // args 0..3 in registers; later ones are stack slots past the 32-byte
        // shadow space (at function entry, [rsp] is the return address).
        if (idx < 4) return [c.rcx, c.rdx, c.r8, c.r9][idx];
        return c.rsp.add(0x28 + (idx - 4) * 8).readPointer();
    } else {
        const c = ctx as X64CpuContext;
        if (idx < 6) return [c.rdi, c.rsi, c.rdx, c.rcx, c.r8, c.r9][idx];
        return c.rsp.add(8 + (idx - 6) * 8).readPointer();
    }
}

/** Decoded arguments of one bssl::ssl_log_secret call. */
export interface SslLogSecretCall {
    ssl: NativePointer;
    label: NativePointer;
    data: NativePointer;
    len: number;
}

/** Largest plausible TLS secret (SHA-384 = 48; leave headroom for forks). */
export const MAX_SECRET_LEN = 64;

/**
 * Pick the Win64 secret encoding. Pure (numbers only) so it is unit-testable:
 * `spanSize` is the u64 at [arg2+8] (null if unreadable). Span-by-reference is
 * the real ABI; the scalar form (data=arg2, size=arg3) only appears when LTO
 * argument promotion split the Span. Under by-reference, [arg2+8] is the size;
 * under the scalar form it is secret bytes, which essentially never decode to a
 * value in 1..64.
 */
export function win64SpanIsByReference(spanSize: number | null): boolean {
    return spanSize !== null && spanSize > 0 && spanSize <= MAX_SECRET_LEN;
}

/**
 * Read bssl::ssl_log_secret(ssl, label, Span<const uint8_t>) arguments.
 * `abi === null` keeps the historical Frida args[] reading (ssl, label, data,
 * size) used on every non-x64/arm64 target.
 */
export function readSslLogSecretCall(
    args: InvocationArguments,
    ctx: CpuContext,
    abi: CallAbi | null,
): SslLogSecretCall {
    if (abi === null) {
        return { ssl: args[0], label: args[1], data: args[2], len: args[3].toUInt32() };
    }
    const ssl = argAt(ctx, abi, 0);
    const label = argAt(ctx, abi, 1);
    const a2 = argAt(ctx, abi, 2);
    if (abi !== "win64") {
        return { ssl, label, data: a2, len: argAt(ctx, abi, 3).toUInt32() };
    }
    let spanSize: number | null = null;
    try {
        spanSize = a2.add(8).readU64().toNumber();
    } catch (_e) { /* unreadable: not a Span pointer */ }
    if (win64SpanIsByReference(spanSize)) {
        return { ssl, label, data: a2.readPointer(), len: spanSize as number };
    }
    return { ssl, label, data: a2, len: argAt(ctx, abi, 3).toUInt32() };
}
