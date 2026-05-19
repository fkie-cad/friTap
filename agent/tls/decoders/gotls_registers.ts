// agent/tls/decoders/gotls_registers.ts
//
// Go ABIInternal register-based extraction of writeKeyLog arguments.
// Go's calling convention passes scalar args in CPU registers, not the
// System V slots Frida exposes via args[]. The mapping is stable for
// crypto/tls.(*Config).writeKeyLog across Go 1.17+ (when ABIInternal
// became the default) and matches the layout the legacy GoTlsLogger used.

import { toHexString } from "../../shared/shared_functions.js";

/**
 * Bounds check: positive, non-zero, and below 1024 bytes — the largest
 * plausible keylog field is a 64-byte secret. Anything bigger almost
 * certainly means we read garbage from a non-Go-ABI frame.
 */
function isPlausibleLen(len: number): boolean {
    return len > 0 && len < 1024;
}

interface KeylogParts {
    labelPtr: NativePointer;
    labelLen: number;
    crPtr: NativePointer;
    crLen: number;
    secretPtr: NativePointer;
    secretLen: number;
}

/**
 * x64: Go ABIInternal places writeKeyLog params in
 *   RBX = label, RCX = labelLen, RDI = clientRandom, RSI = crLen,
 *   R9  = secret, R10 = secretLen.
 */
function readPartsX64(ctx: X64CpuContext): KeylogParts {
    return {
        labelPtr: ctx.rbx,
        labelLen: ctx.rcx.toInt32(),
        crPtr: ctx.rdi,
        crLen: ctx.rsi.toInt32(),
        secretPtr: ctx.r9,
        secretLen: ctx.r10.toInt32(),
    };
}

/**
 * ARM64: Go ABIInternal places writeKeyLog params in
 *   X1 = label, X2 = labelLen, X3 = clientRandom, X4 = crLen,
 *   X5 = secret, X6 = secretLen.
 */
function readPartsArm64(ctx: Arm64CpuContext): KeylogParts {
    return {
        labelPtr: ctx.x1,
        labelLen: ctx.x2.toInt32(),
        crPtr: ctx.x3,
        crLen: ctx.x4.toInt32(),
        secretPtr: ctx.x5,
        secretLen: ctx.x6.toInt32(),
    };
}

/**
 * Validate that every pointer is non-null and every length is plausible.
 * Returns false (and the caller bails) when anything looks suspect.
 */
function partsAreValid(p: KeylogParts): boolean {
    if (p.labelPtr.isNull() || !isPlausibleLen(p.labelLen)) return false;
    if (p.crPtr.isNull() || !isPlausibleLen(p.crLen)) return false;
    if (p.secretPtr.isNull() || !isPlausibleLen(p.secretLen)) return false;
    return true;
}

/**
 * Extract a single SSLKEYLOGFILE line ("LABEL CR_HEX SECRET_HEX") from
 * the Go ABIInternal registers in `ctx`. Returns null when the
 * architecture is unsupported, any pointer is null, any length is
 * implausible, or memory reads throw.
 */
export function extractKeylogFromRegisters(ctx: CpuContext): string | null {
    let parts: KeylogParts;
    if (Process.arch === "x64") {
        parts = readPartsX64(ctx as X64CpuContext);
    } else if (Process.arch === "arm64") {
        parts = readPartsArm64(ctx as Arm64CpuContext);
    } else {
        return null;
    }

    if (!partsAreValid(parts)) return null;

    try {
        const labelStr = parts.labelPtr.readUtf8String(parts.labelLen);
        if (!labelStr) return null;
        const crHex = toHexString(parts.crPtr.readByteArray(parts.crLen));
        const secretHex = toHexString(parts.secretPtr.readByteArray(parts.secretLen));
        return `${labelStr} ${crHex} ${secretHex}`;
    } catch (e) {
        return null;
    }
}
