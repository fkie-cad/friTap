// agent/tls/decoders/gotls_registers.ts
//
// Go ABIInternal register-based extraction of writeKeyLog arguments.
// Go's calling convention passes scalar args in CPU registers, not the
// System V slots Frida exposes via args[]. The mapping is stable for
// crypto/tls.(*Config).writeKeyLog across Go 1.17+ (when ABIInternal
// became the default) and matches the layout the legacy GoTlsLogger used.

import { toHexString } from "../../shared/shared_functions.js";
import { goKeyLogArgs, GoKeyLogArgs } from "../../shared/go_abi.js";

/**
 * Bounds check: positive, non-zero, and below 1024 bytes — the largest
 * plausible keylog field is a 64-byte secret. Anything bigger almost
 * certainly means we read garbage from a non-Go-ABI frame.
 */
function isPlausibleLen(len: number): boolean {
    return len > 0 && len < 1024;
}

/**
 * Validate that every pointer is non-null and every length is plausible.
 * Returns false (and the caller bails) when anything looks suspect.
 */
function partsAreValid(p: GoKeyLogArgs): boolean {
    if (p.label.isNull() || !isPlausibleLen(p.labelLength)) return false;
    if (p.clientRandom.isNull() || !isPlausibleLen(p.clientRandomLength)) return false;
    if (p.secret.isNull() || !isPlausibleLen(p.secretLength)) return false;
    return true;
}

/**
 * Extract a single SSLKEYLOGFILE line ("LABEL CR_HEX SECRET_HEX") from
 * the writeKeyLog arguments in `ctx`, read via go_abi.ts goKeyLogArgs:
 *   x64:   RBX/RCX = label, RDI/RSI = clientRandom, R9/R10 = secret
 *   arm64: X1/X2   = label, X3/X4   = clientRandom, X6/X7  = secret
 *   386/arm (stack): words 1/2 = label, 3/4 = clientRandom, 6/7 = secret at sp+4+4*word
 * (X5 / R8 hold clientRandom's cap — the arm64 layout once read X5/X6 as the secret).
 * Returns null when the architecture is unsupported, any pointer is null,
 * any length is implausible, or memory reads throw.
 */
export function extractKeylogFromRegisters(ctx: CpuContext, arch: string = Process.arch): string | null {
    const parts = goKeyLogArgs(ctx, arch);
    if (parts === null || !partsAreValid(parts)) return null;

    try {
        const labelStr = parts.label.readUtf8String(parts.labelLength);
        if (!labelStr) return null;
        const crHex = toHexString(parts.clientRandom.readByteArray(parts.clientRandomLength));
        const secretHex = toHexString(parts.secret.readByteArray(parts.secretLength));
        return `${labelStr} ${crHex} ${secretHex}`;
    } catch (e) {
        return null;
    }
}
