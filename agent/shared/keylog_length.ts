// agent/shared/keylog_length.ts
//
// PQ-TLS note: ML-KEM/Kyber/hybrid KEMs do NOT change keylog secret widths
// (the KEM shared secret is mixed BEFORE HKDF-Extract, so labeled outputs
// remain HashLen — 32 for SHA-256 suites, 48 for SHA-384). LABEL_EXPECTED_LEN
// is the single extension point for future drafts that emit raw-KEM debug
// labels at non-HashLen widths; MAX_VALID_LEN = 64 leaves headroom.

import { devlog_debug } from "../util/log.js";

// PQ-TLS extension point — add labels that emit non-HashLen output here.
// undefined = HashLen-ambiguous (32 or 48 depending on cipher hash).
const LABEL_EXPECTED_LEN: Readonly<Record<string, number | undefined>> = {
    CLIENT_RANDOM: 48,
    CLIENT_EARLY_TRAFFIC_SECRET: undefined,
    EARLY_EXPORTER_SECRET: undefined,
    EARLY_EXPORTER_MASTER_SECRET: undefined,
    CLIENT_HANDSHAKE_TRAFFIC_SECRET: undefined,
    SERVER_HANDSHAKE_TRAFFIC_SECRET: undefined,
    CLIENT_TRAFFIC_SECRET_0: undefined,
    SERVER_TRAFFIC_SECRET_0: undefined,
    EXPORTER_SECRET: undefined,
    // PQ-TLS extension point — hypothetical future labels:
    // PQ_RAW_KEM_SECRET: 64,
    // HYBRID_KEM_SHARED: 32,
};

const MIN_VALID_LEN = 16;
const MAX_VALID_LEN = 64;
const HARD_GARBAGE_CEIL = 256;
const POINTER_LIKE_THRESHOLD = 0x10000000;
const LABEL_DISAGREE_TOLERANCE = 16;

export interface GarbageCheck {
    garbage: boolean;
    reason: string;
    expected: number | undefined;
}

export function looksLikeGarbageLength(
    claimedLen: number | undefined,
    labelStr: string,
): GarbageCheck {
    const expected = LABEL_EXPECTED_LEN[labelStr];
    if (claimedLen === undefined) {
        return { garbage: true, reason: "undefined", expected };
    }
    if (typeof claimedLen !== "number" || !Number.isFinite(claimedLen)) {
        return { garbage: true, reason: "NaN/Infinity", expected };
    }
    if (!Number.isInteger(claimedLen)) {
        return { garbage: true, reason: "non-integer", expected };
    }
    if (claimedLen <= 0) {
        return { garbage: true, reason: `non-positive=${claimedLen}`, expected };
    }
    if (claimedLen >= POINTER_LIKE_THRESHOLD) {
        return { garbage: true, reason: `pointer-like=0x${claimedLen.toString(16)}`, expected };
    }
    if (claimedLen > HARD_GARBAGE_CEIL) {
        return { garbage: true, reason: `> ${HARD_GARBAGE_CEIL}`, expected };
    }
    if (expected !== undefined && Math.abs(claimedLen - expected) > LABEL_DISAGREE_TOLERANCE) {
        return {
            garbage: true,
            reason: `label '${labelStr}' expects ${expected}, claim=${claimedLen}`,
            expected,
        };
    }
    return { garbage: false, reason: "", expected };
}

function snapToBucket(n: number): 32 | 48 {
    return n >= 48 ? 48 : 32;
}

export interface SafeKeyLenResult {
    len: number;
    trusted: boolean;
    reason: string;
}

export type ByteWalkFn = (label: string, ptr: NativePointer) => number;

export function safeKeyLen(
    claimedLen: number | undefined,
    labelStr: string,
    keyPtr: NativePointer,
    byteWalk: ByteWalkFn,
): SafeKeyLenResult {
    const garbage = looksLikeGarbageLength(claimedLen, labelStr);
    const expected = garbage.expected;

    if (!garbage.garbage) {
        const c = claimedLen as number;
        const inRange = c >= MIN_VALID_LEN && c <= MAX_VALID_LEN;
        const isCanonical = c === 32 || c === 48;

        if (inRange && isCanonical && (expected === undefined || expected === c)) {
            return { len: c, trusted: true, reason: "claimed-canonical" };
        }
        if (expected !== undefined) {
            return {
                len: expected,
                trusted: false,
                reason: `label-override ${labelStr}=${expected} (claim=${c})`,
            };
        }
        if (inRange) {
            const bucketed = snapToBucket(c);
            return {
                len: bucketed,
                trusted: false,
                reason: `bucket-collapse claim=${c} -> ${bucketed}`,
            };
        }
    }

    if (expected !== undefined) {
        return {
            len: expected,
            trusted: false,
            reason: `garbage(${garbage.reason}) + label-fixed ${expected}`,
        };
    }

    try {
        const heuristic = byteWalk(labelStr, keyPtr);
        const bucketed = snapToBucket(heuristic);
        const garbageSuffix = garbage.garbage ? ` (claim garbage: ${garbage.reason})` : "";
        return {
            len: bucketed,
            trusted: false,
            reason: `byte-walk=${heuristic} bucket=${bucketed}${garbageSuffix}`,
        };
    } catch (e) {
        return { len: 32, trusted: false, reason: `byte-walk-failed: ${e}` };
    }
}

export function safeKeyLenLogged(
    claimedLen: number | undefined,
    labelStr: string,
    keyPtr: NativePointer,
    byteWalk: ByteWalkFn,
): SafeKeyLenResult {
    const r = safeKeyLen(claimedLen, labelStr, keyPtr, byteWalk);
    if (!r.trusted) {
        devlog_debug(
            `[keylen] ${labelStr}: claimed=${String(claimedLen)} ` +
            `chosen=${r.len} trusted=${r.trusted} reason=${r.reason}`,
        );
    }
    return r;
}

// Unwrap a Frida InvocationArguments[3] (NativePointer | undefined) into the
// numeric length expected by safeKeyLen. Returns undefined for absent slots
// so `safeKeyLen`'s "undefined → garbage → label-fixed" path triggers cleanly.
export function lenArg(a: any): number | undefined {
    return a ? (a as NativePointer).toUInt32() : undefined;
}
