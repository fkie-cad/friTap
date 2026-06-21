/**
 * key_heuristics.ts — content tests that decide whether a window of bytes looks
 * like cryptographic key material. PUBLIC and protocol-agnostic: a private
 * protocol binding may add its own classifier on top, but the scoring here knows
 * nothing about any specific protocol.
 *
 * Signals, cheapest-first (the engine short-circuits on the entropy gate):
 *  - entropy        : Shannon entropy of the window is high (keys are random).
 *  - aes{128,192,256}_schedule : the bytes at the offset are a valid AES key
 *      SCHEDULE — i.e. re-deriving the round keys from the first 16/24/32 bytes
 *      reproduces the bytes that follow in memory (the classic "aeskeyfind"
 *      forward-rederivation; near-zero false positives).
 *  - x25519_clamp   : 32 bytes with the Curve25519 scalar clamp bits applied
 *      (low 3 bits of byte 0 clear, high bit of byte 31 clear, bit 6 set).
 *  - secret_width   : the candidate length matches a known secret width
 *      (validated via keylog_length.ts, which encodes NSS secret widths).
 */
import { looksLikeGarbageLength } from "../keylog_length.js";

// --- AES (Rijndael) key schedule forward-rederivation --------------------------

// prettier-ignore
const AES_SBOX = new Uint8Array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]);
const AES_RCON = new Uint8Array([0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d]);

/** AES key widths in bytes and their full expanded-schedule lengths. */
const AES_SCHEDULE_LEN: Readonly<Record<number, number>> = { 16: 176, 24: 208, 32: 240 };

/**
 * Derive the full AES key schedule from the first `keyBytes` bytes at
 * buf[off..]. Returns the expanded schedule (176/208/240 bytes).
 */
function aesKeyExpansion(buf: Uint8Array, off: number, keyBytes: number): Uint8Array {
    const Nk = keyBytes / 4;
    const Nr = Nk + 6;
    const total = 4 * (Nr + 1); // words
    const w = new Uint8Array(total * 4);
    for (let i = 0; i < keyBytes; i++) w[i] = buf[off + i];
    const t = new Uint8Array(4);
    for (let i = Nk; i < total; i++) {
        const p = (i - 1) * 4;
        t[0] = w[p]; t[1] = w[p + 1]; t[2] = w[p + 2]; t[3] = w[p + 3];
        if (i % Nk === 0) {
            const tmp = t[0]; // RotWord
            t[0] = AES_SBOX[t[1]] ^ AES_RCON[(i / Nk) - 1];
            t[1] = AES_SBOX[t[2]];
            t[2] = AES_SBOX[t[3]];
            t[3] = AES_SBOX[tmp];
        } else if (Nk > 6 && i % Nk === 4) {
            t[0] = AES_SBOX[t[0]]; t[1] = AES_SBOX[t[1]];
            t[2] = AES_SBOX[t[2]]; t[3] = AES_SBOX[t[3]];
        }
        const q = i * 4, r = (i - Nk) * 4;
        w[q] = w[r] ^ t[0];
        w[q + 1] = w[r + 1] ^ t[1];
        w[q + 2] = w[r + 2] ^ t[2];
        w[q + 3] = w[r + 3] ^ t[3];
    }
    return w;
}

/**
 * True if the bytes at buf[off..] are a stored AES key schedule of width
 * `keyBytes` (16/24/32): re-deriving from the first keyBytes reproduces the
 * trailing schedule bytes already present in memory. Needs the full schedule
 * length available in `buf`.
 */
export function aesScheduleMatchesAt(buf: Uint8Array, off: number, keyBytes: number): boolean {
    const schedLen = AES_SCHEDULE_LEN[keyBytes];
    if (!schedLen || off + schedLen > buf.length) return false;
    const derived = aesKeyExpansion(buf, off, keyBytes);
    // Compare the derived schedule past the raw key to the in-memory bytes.
    for (let i = keyBytes; i < schedLen; i++) {
        if (derived[i] !== buf[off + i]) return false;
    }
    return true;
}

// --- Curve25519 scalar clamp ---------------------------------------------------

/** True if the 32 bytes at buf[off..] carry the Curve25519 scalar clamp. */
export function isClampedX25519Scalar(buf: Uint8Array, off: number): boolean {
    if (off + 32 > buf.length) return false;
    const b0 = buf[off];
    const b31 = buf[off + 31];
    return (b0 & 0x07) === 0 && (b31 & 0x80) === 0 && (b31 & 0x40) !== 0;
}

// --- Entropy -------------------------------------------------------------------

/** Shannon entropy (bits/byte) of buf[off..off+len). Range 0..8. */
export function shannonEntropy(buf: Uint8Array, off: number, len: number): number {
    if (len <= 0 || off + len > buf.length) return 0;
    const counts = new Uint32Array(256);
    for (let i = 0; i < len; i++) counts[buf[off + i]]++;
    let h = 0;
    for (let i = 0; i < 256; i++) {
        if (counts[i] === 0) continue;
        const p = counts[i] / len;
        h -= p * Math.log2(p);
    }
    return h;
}

// --- Secret-width validation (via keylog_length.ts) ----------------------------

/** Common symmetric/secret widths in bytes (AES keys, TLS secrets, X25519). */
const PLAUSIBLE_WIDTHS = new Set([16, 24, 32, 48, 64]);

/**
 * True if `len` is a plausible secret width. When a NSS-style label is in
 * proximity, defer to keylog_length's per-label width check (rejects e.g. a
 * 5-byte CLIENT_RANDOM); otherwise use the generic width allowlist.
 */
export function isPlausibleSecretWidth(len: number, label?: string): boolean {
    if (label) {
        return !looksLikeGarbageLength(len, label).garbage;
    }
    return PLAUSIBLE_WIDTHS.has(len);
}

// --- Aggregate scoring ---------------------------------------------------------

/** Minimum Shannon entropy (bits/byte over a 32-byte window) to consider a window. */
export const ENTROPY_GATE = 3.5;

/** The fixed-size window the engine slides while scanning. */
export const WINDOW_LEN = 32;

export interface CandidateScore {
    score: number;
    signals: string[];
    /** Best-fit candidate length in bytes (AES width when matched, else WINDOW_LEN). */
    length: number;
}

/**
 * Score a WINDOW_LEN-byte window at buf[off..]. Returns score 0 (with no
 * signals) when the window fails the entropy gate, so callers can cheaply skip
 * low-entropy regions. `label` is an optional NSS label found near the window.
 */
export function scoreCandidate(buf: Uint8Array, off: number, label?: string): CandidateScore {
    const signals: string[] = [];
    const entropy = shannonEntropy(buf, off, WINDOW_LEN);
    if (entropy < ENTROPY_GATE) {
        return { score: 0, signals, length: WINDOW_LEN };
    }
    let score = entropy; // 3.5..8 baseline
    signals.push("entropy");
    let length = WINDOW_LEN;

    // AES key schedule (strongest signal) — try widest key first.
    for (const keyBytes of [32, 24, 16]) {
        if (aesScheduleMatchesAt(buf, off, keyBytes)) {
            signals.push(`aes${keyBytes * 8}_schedule`);
            score += 100;
            length = keyBytes;
            break;
        }
    }

    if (isClampedX25519Scalar(buf, off)) {
        signals.push("x25519_clamp");
        score += 8;
        length = 32;
    }

    if (isPlausibleSecretWidth(length, label)) {
        signals.push("secret_width");
        score += 4;
    }

    return { score, signals, length };
}
