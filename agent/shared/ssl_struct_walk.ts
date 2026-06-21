import { get_hex_string_from_byte_array } from "./shared_functions.js";

/*
 * Shared helpers for walking the BoringSSL `ssl_st` struct to recover
 * `client_random` when SSL_get_client_random is not exported (stripped
 * statically-linked forks such as Cloudflare WARP's libwarp_mobile.so).
 *
 * Consumers today: agent/shared/boringssl_symbol_hook.ts (modern shared
 * fallback) and agent/legacy/tls/libs/cronet.ts (legacy Cronet class).
 * agent/legacy/tls/libs/openssl_boringssl.ts uses a different SSL layout
 * (0x160/0x140) and intentionally does not consume this module.
 */

export const SSL3_RANDOM_SIZE = 32;

/*
 * Cap on per-SSL* client_random memoization. TLS 1.3 emits up to five
 * secrets per session (handshake-c, handshake-s, traffic-c, traffic-s,
 * exporter); the cache avoids walking the SSL struct five times for the
 * same context. Memory footprint at the cap (~80 KB) is negligible.
 *
 * Note: BoringSSL can reuse the same SSL* allocation for a fresh handshake
 * after SSL_free + SSL_new. If we ever observe stale-cache symptoms in the
 * wild, evict on an SSL_free hook.
 */
export const CLIENT_RANDOM_CACHE_MAX = 1024;

// Any candidate s3 pointer below this value is rejected as obviously
// invalid (cannot be a real userspace address; catches tagged-int / null
// garbage when probing the wrong offset).
export const MIN_VALID_S3_PTR = ptr(0x1000);

/*
 * Returns true when more than half of the buffer's bytes are zero. Used to
 * reject candidate offsets that point at uninitialised memory: a real
 * client_random is HKDF/CSPRNG output, so the probability of >=17/32 zero
 * bytes is ~10^-20 — negligible.
 */
export function isMostlyZero(buf: Uint8Array): boolean {
    let zeros = 0;
    for (let i = 0; i < buf.length; i++) {
        if (buf[i] === 0) zeros++;
    }
    return zeros * 2 > buf.length;
}

/*
 * Probe a single candidate s3 offset. Returns the hex-encoded client_random
 * on success or null on any failure (read fault, null/tagged s3 pointer,
 * mostly-zero bytes). Mirrors standalone/libwarp_mobile_ssl_log_secret.js:73-86.
 */
export function tryReadClientRandomAt(
    sslPtr: NativePointer,
    s3Off: number,
): string | null {
    try {
        const s3Ptr = sslPtr.add(s3Off).readPointer();
        if (s3Ptr.isNull()) return null;
        if (s3Ptr.compare(MIN_VALID_S3_PTR) < 0) return null;
        const buf = s3Ptr.add(0x30).readByteArray(SSL3_RANDOM_SIZE);
        if (!buf) return null;
        const u8 = new Uint8Array(buf as ArrayBuffer);
        if (isMostlyZero(u8)) return null;
        return get_hex_string_from_byte_array(u8);
    } catch (_) {
        return null;
    }
}

/*
 * Candidate ssl->s3 offsets, in the same probe order used for client_random
 * recovery (arch-primary 0x30 / 0x2c, then nearby fork-observed slots).
 */
const S3_CANDIDATE_OFFSETS = [0x30, 0x2c, 0x28, 0x38];

/*
 * Resolve the live ``ssl->s3`` pointer from an SSL*, validating the candidate
 * by reading a plausible (non-mostly-zero) client_random at s3+0x30. Returns
 * the s3 pointer or null. Used by the TLS 1.3 attach-mode secret recovery to
 * read both client_random and the retained traffic secrets from the same s3.
 */
export function findS3(sslPtr: NativePointer): NativePointer | null {
    if (sslPtr.isNull()) return null;
    for (const off of S3_CANDIDATE_OFFSETS) {
        try {
            const s3Ptr = sslPtr.add(off).readPointer();
            if (s3Ptr.isNull() || s3Ptr.compare(MIN_VALID_S3_PTR) < 0) continue;
            const buf = s3Ptr.add(0x30).readByteArray(SSL3_RANDOM_SIZE);
            if (!buf) continue;
            if (isMostlyZero(new Uint8Array(buf as ArrayBuffer))) continue;
            return s3Ptr;
        } catch (_) {
            /* try next candidate offset */
        }
    }
    return null;
}

/* Read the 32-byte client_random at s3+0x30 as a hex string ("" on failure). */
export function readClientRandomHex(s3Ptr: NativePointer): string {
    try {
        const buf = s3Ptr.add(0x30).readByteArray(SSL3_RANDOM_SIZE);
        if (!buf) return "";
        return get_hex_string_from_byte_array(new Uint8Array(buf as ArrayBuffer));
    } catch (_) {
        return "";
    }
}
