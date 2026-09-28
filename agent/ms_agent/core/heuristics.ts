import { state } from "../state.js";

/* ---------------------------------------------------------------------------
 * Validators. Each one answers a single question about a candidate, and each one
 * exists because a specific class of false positive was observed on the target.
 * ------------------------------------------------------------------------- */

export function parseValidators(v) {
    return {
        maxZeroFraction: v.max_zero_fraction,
        minEntropyBits: v.min_shannon_entropy_bits,
        minSecretLen: v.min_secret_len,
        maxSecretLen: v.max_secret_len,
        pointerMin: ptr(v.pointer_min),
        tagMask: ptr(v.pointer_tag_mask)
    };
}

/* A run of mostly-zero bytes is uninitialised storage, never CSPRNG output. */
export function passesZeroFraction(bytes) {
    var zeros = 0;
    for (var i = 0; i < bytes.length; i++) if (bytes[i] === 0) zeros++;
    return (zeros / bytes.length) <= state.validators.maxZeroFraction;
}

/* Shannon entropy in bits per byte. Key material sits near 8; ASCII text, repeated
 * structures and pointer arrays sit far below the configured floor. */
export function shannonEntropyBits(bytes) {
    var counts = {}, i;
    for (i = 0; i < bytes.length; i++) counts[bytes[i]] = (counts[bytes[i]] || 0) + 1;
    var bits = 0;
    for (var k in counts) {
        var p = counts[k] / bytes.length;
        bits -= p * (Math.log(p) / Math.LN2);
    }
    return bits;
}

export function passesEntropy(bytes) {
    return shannonEntropyBits(bytes) >= state.validators.minEntropyBits;
}

/* Guards against a length byte that is stale garbage rather than a real size. */
export function passesLengthBounds(len) {
    return len >= state.validators.minSecretLen && len <= state.validators.maxSecretLen;
}

/* Every secret BoringSSL stores here is exactly one hash output long, so a length
 * that is not a hash size is a stale size_ byte, not a secret. Kept separate from
 * passesLengthBounds because the two come from different parts of the profile
 * (constants.valid_hash_lens vs validators.min/max_secret_len) and answer
 * different questions: "a plausible size" vs "a size this build can produce". */
export function isValidHashLen(len) {
    return state.profile.constants.valid_hash_lens.indexOf(len) !== -1;
}

/* The single per-secret gate. It is deliberately the ONLY way a candidate secret
 * reaches emitKeylog, so every emit site — the SSL_HANDSHAKE slots, the
 * SSL3_STATE traffic secrets and the SSL_SESSION master secret — gets the same
 * checks. The hash-length test lives here rather than in the Tier A slot walk
 * because a stale size_ byte of e.g. 40 passes the bounds and entropy checks and
 * would produce a WRONG-LENGTH secret carrying a correct label and a correct
 * client_random: worse than a miss, because it looks usable. */
export function looksLikeSecret(bytes) {
    return bytes !== null &&
           isValidHashLen(bytes.length) &&
           passesLengthBounds(bytes.length) &&
           passesZeroFraction(bytes) &&
           passesEntropy(bytes);
}

/* client_random is a fixed-size field, so only its content is in question. */
export function looksLikeRandom(bytes) {
    return bytes !== null && passesZeroFraction(bytes) && passesEntropy(bytes);
}
