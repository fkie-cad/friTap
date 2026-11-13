/*
 * Keylog -> SSL* identity bridge (P1, design B3).
 *
 * sendKeylog(line, ssl?, module?) hands every keylog line that came with its
 * SSL* to the registered observer, BEFORE the keylog_enabled gate, so the
 * per-SSL* identity cache (ssl_identity.ts) learns the connection's
 * client_random even in plaintext-only mode (-p without -k).
 *
 * This module has NO imports on purpose: shared_structures.ts must stay an
 * import leaf, and ssl_identity.ts transitively imports shared_functions.ts,
 * which imports shared_structures.ts. Importing ssl_identity directly from
 * shared_structures would create a cycle; instead ssl_identity registers
 * itself here (dependency inversion).
 */

/** Receives (SSL*, lower-case 64-hex client_random, module name?). */
export type KeylogSslObserver = (ssl: NativePointer, clientRandomHex: string, module?: string) => void;

const CLIENT_RANDOM_TOKEN_RE = /^[0-9a-fA-F]{64}$/;

let keylogSslObserver: KeylogSslObserver | null = null;

/** Register (or with null, clear) the observer. The last registration wins. */
export function setKeylogSslObserver(observer: KeylogSslObserver | null): void {
    keylogSslObserver = observer;
}

/**
 * The client_random of an NSS keylog line ("LABEL <cr-hex> <secret-hex>"):
 * the 2nd whitespace token when it is exactly 64 hex chars, lower-cased.
 * Anything else (non-NSS formats, RSA Session-ID lines, garbage) gives "".
 */
export function extractKeylogClientRandom(line: unknown): string {
    if (typeof line !== "string") return "";
    const tokens = line.trim().split(/\s+/);
    if (tokens.length < 2) return "";
    const candidate = tokens[1];
    return CLIENT_RANDOM_TOKEN_RE.test(candidate) ? candidate.toLowerCase() : "";
}

function isUsableSslPointer(ssl: unknown): ssl is NativePointer {
    if (!ssl || typeof (ssl as NativePointer).isNull !== "function") return false;
    return !(ssl as NativePointer).isNull();
}

/** Forward the line's client_random for `ssl` to the observer. Never throws. */
export function observeKeylogSsl(line: unknown, ssl?: NativePointer | null, module?: string): void {
    if (!keylogSslObserver || !isUsableSslPointer(ssl)) return;
    try {
        const clientRandom = extractKeylogClientRandom(line);
        if (clientRandom) keylogSslObserver(ssl, clientRandom, module);
    } catch (_) {
        // Identity tracking is best-effort; it must never break keylog emission.
    }
}
