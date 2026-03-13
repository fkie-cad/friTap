// agent/tls/definitions/shared_constants.ts
//
// Shared constants extracted from per-library definition files.

/** Socket helper symbols needed by every TLS library definition. */
export const STANDARD_SOCKET_SYMBOLS: string[] = ["getpeername", "getsockname", "ntohs", "ntohl"];

/**
 * Base dummy session ID used when enable_default_fd is true and the real
 * session ID cannot be obtained.  Per-library variants differ only in the
 * last hex digit (6 = OpenSSL, 7 = GnuTLS, 8 = WolfSSL).
 */
const DUMMY_SESSION_ID_BASE = "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF7633";

export const DUMMY_SESSION_ID_OPENSSL  = DUMMY_SESSION_ID_BASE + "6";
export const DUMMY_SESSION_ID_GNUTLS   = DUMMY_SESSION_ID_BASE + "7";
export const DUMMY_SESSION_ID_WOLFSSL  = DUMMY_SESSION_ID_BASE + "8";
