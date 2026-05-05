// agent/tls/definitions/shared_constants.ts
//
// Shared constants extracted from per-library definition files.

import { DUMMY_SESSION_ID_BASE } from "../../shared/generated_constants.js";

/** Socket helper symbols needed by every TLS library definition. */
export const STANDARD_SOCKET_SYMBOLS: string[] = ["getpeername", "getsockname", "ntohs", "ntohl"];

/**
 * Per-library dummy session ID variants. The base comes from the Python
 * source of truth (friTap/connection_index.py). Variants differ only in the
 * last hex digit (6 = OpenSSL, 7 = GnuTLS, 8 = WolfSSL, 9 = NSS).
 */
export const DUMMY_SESSION_ID_OPENSSL  = DUMMY_SESSION_ID_BASE + "6";
export const DUMMY_SESSION_ID_GNUTLS   = DUMMY_SESSION_ID_BASE + "7";
export const DUMMY_SESSION_ID_WOLFSSL  = DUMMY_SESSION_ID_BASE + "8";
export const DUMMY_SESSION_ID_NSS      = DUMMY_SESSION_ID_BASE + "9";

/** TLS 1.3 HKDF internal label → SSLKEYLOGFILE label mapping (RFC 8446 section 7.1). */
export const TLS13_LABEL_MAP: { [key: string]: string } = {
    "c hs traffic":   "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "s hs traffic":   "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "c ap traffic":   "CLIENT_TRAFFIC_SECRET_0",
    "s ap traffic":   "SERVER_TRAFFIC_SECRET_0",
    "exp master":     "EXPORTER_SECRET",
    "res master":     "RESUMPTION_MASTER_SECRET",
};
