/**
 * agent/rc4/definitions/rc4.ts — constants for the RC4 key-setup hooks.
 *
 * RC4 is an INDEPENDENT friTap protocol (it does NOT imply TLS). These hooks
 * capture the RC4 *key* wherever a program sets up an RC4 key schedule, whether
 * RC4 is the outer cipher (`--protocol rc4`) or nested inside TLS
 * (`--protocol tls,rc4`). The RC4-in-TLS record layer itself is handled by the
 * TLS hooks (SSPI EncryptMessage/DecryptMessage in agent/tls/definitions/sspi.ts)
 * when `tls` is also selected; this unit only recovers the RC4 key.
 *
 * The hook targets and the constants below are ported from the research agent
 * research/memory_scan_lsass/agent/rc4_decrypt.js (the live RC4 agent) and its
 * shared known-answer test.
 */

/** RC4 known-answer test: RC4("Key","Plaintext") == bbf316e8d940af0ad3. */
export const RC4_KAT_KEY = "Key";
export const RC4_KAT_PLAINTEXT = "Plaintext";
export const RC4_KAT_CIPHERTEXT_HEX = "bbf316e8d940af0ad3";

/** Windows legacy CryptoAPI: CALG_RC4 algorithm id and KP_ALGID key param. */
export const CALG_RC4 = 0x6801;
export const KP_ALGID = 7;
/** CryptExportKey blob type: PLAINTEXTKEYBLOB (raw symmetric key, when exportable). */
export const PLAINTEXTKEYBLOB = 0x8;

/**
 * Sane bounds on a recovered RC4 key length (bytes). RC4 keys are 1..256 bytes;
 * we clamp to a practical window so a bogus length never triggers a huge read.
 */
export const RC4_MIN_KEY_LEN = 1;
export const RC4_MAX_KEY_LEN = 256;
