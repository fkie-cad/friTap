// agent/shared/clienthello_random.ts
//
// Extract the 32-byte TLS client_random from a ClientHello buffer.
//
// WHY THIS EXISTS
// ---------------
// For a statically linked, stripped LibreSSL host (e.g. curl-for-win's
// curl.exe) the KDF leaf (tls13_hkdf_expand_label) yields the derived secret +
// label, but client_random is NOT reachable from any KDF frame
// (tls13_derive_*_secrets operates on a tls13_secrets struct with no SSL*). The
// robust, build-independent, offset-free way to recover client_random is to
// parse it out of the plaintext ClientHello as it is written to the socket —
// the same "parse the ClientHello from a buffer" trick friTap already uses on
// the Windows Schannel path (agent/tls/decoders/ncrypt_keylog.ts).
//
// A `send`/`WSASend` buffer can carry the ClientHello in one of two framings,
// so handle both:
//
//   (1) full TLS record:
//         [0]      content type        0x16 (handshake)
//         [1..2]   record version      0x0301 / 0x0303
//         [3..4]   record length
//         [5]      handshake type      0x01 (ClientHello)
//         [6..8]   handshake length
//         [9..10]  client_version      0x03xx
//         [11..42] random[32]
//
//   (2) bare handshake message (header/body split across sends — matches the
//       Schannel SslHashHandshake layout):
//         [0]      handshake type      0x01 (ClientHello)
//         [1..3]   handshake length
//         [4..5]   client_version      0x03xx
//         [6..37]  random[32]

import { toHexString } from "../util/hex.js";

/**
 * Return the 32-byte client_random (lowercase hex) if `buf`/`len` holds a
 * ClientHello in either framing, else null. Never throws.
 */
export function extractClientRandomFromHandshake(buf: NativePointer, len: number): string | null {
    if (buf.isNull() || len < 38) return null;
    try {
        const b0 = buf.readU8();

        // (1) TLS record carrying the ClientHello.
        if (b0 === 0x16 && len >= 11 + 32) {
            const hsType = buf.add(5).readU8();
            const clientVersionHi = buf.add(9).readU8();
            if (hsType === 0x01 && clientVersionHi === 0x03) {
                const bytes = buf.add(11).readByteArray(32);
                if (bytes) return toHexString(bytes);
            }
            return null;
        }

        // (2) Bare ClientHello handshake message.
        if (b0 === 0x01 && len >= 6 + 32) {
            const clientVersionHi = buf.add(4).readU8();
            if (clientVersionHi === 0x03) {
                const bytes = buf.add(6).readByteArray(32);
                if (bytes) return toHexString(bytes);
            }
            return null;
        }
    } catch (_) {
        return null;
    }
    return null;
}
