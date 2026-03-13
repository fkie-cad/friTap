// agent/tls/definitions/mbedtls.ts
//
// Data-driven mbedTLS hook definition.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";

/**
 * Decode the file descriptor from an mbedtls_ssl_context struct.
 *
 * mbedTLS stores the BIO (transport) pointer at a platform-dependent offset:
 *   - Windows: sslcontext + 48
 *   - Other:   sslcontext + 56
 *
 * The BIO pointer typically points to the socket fd (int32).
 */
function mbedTlsFdDecoder(sslCtx: NativePointer, _fns: ResolvedFunctions): number {
    const pBioOffset = Process.platform === "windows" ? 48 : 56;
    const pBio = sslCtx.add(pBioOffset).readPointer();
    return pBio.readS32();
}

/**
 * Decode the session ID from an mbedtls_ssl_context struct.
 *
 * Layout from the ssl context:
 *   - session pointer: sslcontext + 24 + 7 * pointerSize
 *   - id_len:          session + 16  (uint32)
 *   - id:              session + 20  (byte array)
 */
function mbedTlsSessionIdDecoder(sslCtx: NativePointer, _fns: ResolvedFunctions): string {
    const sessionPtr = sslCtx.add(24 + 7 * Process.pointerSize).readPointer();
    if (sessionPtr.isNull()) {
        return "";
    }
    const idLen = sessionPtr.add(16).readU32();
    if (idLen === 0 || idLen > 32) {
        return "";
    }
    return readHexFromPointer(sessionPtr.add(20), idLen);
}

export function createMbedTlsDefinition(): HookDefinition {
    return {
        libraryId: "mbedtls",
        offsetKey: "mbedtls",
        functions: {
            librarySymbols: ["mbedtls_ssl_read", "mbedtls_ssl_write"],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        fdDecoder: mbedTlsFdDecoder,
        sessionIdDecoder: mbedTlsSessionIdDecoder,
        readHook: {
            symbol: "mbedtls_ssl_read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "mbedtls_ssl_read",
        },
        writeHook: {
            symbol: "mbedtls_ssl_write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "mbedtls_ssl_write",
        },
        keylog: { kind: "none" },
    };
}
