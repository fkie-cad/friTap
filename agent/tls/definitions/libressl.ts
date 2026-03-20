// agent/tls/definitions/libressl.ts
//
// Data-driven LibreSSL hook definition for macOS system SSL (/usr/lib/libssl.*.dylib).
//
// Key differences from BoringSSL macOS path:
// - Read/write hooks ENABLED (LibreSSL's SSL_get_fd works correctly)
// - Two-tier keylog: SSL_CTX_set_keylog_callback (LibreSSL 3.5+) → KDF function hooks
// - KDF hooks use non-exported symbols found via Module.enumerateSymbols()

import { HookDefinition, ResolvedFunctions, KeylogApproach } from "../../core/hook_definition.js";
import { devlog, devlog_error, log } from "../../util/log.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { findNonExportedSymbols } from "../../shared/shared_functions.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { STANDARD_SOCKET_SYMBOLS, TLS13_LABEL_MAP } from "./shared_constants.js";
import { openSslFdDecoder, openSslSessionIdDecoder } from "./openssl.js";

// Pre-allocated buffers reused across hook invocations
const _clientRandomBuf = Memory.alloc(32);
const _masterKeyBuf = Memory.alloc(48);

/**
 * Create a two-tier keylog approach for LibreSSL:
 * Tier 1: Use SSL_CTX_set_keylog_callback if available (LibreSSL 3.5+)
 * Tier 2: Hook non-exported KDF functions (tls1_PRF / tls13_hkdf_expand_label)
 */
function createLibreSslKeylogApproach(): KeylogApproach {
    return {
        kind: "custom",
        install: (addresses, modName, resolvedFns, _enableDefaultFd) => {
            let keylogCallbackInstalled = false;

            // ── Tier 1: SSL_CTX_set_keylog_callback (LibreSSL 3.5+) ──
            if (resolvedFns["SSL_CTX_set_keylog_callback"]) {
                const keylogCb = new NativeCallback(
                    function (_ssl: NativePointer, line: NativePointer) {
                        sendKeylog(line.readCString());
                    },
                    "void",
                    ["pointer", "pointer"],
                );

                const sslNewAddr = addresses[modName]?.["SSL_new"];
                if (sslNewAddr && !sslNewAddr.isNull()) {
                    Interceptor.attach(sslNewAddr, {
                        onEnter: function (args: any) {
                            try {
                                resolvedFns["SSL_CTX_set_keylog_callback"](args[0], keylogCb);
                            } catch (e) {
                                devlog_error(`[LibreSSL] Error in SSL_new keylog hook: ${e}`);
                            }
                        },
                    });
                    keylogCallbackInstalled = true;
                    log("[LibreSSL] Keylog via SSL_CTX_set_keylog_callback installed");
                }
            }

            // ── Tier 2: Hook non-exported KDF functions ──
            if (!keylogCallbackInstalled) {
                log("[LibreSSL] SSL_CTX_set_keylog_callback not available, trying KDF hooks");
                installKdfHooks(modName, resolvedFns);
            }
        },
    };
}

/**
 * Install hooks on LibreSSL's non-exported KDF functions for key extraction.
 * Uses SSL_get_client_random to get the client_random from the SSL* during handshake.
 */
function installKdfHooks(modName: string, resolvedFns: ResolvedFunctions): void {
    const SSL_get_client_random = resolvedFns["SSL_get_client_random"];

    // Batch-resolve all non-exported symbols in a single pass
    const nonExported = findNonExportedSymbols(modName, [
        "tls13_hkdf_expand_label",
        "tls13_hkdf_expand_label_with_length",
        "tls1_PRF",
    ]);

    // ── TLS 1.3: tls13_hkdf_expand_label ──
    // Signature: int tls13_hkdf_expand_label(tls13_secret *out, const EVP_MD *digest,
    //     const tls13_secret *secret, const char *label, const tls13_secret *context)
    // tls13_secret = { uint8_t *data; size_t len; }
    const hkdfAddr = nonExported.get("tls13_hkdf_expand_label");
    if (hkdfAddr) {
        log("[LibreSSL] Hooking tls13_hkdf_expand_label for TLS 1.3 key extraction");
        attachHkdfHook(hkdfAddr, SSL_get_client_random, "tls13_hkdf_expand_label");
    } else {
        devlog("[LibreSSL] tls13_hkdf_expand_label not found (TLS 1.3 keylog unavailable)");
    }

    // Also try the _with_length variant
    const hkdfWithLenAddr = nonExported.get("tls13_hkdf_expand_label_with_length");
    if (hkdfWithLenAddr) {
        log("[LibreSSL] Hooking tls13_hkdf_expand_label_with_length for TLS 1.3 key extraction");
        attachHkdfHook(hkdfWithLenAddr, SSL_get_client_random, "tls13_hkdf_expand_label_with_length");
    }

    // ── TLS 1.2: tls1_PRF ──
    const prfAddr = nonExported.get("tls1_PRF");
    if (prfAddr) {
        log("[LibreSSL] Hooking tls1_PRF for TLS 1.2 key extraction");
        Interceptor.attach(prfAddr, {
            onEnter: function (args: any) {
                this.sslPtr = args[0]; // SSL*
            },
            onLeave: function (_retval: any) {
                try {
                    if (!SSL_get_client_random) return;

                    const crLen = SSL_get_client_random(this.sslPtr, _clientRandomBuf, 32) as number;
                    if (crLen !== 32) return;
                    const clientRandom = readHexFromPointer(_clientRandomBuf, 32);

                    const masterKey = extractMasterKey(this.sslPtr, resolvedFns);
                    if (!masterKey) return;

                    sendKeylog(`CLIENT_RANDOM ${clientRandom} ${masterKey}`);
                } catch (e) {
                    devlog_error(`[LibreSSL] tls1_PRF onLeave error: ${e}`);
                }
            },
        });
    } else {
        devlog("[LibreSSL] tls1_PRF not found (TLS 1.2 keylog unavailable)");
    }

    // ── Hook SSL_do_handshake to track current SSL* per thread ──
    installHandshakeTracker(modName);
}

/**
 * Shared HKDF hook installer for tls13_hkdf_expand_label variants.
 * Both variants have the same argument layout: args[0]=out, args[3]=label.
 */
function attachHkdfHook(
    addr: NativePointer,
    SSL_get_client_random: NativeFunction<any, any> | undefined,
    funcName: string,
): void {
    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            this.outSecret = args[0];    // tls13_secret *out
            this.labelPtr = args[3];     // const char *label
        },
        onLeave: function (_retval: any) {
            try {
                const label = this.labelPtr.readCString();
                const sslkeylogLabel = TLS13_LABEL_MAP[label];
                if (!sslkeylogLabel) {
                    devlog(`[LibreSSL] Unknown TLS 1.3 label: ${label}`);
                    return;
                }

                // Read output secret: tls13_secret { uint8_t *data; size_t len; }
                const dataPtr = this.outSecret.readPointer();
                const dataLen = this.outSecret.add(Process.pointerSize).readULong();
                if (dataPtr.isNull() || dataLen === 0) return;

                const secretHex = readHexFromPointer(dataPtr, dataLen as number);

                const clientRandom = getThreadClientRandom(SSL_get_client_random);
                if (!clientRandom) {
                    devlog(`[LibreSSL] Could not get client_random for ${funcName} keylog`);
                    return;
                }

                sendKeylog(`${sslkeylogLabel} ${clientRandom} ${secretHex}`);
            } catch (e) {
                devlog_error(`[LibreSSL] ${funcName} onLeave error: ${e}`);
            }
        },
    });
}

// Thread-local SSL* tracking for mapping KDF calls back to their SSL connection
const _threadSslMap = new Map<number, NativePointer>();

function installHandshakeTracker(modName: string): void {
    // Try exported symbols first (cheaper), then fall back to non-exported
    for (const sym of ["SSL_do_handshake", "SSL_connect"]) {
        let hookAddr: NativePointer | null = null;
        try {
            hookAddr = Process.getModuleByName(modName).getExportByName(sym);
        } catch (_) {
            // Not exported — will be caught by the null check below
        }

        if (!hookAddr || hookAddr.isNull()) {
            // Fallback: try non-exported (single symbol, not batch — only runs if export failed)
            const found = findNonExportedSymbols(modName, [sym]);
            hookAddr = found.get(sym) || null;
        }

        if (hookAddr && !hookAddr.isNull()) {
            Interceptor.attach(hookAddr, {
                onEnter: function (args: any) {
                    _threadSslMap.set(Process.getCurrentThreadId(), args[0]);
                },
                onLeave: function (_retval: any) {
                    _threadSslMap.delete(Process.getCurrentThreadId());
                },
            });
            devlog(`[LibreSSL] Handshake tracker installed on ${sym}`);
            break;
        }
    }
}

function getThreadClientRandom(SSL_get_client_random: NativeFunction<any, any> | undefined): string | null {
    if (!SSL_get_client_random) return null;
    const ssl = _threadSslMap.get(Process.getCurrentThreadId());
    if (!ssl) return null;

    try {
        const len = SSL_get_client_random(ssl, _clientRandomBuf, 32) as number;
        if (len !== 32) return null;
        return readHexFromPointer(_clientRandomBuf, 32);
    } catch (e) {
        devlog(`[LibreSSL] getThreadClientRandom error: ${e}`);
        return null;
    }
}

function extractMasterKey(ssl: NativePointer, resolvedFns: ResolvedFunctions): string | null {
    if (!resolvedFns["SSL_get_session"]) return null;
    const session = resolvedFns["SSL_get_session"](ssl) as NativePointer;
    if (session.isNull()) return null;

    if (resolvedFns["SSL_SESSION_get_master_key"]) {
        const mkLen = resolvedFns["SSL_SESSION_get_master_key"](session, _masterKeyBuf, 48) as number;
        if (mkLen > 0) {
            return readHexFromPointer(_masterKeyBuf, mkLen);
        }
    }

    return null;
}

export function createLibreSslDefinition(): HookDefinition {
    const librarySymbols = [
        "SSL_read",
        "SSL_write",
        "SSL_get_fd",
        "SSL_get_session",
        "SSL_SESSION_get_id",
        "SSL_new",
        "SSL_CTX_set_keylog_callback",
        "SSL_get_client_random",
        "SSL_SESSION_get_master_key",
        "SSL_do_handshake",
        "SSL_connect",
    ];

    return {
        libraryId: "libressl",
        offsetKey: "openssl",
        functions: {
            librarySymbols,
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            { symbol: "SSL_get_fd", retType: "int", argTypes: ["pointer"] },
            { symbol: "SSL_get_session", retType: "pointer", argTypes: ["pointer"] },
            { symbol: "SSL_SESSION_get_id", retType: "pointer", argTypes: ["pointer", "pointer"] },
            { symbol: "SSL_CTX_set_keylog_callback", retType: "void", argTypes: ["pointer", "pointer"] },
            { symbol: "SSL_get_client_random", retType: "int", argTypes: ["pointer", "pointer", "int"] },
            { symbol: "SSL_SESSION_get_master_key", retType: "int", argTypes: ["pointer", "pointer", "int"] },
        ],
        fdDecoder: openSslFdDecoder,
        sessionIdDecoder: openSslSessionIdDecoder,
        readHook: {
            symbol: "SSL_read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "SSL_read",
        },
        writeHook: {
            symbol: "SSL_write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "SSL_write",
        },
        keylog: createLibreSslKeylogApproach(),
    };
}
