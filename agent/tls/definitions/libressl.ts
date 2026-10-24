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
import { findLibreSslKdfAddresses, attachLibreSslPrfHook } from "../../shared/libressl_kdf.js";
import { installLibreSslClientRandomViaSend, resolveLibreSslClientRandom, attachHandshakeTracker, currentHandshakeSsl } from "../../shared/libressl_client_random.js";
import { getParsedPatterns } from "../../fritap_agent.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { STANDARD_SOCKET_SYMBOLS, TLS13_LABEL_MAP } from "./shared_constants.js";
import { openSslClientRandomDecoder, openSslFdDecoder, openSslSessionIdDecoder } from "./openssl.js";
import { createKeylogCallbackTracker } from "../../shared/keylog_callback_tracker.js";

// Pre-allocated buffer reused across hook invocations
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

            // ── Tier 1: SSL_CTX_set_keylog_callback (LibreSSL 3.5+) ──
            const setKeylogAddr = addresses[modName]?.["SSL_CTX_set_keylog_callback"];
            if (resolvedFns["SSL_CTX_set_keylog_callback"] && setKeylogAddr && !setKeylogAddr.isNull()) {
                const keylogCb = new NativeCallback(
                    function (_ssl: NativePointer, line: NativePointer) {
                        devlog(`invoking keylog_callback from LibreSSL (${modName})`);
                        sendKeylog(line.readCString());
                    },
                    "void",
                    ["pointer", "pointer"],
                );

                const sslNewAddr = addresses[modName]?.["SSL_new"];
                if (sslNewAddr && !sslNewAddr.isNull()) {
                    // Records every SSL_CTX we point at keylogCb so releaseAgentHooks can
                    // undo it before keylogCb is freed (shared/keylog_callback_tracker.ts).
                    // SSL_CTX_up_ref / SSL_CTX_get_keylog_callback are optional: the
                    // tracker degrades safely when this LibreSSL build lacks them.
                    const tracker = createKeylogCallbackTracker(modName, setKeylogAddr, keylogCb, true);
                    Interceptor.attach(sslNewAddr, {
                        onEnter: function (args: any) {
                            try {
                                tracker.install(args[0]);
                            } catch (e) {
                                devlog_error(`[LibreSSL] Error in SSL_new keylog hook: ${e}`);
                            }
                        },
                    });
                    log("[LibreSSL] Keylog via SSL_CTX_set_keylog_callback installed");
                }
            }

            // ── Tier 2: Hook non-exported KDF functions ──
            // Always: LibreSSL exports SSL_CTX_set_keylog_callback (3.5+) but
            // never invokes the callback, so Tier 1 alone yields no keys.
            installKdfHooks(modName, resolvedFns);
            log(`[*] ${modName}: keylog hooks installed via KDF function hooks (tls1_PRF / tls13_hkdf_expand_label)`);
            return true;
        },
    };
}

/**
 * Install hooks on LibreSSL's non-exported KDF functions for key extraction.
 * Uses SSL_get_client_random to get the client_random from the SSL* during handshake.
 */
function installKdfHooks(modName: string, resolvedFns: ResolvedFunctions): void {
    const SSL_get_client_random = resolvedFns["SSL_get_client_random"];

    // Resolve the KDF functions: symbol table first (dynamic/symbol-bearing
    // builds), byte-pattern fallback for stripped static hosts. Shared with the
    // legacy class via agent/shared/libressl_kdf.ts.
    const nonExported = findLibreSslKdfAddresses(modName, getParsedPatterns());

    // Stripped-static path: SSL_get_client_random is gone and client_random is
    // not reachable from any KDF frame, so capture it from the plaintext
    // ClientHello written to the socket (send()). The KDF hooks fall back to
    // this per-thread value.
    if (!SSL_get_client_random && (nonExported.hkdf || nonExported.hkdfWithLen || nonExported.prf)) {
        installLibreSslClientRandomViaSend();
    }

    // ── TLS 1.3: tls13_hkdf_expand_label ──
    // Signature: int tls13_hkdf_expand_label(tls13_secret *out, const EVP_MD *digest,
    //     const tls13_secret *secret, const char *label, const tls13_secret *context)
    // tls13_secret = { uint8_t *data; size_t len; }
    const hkdfAddr = nonExported.hkdf;
    if (hkdfAddr) {
        log("[LibreSSL] Hooking tls13_hkdf_expand_label for TLS 1.3 key extraction");
        attachHkdfHook(hkdfAddr, SSL_get_client_random, "tls13_hkdf_expand_label");
    } else {
        devlog("[LibreSSL] tls13_hkdf_expand_label not found (TLS 1.3 keylog unavailable)");
    }

    // Also try the _with_length variant
    const hkdfWithLenAddr = nonExported.hkdfWithLen;
    if (hkdfWithLenAddr) {
        log("[LibreSSL] Hooking tls13_hkdf_expand_label_with_length for TLS 1.3 key extraction");
        attachHkdfHook(hkdfWithLenAddr, SSL_get_client_random, "tls13_hkdf_expand_label_with_length");
    }

    // ── TLS 1.2: tls1_PRF ──
    const prfAddr = nonExported.prf;
    if (prfAddr) {
        log("[LibreSSL] Hooking tls1_PRF for TLS 1.2 key extraction");
        attachLibreSslPrfHook(prfAddr, SSL_get_client_random, (ssl) => extractMasterKey(ssl, resolvedFns));
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

                devlog(`invoking ${funcName} keylog hook from LibreSSL`);
                sendKeylog(`${sslkeylogLabel} ${clientRandom} ${secretHex}`);
            } catch (e) {
                devlog_error(`[LibreSSL] ${funcName} onLeave error: ${e}`);
            }
        },
    });
}

function installHandshakeTracker(modName: string): void {
    // Hook every handshake entry point: LibreSSL's SSL_connect/SSL_accept call
    // the method's handshake directly, NOT through SSL_do_handshake.
    // Try exported symbols first (cheaper), then fall back to non-exported
    for (const sym of ["SSL_do_handshake", "SSL_connect", "SSL_accept"]) {
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
            attachHandshakeTracker(hookAddr);
            devlog(`[LibreSSL] Handshake tracker installed on ${sym}`);
        }
    }
}

function getThreadClientRandom(SSL_get_client_random: NativeFunction<any, any> | undefined): string | null {
    return resolveLibreSslClientRandom(SSL_get_client_random, currentHandshakeSsl());
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
        "SSL_accept",
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
        clientRandomDecoder: openSslClientRandomDecoder,
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
