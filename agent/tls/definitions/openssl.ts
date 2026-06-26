// agent/tls/definitions/openssl.ts
//
// Data-driven OpenSSL/BoringSSL hook definition.
// Covers common read/write/fd/session patterns.
// Platform-specific keylog and key extraction stays in platform execute functions.

import { HookDefinition, ResolvedFunctions, KeylogApproach, ExtraHookDef } from "../../core/hook_definition.js";
import { log, devlog, devlog_error, devlog_debug } from "../../util/log.js";
import { sendKeylog, sendDatalog } from "../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { enable_default_fd, pcap_enabled, pairip_safe } from "../../fritap_agent.js";
import { registerBlinkTarget, PAIRIP_BLINK_ENABLED } from "../../shared/pairip_blink.js";
import { STANDARD_SOCKET_SYMBOLS, DUMMY_SESSION_ID_OPENSSL } from "./shared_constants.js";
import { createLifecycleHook, createBufferedClientRandomDecoder } from "./shared_factories.js";
import { installBoringSSLSymbolHook, makeBoringSslDumpKeys, DumpKeysCb } from "../../shared/boringssl_symbol_hook.js";

export function openSslFdDecoder(ssl: NativePointer, fns: ResolvedFunctions): number {
    if (!fns["SSL_get_fd"]) return -1;
    return fns["SSL_get_fd"](ssl) as number;
}

// Pre-allocated buffer for session ID length (reused across calls)
export const _sessionIdLenPtr = Memory.alloc(4);

export function openSslSessionIdDecoder(ssl: NativePointer, fns: ResolvedFunctions): string {
    if (!fns["SSL_get_session"] || !fns["SSL_SESSION_get_id"]) {
        if (enable_default_fd) {
            return DUMMY_SESSION_ID_OPENSSL;
        }
        return "";
    }
    const session = fns["SSL_get_session"](ssl) as NativePointer;
    if (session.isNull()) {
        if (enable_default_fd) {
            log("using dummy SessionID: " + DUMMY_SESSION_ID_OPENSSL);
            return DUMMY_SESSION_ID_OPENSSL;
        }
        return "";
    }
    const idPtr = fns["SSL_SESSION_get_id"](session, _sessionIdLenPtr) as NativePointer;
    const len = _sessionIdLenPtr.readU32();
    if (len === 0 || idPtr.isNull()) return "";
    return readHexFromPointer(idPtr, len);
}

export const openSslClientRandomDecoder = createBufferedClientRandomDecoder("SSL_get_client_random");

export interface OpenSslDefOptions {
    includeExSymbols?: boolean;
    skipReadWriteHooks?: boolean;
}

export function createOpenSslDefinition(options?: OpenSslDefOptions): HookDefinition {
    const includeEx = options?.includeExSymbols ?? false;
    const skipRW = options?.skipReadWriteHooks ?? false;

    const librarySymbols = [
        "SSL_read",
        "SSL_write",
        "SSL_get_fd",
        "SSL_get_session",
        "SSL_SESSION_get_id",
        "SSL_new",
        "SSL_CTX_set_keylog_callback",
        "SSL_get_client_random",
        "SSL_free",
    ];
    if (includeEx) {
        librarySymbols.push("SSL_read_ex", "SSL_write_ex", "SSL_CTX_new");
    }

    const def: HookDefinition = {
        libraryId: "openssl",
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
        ],
        fdDecoder: openSslFdDecoder,
        sessionIdDecoder: openSslSessionIdDecoder,
        clientRandomDecoder: openSslClientRandomDecoder,
        keylog: { kind: "none" },
    };

    if (!skipRW) {
        def.readHook = {
            symbol: "SSL_read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "SSL_read",
        };
        def.writeHook = {
            symbol: "SSL_write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "SSL_write",
        };
    }

    def.extraHooks = [
        ...(def.extraHooks || []),
        createLifecycleHook("SSL_free", openSslFdDecoder, openSslSessionIdDecoder, openSslClientRandomDecoder),
    ];

    return def;
}

export function createBoringSSLKeylogApproach(): KeylogApproach {
    return {
        kind: "custom",
        install: (addresses, modName, resolvedFns, _enableDefaultFd) => {
            const setKeylogAddr = addresses[modName]?.["SSL_CTX_set_keylog_callback"];
            if (!setKeylogAddr || setKeylogAddr.isNull()) {
                devlog_debug(`[boringssl-cb] ${modName}: SSL_CTX_set_keylog_callback unresolved, skipping callback tier`);
                return false;
            }

            const keylogCb = new NativeCallback(
                function (_ssl: NativePointer, line: NativePointer) {
                    devlog(`invoking keylog_callback from OpenSSL_BoringSSL (${modName})`);
                    sendKeylog(line.readCString());
                },
                "void",
                ["pointer", "pointer"],
            );

            const setKeylogOn = resolvedFns["SSL_CTX_set_keylog_callback"];
            const sslNewAddr = addresses[modName]?.["SSL_new"];
            const ctxNewAddr = addresses[modName]?.["SSL_CTX_new"];
            const canSslNew = !!(sslNewAddr && !sslNewAddr.isNull() && setKeylogOn);
            const canCtxNew = !!(ctxNewAddr && !ctxNewAddr.isNull() && setKeylogOn);

            // Tier 1 success requires at least one of SSL_new / SSL_CTX_new — the
            // set_keylog_callback intercept only fires when the app installs its own
            // callback, which isn't a reliable trigger.
            if (!canSslNew && !canCtxNew) return false;

            // (Re-)attach the inline keylog hooks; returns the listeners so the
            // pairip-safe blink loop can detach/re-attach them (keeping .text
            // pristine between blinks while the heap-resident keylog callback
            // keeps firing). In normal mode this just attaches once.
            const attachAll = (): InvocationListener[] => {
                const ls: InvocationListener[] = [];
                if (canSslNew) {
                    ls.push(Interceptor.attach(sslNewAddr!, {
                        onEnter: function (args: any) {
                            try { setKeylogOn!(args[0], keylogCb); }
                            catch (e) { devlog_error(`[modern] Error in SSL_new keylog hook: ${e}`); }
                        },
                    }));
                }
                if (canCtxNew) {
                    ls.push(Interceptor.attach(ctxNewAddr!, {
                        onLeave: function (retval: any) {
                            if (retval.isNull()) return;
                            try { setKeylogOn!(retval, keylogCb); }
                            catch (e) { devlog_error(`[modern] Error in SSL_CTX_new keylog hook: ${e}`); }
                        },
                    }));
                }
                ls.push(Interceptor.attach(setKeylogAddr, {
                    onEnter: function (args: any) {
                        const userCb = args[1];
                        if (!userCb.isNull()) {
                            Interceptor.attach(userCb, {
                                onEnter: function (innerArgs: any) {
                                    devlog(`invoking user-installed keylog_callback from OpenSSL_BoringSSL (${modName})`);
                                    sendKeylog(innerArgs[1].readCString());
                                },
                            });
                        }
                    },
                }));
                return ls;
            };

            if (pairip_safe && PAIRIP_BLINK_ENABLED) {
                // Blink: register (roots keylogCb, first BRIGHT attach, schedules toggling).
                registerBlinkTarget(modName, keylogCb, attachAll);
            } else {
                attachAll();
            }

            log(`[*] ${modName}: keylog hooks installed via SSL_CTX_set_keylog_callback (SSL_new=${canSslNew}, SSL_CTX_new=${canCtxNew})`);
            return true;
        },
    };
}

/**
 * Symbol-based fallback that hooks bssl::ssl_log_secret directly.
 *
 * Use as a complementary KeylogApproach when the public
 * SSL_CTX_set_keylog_callback API can't be installed (stripped builds,
 * customised forks, etc.). The loader auto-wires this for any HookDefinition
 * tagged libraryType: "boringssl" — see executeFromDefinition() in
 * agent/core/loader.ts. You can also pass it explicitly as def.keylog when
 * the lib has no usable public keylog API at all.
 */
export function createBoringSSLSslLogSecretFallback(dumpKeys?: DumpKeysCb): KeylogApproach {
    return {
        kind: "custom",
        install: (_addresses, modName, _resolvedFns, _enableDefaultFd) => {
            return installBoringSSLSymbolHook(modName, dumpKeys ?? makeBoringSslDumpKeys(modName));
        },
    };
}

export function createSslReadWriteExHooks(): ExtraHookDef[] {
    return [
        {
            install: (addresses, modName, resolvedFns, enableDefaultFd) => {
                if (!pcap_enabled) return;
                // SSL_read_ex
                const readExAddr = addresses[modName]?.["SSL_read_ex"];
                if (readExAddr && !readExAddr.isNull()) {
                    Interceptor.attach(readExAddr, {
                        onEnter: function (args: any) {
                            const ssl = args[0];
                            const fd = resolvedFns["SSL_get_fd"]?.(ssl) as number ?? -1;
                            const message = getPortsAndAddresses(fd, true, addresses[modName], enableDefaultFd);
                            if (message === null) return;
                            message["ssl_session_id"] = openSslSessionIdDecoder(ssl, resolvedFns);
                            message["client_random"] = openSslClientRandomDecoder(ssl, resolvedFns);
                            message["function"] = "SSL_read_ex";
                            this.message = message;
                            this.buf = args[1];
                            this.readbytes = args[3]; // pointer to actual bytes read
                        },
                        onLeave: function (retval: any) {
                            if (!this.message) return;
                            const actualBytes = this.readbytes.readU32();
                            if (actualBytes <= 0) return;
                            sendDatalog(this.message, this.buf.readByteArray(actualBytes));
                        },
                    });
                }

                // SSL_write_ex
                const writeExAddr = addresses[modName]?.["SSL_write_ex"];
                if (writeExAddr && !writeExAddr.isNull()) {
                    Interceptor.attach(writeExAddr, {
                        onEnter: function (args: any) {
                            const ssl = args[0];
                            const fd = resolvedFns["SSL_get_fd"]?.(ssl) as number ?? -1;
                            const message = getPortsAndAddresses(fd, false, addresses[modName], enableDefaultFd);
                            if (message === null) return;
                            message["ssl_session_id"] = openSslSessionIdDecoder(ssl, resolvedFns);
                            message["client_random"] = openSslClientRandomDecoder(ssl, resolvedFns);
                            message["function"] = "SSL_write_ex";
                            const buf = args[1];
                            const bufLen = parseInt(args[2]);
                            sendDatalog(message, buf.readByteArray(bufLen));
                        },
                    });
                }
            },
        },
    ];
}
