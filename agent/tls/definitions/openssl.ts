// agent/tls/definitions/openssl.ts
//
// Data-driven OpenSSL/BoringSSL hook definition.
// Covers common read/write/fd/session patterns.
// Platform-specific keylog and key extraction stays in platform execute functions.

import { HookDefinition, ResolvedFunctions, KeylogApproach, ExtraHookDef } from "../../core/hook_definition.js";
import { log, devlog_error } from "../../util/log.js";
import { sendKeylog, sendDatalog } from "../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { enable_default_fd } from "../../fritap_agent.js";
import { STANDARD_SOCKET_SYMBOLS, DUMMY_SESSION_ID_OPENSSL } from "./shared_constants.js";

function openSslFdDecoder(ssl: NativePointer, fns: ResolvedFunctions): number {
    if (!fns["SSL_get_fd"]) return -1;
    return fns["SSL_get_fd"](ssl) as number;
}

// Pre-allocated buffer for session ID length (reused across calls)
const _sessionIdLenPtr = Memory.alloc(4);

function openSslSessionIdDecoder(ssl: NativePointer, fns: ResolvedFunctions): string {
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
        ],
        fdDecoder: openSslFdDecoder,
        sessionIdDecoder: openSslSessionIdDecoder,
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

    return def;
}

export function createBoringSSLKeylogApproach(): KeylogApproach {
    return {
        kind: "custom",
        install: (addresses, modName, resolvedFns, _enableDefaultFd) => {
            const keylogCb = new NativeCallback(
                function (_ssl: NativePointer, line: NativePointer) {
                    sendKeylog(line.readCString());
                },
                "void",
                ["pointer", "pointer"],
            );

            // Hook SSL_new to set keylog callback on the SSL_CTX passed as arg[0]
            const sslNewAddr = addresses[modName]?.["SSL_new"];
            if (sslNewAddr && !sslNewAddr.isNull() && resolvedFns["SSL_CTX_set_keylog_callback"]) {
                Interceptor.attach(sslNewAddr, {
                    onEnter: function (args: any) {
                        try {
                            resolvedFns["SSL_CTX_set_keylog_callback"](args[0], keylogCb);
                        } catch (e) {
                            devlog_error(`[modern] Error in SSL_new keylog hook: ${e}`);
                        }
                    },
                });
            }

            // Fallback: hook SSL_CTX_new to set callback on newly created contexts
            const ctxNewAddr = addresses[modName]?.["SSL_CTX_new"];
            if (ctxNewAddr && !ctxNewAddr.isNull() && resolvedFns["SSL_CTX_set_keylog_callback"]) {
                Interceptor.attach(ctxNewAddr, {
                    onLeave: function (retval: any) {
                        if (retval.isNull()) return;
                        try {
                            resolvedFns["SSL_CTX_set_keylog_callback"](retval, keylogCb);
                        } catch (e) {
                            devlog_error(`[modern] Error in SSL_CTX_new keylog hook: ${e}`);
                        }
                    },
                });
            }

            // Intercept application-set keylog callbacks
            const setKeylogAddr = addresses[modName]?.["SSL_CTX_set_keylog_callback"];
            if (setKeylogAddr && !setKeylogAddr.isNull()) {
                Interceptor.attach(setKeylogAddr, {
                    onEnter: function (args: any) {
                        const userCb = args[1];
                        if (!userCb.isNull()) {
                            Interceptor.attach(userCb, {
                                onEnter: function (innerArgs: any) {
                                    sendKeylog(innerArgs[1].readCString());
                                },
                            });
                        }
                    },
                });
            }
        },
    };
}

export function createSslReadWriteExHooks(): ExtraHookDef[] {
    return [
        {
            install: (addresses, modName, resolvedFns, enableDefaultFd) => {
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
