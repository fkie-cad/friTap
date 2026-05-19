// agent/tls/definitions/matrixssl.ts
//
// Data-driven MatrixSSL hook definition.
//
// MatrixSSL exposes no keylog API, so this definition is PCAP-only:
//   keylog: { kind: "none" } — no SSLKEYLOGFILE output
//
// Two wrinkles vs. the SSL_read/SSL_write shape used by openssl.ts:
//   1. The write path is two-phase: matrixSslGetWritebuf produces a buffer
//      pointer, the caller fills it, then matrixSslEncodeWritebuf commits.
//      Plaintext is final only at the second call. Modelled via extraHooks
//      so we don't need a new HookDefinition variant.
//   2. The read path's retval is a MATRIXSSL_* status code, not a byte
//      count. Legacy code (agent/legacy/tls/libs/matrixssl.ts) reads bytes
//      whenever retval > 0; we preserve that semantic via extraHooks too.

import {
    HookDefinition,
    ResolvedFunctions,
    ExtraHookDef,
} from "../../core/hook_definition.js";
import { sendDatalog } from "../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { devlog } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";

// MatrixSSL exposes no fd getter. Returning -1 routes downstream metadata
// through the enable_default_fd path (synthetic 5-tuple). Matches legacy
// behaviour: legacy never wired `this.fd` inside the read/write
// interceptors either.
function matrixSslFdDecoder(_ssl: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}

// matrixSslGetSid(ssl) returns psSessionId_t* with layout (per legacy
// matrixssl.ts:152-157):
//   pointerSize     : pointer to id bytes
//   2 * pointerSize : id_len (uint32)
function matrixSslSessionIdDecoder(ssl: NativePointer, fns: ResolvedFunctions): string {
    const getSid = fns["matrixSslGetSid"];
    if (!getSid) return "";
    try {
        const sid = getSid(ssl) as NativePointer;
        if (sid.isNull()) return "";
        const idLen = sid.add(2 * Process.pointerSize).readU32();
        if (idLen === 0 || idLen > 64) return "";
        const idPtr = sid.add(Process.pointerSize).readPointer();
        if (idPtr.isNull()) return "";
        const str = idPtr.readCString(idLen);
        return str ?? "";
    } catch (e) {
        devlog(`[matrixssl] sessionId decode failed: ${e}`);
        return "";
    }
}

function createMatrixSslReadHook(): ExtraHookDef {
    return {
        install: (addresses, modName, resolvedFns, enableDefaultFd) => {
            if (!pcap_enabled) return;
            const moduleAddrs = addresses[modName];
            const addr = moduleAddrs?.["matrixSslReceivedData"];
            if (!addr || addr.isNull()) {
                devlog("[matrixssl] matrixSslReceivedData unresolved – read capture disabled");
                return;
            }

            Interceptor.attach(addr, {
                onEnter: function (args: any) {
                    this.ssl = args[0];
                    // Mirror legacy semantics: args[2] = plaintext buffer,
                    // args[3] = output length pointer (legacy treated it as
                    // a numeric length — preserved here to avoid behaviour
                    // change). See agent/legacy/tls/libs/matrixssl.ts:53-54.
                    this.buffer = args[2];
                    this.len = args[3];
                },
                onLeave: function (retval: any) {
                    retval |= 0;
                    if (retval <= 0) return;
                    try {
                        const data = this.buffer.readByteArray(this.len);
                        const message = getPortsAndAddresses(-1, true, moduleAddrs, enableDefaultFd);
                        if (message === null) return;
                        message["ssl_session_id"] =
                            matrixSslSessionIdDecoder(this.ssl, resolvedFns);
                        message["function"] = "matrixSslReceivedData";
                        sendDatalog(message, data);
                    } catch (e) {
                        devlog(`[matrixssl] read capture error: ${e}`);
                    }
                },
            });
        },
    };
}

function createMatrixSslWriteHooks(): ExtraHookDef {
    return {
        install: (addresses, modName, resolvedFns, enableDefaultFd) => {
            if (!pcap_enabled) return;
            const moduleAddrs = addresses[modName];
            const getBufAddr = moduleAddrs?.["matrixSslGetWritebuf"];
            const encodeAddr = moduleAddrs?.["matrixSslEncodeWritebuf"];
            if (!getBufAddr || getBufAddr.isNull()) {
                devlog("[matrixssl] matrixSslGetWritebuf unresolved – write capture disabled");
                return;
            }
            if (!encodeAddr || encodeAddr.isNull()) {
                devlog("[matrixssl] matrixSslEncodeWritebuf unresolved – write capture disabled");
                return;
            }

            // Per-thread state. GetWritebuf and EncodeWritebuf are called
            // back-to-back on the same thread per MatrixSSL's documented usage.
            const pending: Map<number, { ssl: NativePointer; buf: NativePointer; len: number }> = new Map();

            Interceptor.attach(getBufAddr, {
                onEnter: function (args: any) {
                    this.ssl = args[0];
                    this.outBuffer = args[1];
                },
                onLeave: function (retval: any) {
                    retval |= 0;
                    if (retval <= 0) return;
                    pending.set(Process.getCurrentThreadId(), {
                        ssl: this.ssl,
                        buf: this.outBuffer,
                        len: retval,
                    });
                },
            });

            Interceptor.attach(encodeAddr, {
                onEnter: function (args: any) {
                    const tid = Process.getCurrentThreadId();
                    const state = pending.get(tid);
                    if (!state) return;
                    pending.delete(tid);
                    try {
                        const data = state.buf.readByteArray(state.len);
                        const message = getPortsAndAddresses(-1, false, moduleAddrs, enableDefaultFd);
                        if (message === null) return;
                        message["ssl_session_id"] =
                            matrixSslSessionIdDecoder(state.ssl, resolvedFns);
                        message["function"] = "matrixSslEncodeWritebuf";
                        sendDatalog(message, data);
                    } catch (e) {
                        devlog(`[matrixssl] write capture error: ${e}`);
                    }
                },
            });
        },
    };
}

export function createMatrixSslDefinition(): HookDefinition {
    return {
        libraryId: "matrixssl",
        offsetKey: "matrixssl",
        functions: {
            librarySymbols: [
                "matrixSslReceivedData",
                "matrixSslGetWritebuf",
                "matrixSslEncodeWritebuf",
                "matrixSslGetSid",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            { symbol: "matrixSslGetSid", retType: "pointer", argTypes: ["pointer"] },
        ],
        fdDecoder: matrixSslFdDecoder,
        sessionIdDecoder: matrixSslSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        // readHook / writeHook intentionally undefined; capture is done via
        // extraHooks because MatrixSSL's ABI doesn't fit the generic
        // single-symbol read/write executor.
        keylog: { kind: "none" },
        extraHooks: [
            createMatrixSslReadHook(),
            createMatrixSslWriteHooks(),
        ],
        libraryType: "matrixssl",
    };
}
