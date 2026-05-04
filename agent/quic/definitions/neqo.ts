// agent/quic/definitions/neqo.ts
//
// Data-driven Mozilla Neqo (Firefox HTTP/3) hook definition.
// Hooks neqo_glue FFI boundary in libxul for plaintext HTTP/3 stream capture.
//
// Key functions:
//   neqo_http3conn_new                   — connection creation with addresses
//   neqo_http3conn_read_response_data    — plaintext response body read
//   neqo_htttp3conn_send_request_body    — plaintext request body send (triple 't' typo!)
//   neqo_http3conn_close                 — connection teardown
//
// NSS handles keylogging — neqo uses NSS for its TLS layer, so friTap's
// existing NSS hooks capture QUIC TLS keys automatically.

import { HookDefinition, ExtraHookDef } from "../../core/hook_definition.js";
import { sendQuicDatalog, sendConnectionLifecycle } from "../../shared/shared_structures.js";
import { log, devlog } from "../../util/log.js";
import { quicConnectionTracker, buildQuicMessage, QuicConnectionInfo } from "../shared/quic_connection_tracker.js";
import { findNonExportedSymbols } from "../../shared/shared_functions.js";


// --- Helpers -----------------------------------------------------------------

/**
 * Batch-resolve all neqo symbols using a multi-strategy approach.
 * Returns a map of symbolName → NativePointer for found symbols.
 *
 * Strategies tried in order:
 * 1. Export table (works on Android/Linux/Windows)
 * 2. Symbol table via single enumerateSymbols() pass (works on macOS if not stripped)
 * 3. DebugSymbol (works if debug info is available)
 */
function resolveNeqoSymbols(
    moduleName: string,
    symbolNames: string[],
): Map<string, NativePointer> {
    const resolved = new Map<string, NativePointer>();
    const remaining: string[] = [];

    // Strategy 1: export table
    for (const name of symbolNames) {
        const addr = (Module as any).findExportByName(moduleName, name) as NativePointer | null;
        if (addr && !addr.isNull()) {
            resolved.set(name, addr);
        } else {
            remaining.push(name);
        }
    }
    if (remaining.length === 0) return resolved;

    // Strategy 2: single batch symbol table enumeration (includes macOS underscore variants)
    const withUnderscores = remaining.flatMap(n => [n, "_" + n]);
    const symResults = findNonExportedSymbols(moduleName, withUnderscores);
    for (const name of remaining) {
        const addr = symResults.get(name) || symResults.get("_" + name);
        if (addr && !addr.isNull()) {
            devlog("[neqo] found " + name + " via symbol table");
            resolved.set(name, addr);
        }
    }

    // Strategy 3: DebugSymbol for any still-unresolved
    for (const name of remaining) {
        if (resolved.has(name)) continue;
        try {
            const matches = DebugSymbol.findFunctionsNamed(name);
            if (matches.length > 0) {
                devlog("[neqo] found " + name + " via DebugSymbol");
                resolved.set(name, matches[0]);
            }
        } catch (_e) { /* DebugSymbol may not be available */ }
    }

    return resolved;
}

/** Cache of resolved symbols, populated once per module at install time. */
let resolvedSymbolCache: Map<string, NativePointer> | null = null;

/**
 * Look up a single neqo symbol from the cache, populating it on first call.
 * All symbols are resolved in a single batch to avoid repeated 152MB module enumeration.
 */
function resolveNeqoSymbol(moduleName: string, symbolName: string): NativePointer | null {
    if (!resolvedSymbolCache) {
        resolvedSymbolCache = resolveNeqoSymbols(moduleName, [
            "neqo_http3conn_new",
            "neqo_http3conn_read_response_data",
            "neqo_htttp3conn_send_request_body",
            "neqo_http3conn_send_request_body",
            "neqo_http3conn_close",
        ]);
    }
    return resolvedSymbolCache.get(symbolName) || null;
}

/**
 * Parse Mozilla's NetAddr union into IP:port.
 *
 * NetAddr layout (from netwerk/dns/DNS.h):
 *   offset 0: u16 family  (AF_INET=2, AF_INET6=10 on Linux / 30 on macOS)
 *   offset 2: u16 port    (network byte order)
 *   AF_INET:  offset 4: u32 IPv4 address (network byte order)
 *   AF_INET6: offset 4: u32 flowinfo, offset 8: u8[16] IPv6 address
 */
function parseNetAddr(ptr: NativePointer): { addr: string; port: number; family: string } {
    const sentinel = { addr: "0.0.0.0", port: 0, family: "AF_INET" };
    if (ptr.isNull()) return sentinel;

    try {
        const family = ptr.readU16();

        // Validate family to detect signature changes
        if (family !== 2 && family !== 10 && family !== 30) {
            devlog("[neqo] unexpected NetAddr family: " + family);
            return sentinel;
        }

        // Port at offset 2 (network byte order → host byte order)
        const portRaw = ptr.add(2).readU16();
        const port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);

        if (family === 2) {
            // AF_INET: IPv4 address at offset 4
            const a = ptr.add(4).readU8();
            const b = ptr.add(5).readU8();
            const c = ptr.add(6).readU8();
            const d = ptr.add(7).readU8();
            return { addr: a + "." + b + "." + c + "." + d, port, family: "AF_INET" };
        }

        // AF_INET6 (family 10 on Linux, 30 on macOS): IPv6 address at offset 8
        const addrBytes = ptr.add(8).readByteArray(16);
        if (addrBytes) {
            const hex = Array.from(new Uint8Array(addrBytes))
                .map(b => b.toString(16).padStart(2, "0"))
                .join("");
            const groups: string[] = [];
            for (let i = 0; i < 32; i += 4) {
                groups.push(hex.substring(i, i + 4));
            }
            return { addr: groups.join(":"), port, family: "AF_INET6" };
        }
    } catch (e) {
        devlog("[neqo] failed to parse NetAddr: " + e);
    }
    return sentinel;
}

/** Default sentinel connection info when tracker lookup fails. */
const UNKNOWN_CONNECTION: QuicConnectionInfo = {
    serverName: "",
    localAddr: "0.0.0.0",
    localPort: 0,
    peerAddr: "0.0.0.0",
    peerPort: 0,
    ssFamily: "AF_INET",
    scid: "",
    dcid: "",
};


// --- Extra Hook Factories ----------------------------------------------------

/**
 * Hook neqo_http3conn_new — connection creation.
 *
 * Signature (18 params):
 *   neqo_http3conn_new(origin, alpn, local_addr, remote_addr,
 *     max_table_size, max_blocked_streams, max_data, max_stream_data,
 *     version_negotiation, webtransport, qlog_dir, provider_flags,
 *     idle_timeout, fast_pto, socket, pmtud_enabled, result) -> nsresult
 *
 * We need: local_addr (arg2), remote_addr (arg3), result (last arg).
 */
function createNeqoConnNewHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            let addr = addresses[moduleName]?.["neqo_http3conn_new"];
            if (!addr || addr.isNull()) {
                addr = resolveNeqoSymbol(moduleName, "neqo_http3conn_new");
            }
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    // local_addr and remote_addr are always in registers (arg2, arg3)
                    this.localAddr = parseNetAddr(args[2]);
                    this.remoteAddr = parseNetAddr(args[3]);
                    // result out-param is the last argument (arg16 on 64-bit)
                    this.resultPtr = args[16];
                },
                onLeave(retval) {
                    if (this.resultPtr === undefined) return;
                    // NS_OK = 0
                    if (retval.toUInt32() !== 0) return;

                    try {
                        const connPtr = this.resultPtr.readPointer();
                        if (connPtr.isNull()) return;

                        const connKey = connPtr.toString();
                        const info: QuicConnectionInfo = {
                            serverName: "",
                            localAddr: this.localAddr.addr,
                            localPort: this.localAddr.port,
                            peerAddr: this.remoteAddr.addr,
                            peerPort: this.remoteAddr.port,
                            ssFamily: this.remoteAddr.family,
                            scid: "",
                            dcid: "",
                        };
                        quicConnectionTracker.register(connKey, info);
                        sendConnectionLifecycle("created", buildQuicMessage(info, connKey, "neqo_http3conn_new"));
                    } catch (e) {
                        devlog("[neqo] failed to register connection: " + e);
                    }
                },
            });
            log("[*] Hooked neqo_http3conn_new for connection tracking");
        },
    };
}

/**
 * Hook neqo_http3conn_read_response_data — plaintext response capture.
 *
 * Signature:
 *   neqo_http3conn_read_response_data(conn, stream_id: u64, buf, len: u32,
 *     read: *mut u32, fin: *mut bool) -> nsresult
 *
 * On 64-bit: args[0]=conn, args[1]=stream_id, args[2]=buf, args[3]=len,
 *            args[4]=read, args[5]=fin
 */
function createNeqoReadResponseHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            let addr = addresses[moduleName]?.["neqo_http3conn_read_response_data"];
            if (!addr || addr.isNull()) {
                addr = resolveNeqoSymbol(moduleName, "neqo_http3conn_read_response_data");
            }
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    this.conn = args[0];
                    this.streamId = args[1].toUInt32();
                    this.buf = args[2];
                    this.len = args[3].toUInt32();
                    this.readPtr = args[4];
                    this.finPtr = args[5];
                },
                onLeave(retval) {
                    if (this.buf === undefined) return;
                    // NS_OK = 0
                    if (retval.toUInt32() !== 0) return;

                    try {
                        const bytesRead = Math.min(this.readPtr.readU32(), this.len);
                        if (bytesRead <= 0) return;

                        const data = this.buf.readByteArray(bytesRead);
                        const connKey = this.conn.toString();
                        const connInfo = quicConnectionTracker.get(connKey) || UNKNOWN_CONNECTION;
                        const message = buildQuicMessage(connInfo, connKey, "neqo_read_response_data");

                        sendQuicDatalog(message, data, this.streamId, connInfo.scid, connInfo.dcid);

                        // Check fin flag (Rust bool is 1 byte)
                        if (this.finPtr && !this.finPtr.isNull()) {
                            if (this.finPtr.readU8() !== 0) {
                                sendConnectionLifecycle("stream_fin", {
                                    ...message,
                                    stream_id: this.streamId,
                                });
                            }
                        }
                    } catch (e) {
                        devlog("[neqo] read_response_data hook error: " + e);
                    }
                },
            });
            log("[*] Hooked neqo_http3conn_read_response_data for plaintext capture");
        },
    };
}

/**
 * Hook neqo_htttp3conn_send_request_body — plaintext request capture.
 *
 * IMPORTANT: The function name has a triple 't' typo in Mozilla's source code.
 * We try both the typo and correct spelling for forward compatibility.
 *
 * Signature:
 *   neqo_htttp3conn_send_request_body(conn, stream_id: u64, buf, len: u32,
 *     read: *mut u32) -> nsresult
 *
 * On 64-bit: args[0]=conn, args[1]=stream_id, args[2]=buf, args[3]=len,
 *            args[4]=read
 */
function createNeqoSendRequestBodyHook(): ExtraHookDef {
    // Both spellings: triple 't' typo (current Mozilla source) + correct (forward compat)
    const SEND_CANDIDATES = [
        "neqo_htttp3conn_send_request_body",
        "neqo_http3conn_send_request_body",
    ];

    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            let addr: NativePointer | null = null;
            let resolvedName = "";

            for (const name of SEND_CANDIDATES) {
                addr = addresses[moduleName]?.[name];
                if (addr && !addr.isNull()) { resolvedName = name; break; }
                addr = resolveNeqoSymbol(moduleName, name);
                if (addr) { resolvedName = name; break; }
            }
            if (!addr) return;

            devlog("[neqo] resolved send_request_body as: " + resolvedName);

            Interceptor.attach(addr, {
                onEnter(args) {
                    this.conn = args[0];
                    this.streamId = args[1].toUInt32();
                    const buf = args[2];
                    const len = args[3].toUInt32();
                    this.readPtr = args[4];
                    // Read data NOW before the function consumes it
                    if (!buf.isNull() && len > 0) {
                        try {
                            this.data = buf.readByteArray(len);
                            this.dataLen = len;
                        } catch (e) {
                            devlog("[neqo] failed to read send buffer: " + e);
                        }
                    }
                },
                onLeave(retval) {
                    if (this.data === undefined) return;
                    if (retval.toUInt32() !== 0) return;

                    try {
                        const bytesSent = this.readPtr.readU32();
                        if (bytesSent <= 0) return;

                        // Use the pre-captured data, truncated to actual bytes sent
                        const data = (bytesSent < this.dataLen)
                            ? this.data.slice(0, bytesSent)
                            : this.data;

                        const connKey = this.conn.toString();
                        const connInfo = quicConnectionTracker.get(connKey) || UNKNOWN_CONNECTION;
                        const message = buildQuicMessage(connInfo, connKey, "neqo_send_request_body");

                        sendQuicDatalog(message, data, this.streamId, connInfo.scid, connInfo.dcid);
                    } catch (e) {
                        devlog("[neqo] send_request_body hook error: " + e);
                    }
                },
            });
            log("[*] Hooked " + resolvedName + " for plaintext capture");
        },
    };
}

/**
 * Hook neqo_http3conn_close — connection teardown.
 *
 * Signature:
 *   neqo_http3conn_close(conn, error: u64) -> void
 */
function createNeqoCloseHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            let addr = addresses[moduleName]?.["neqo_http3conn_close"];
            if (!addr || addr.isNull()) {
                addr = resolveNeqoSymbol(moduleName, "neqo_http3conn_close");
            }
            if (!addr) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    const connKey = args[0].toString();
                    const info = quicConnectionTracker.remove(connKey);
                    if (info) {
                        sendConnectionLifecycle("destroyed", buildQuicMessage(info, connKey, "neqo_http3conn_close"));
                    }
                },
            });
            log("[*] Hooked neqo_http3conn_close for connection cleanup");
        },
    };
}


// --- Definition Factory ------------------------------------------------------

export function createNeqoDefinition(): HookDefinition {
    return {
        libraryId: "neqo",
        offsetKey: "neqo",
        functions: {
            librarySymbols: [
                "neqo_http3conn_new",
                "neqo_http3conn_read_response_data",
                "neqo_htttp3conn_send_request_body",    // triple 't' typo in Mozilla source!
                "neqo_http3conn_send_request_body",     // correct spelling fallback
                "neqo_http3conn_close",
            ],
            socketSymbols: [],
        },
        nativeFunctions: [],
        fdDecoder: (_ctx, _fns) => -1,
        sessionIdDecoder: (ctx) => ctx.toString(),
        keylog: { kind: "none" },       // NSS handles keylogging for QUIC
        extraHooks: [
            createNeqoConnNewHook(),
            createNeqoReadResponseHook(),
            createNeqoSendRequestBodyHook(),
            createNeqoCloseHook(),
        ],
    };
}
