// agent/quic/definitions/quiche.ts
//
// Data-driven Cloudflare quiche hook definition.
// Hooks stream-level plaintext and injects keylog via pipe fd.

import { HookDefinition, ExtraHookDef, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendQuicDatalog, sendQuicKeylog, sendConnectionLifecycle } from "../../shared/shared_structures.js";
import { log, devlog, devlog_error } from "../../util/log.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { quicConnectionTracker, buildQuicMessage, QuicConnectionInfo } from "../shared/quic_connection_tracker.js";
import { readHexFromPointer } from "../../tls/decoders/hex_utils.js";

/** Mutable ref to resolved NativeFunctions, shared by ExtraHookDef closures. */
interface ResolvedRef {
    configLogKeys: NativeFunction<void, [NativePointer]> | null;
    setKeylogFd: NativeFunction<void, [NativePointer, number]> | null;
}

// --- Helpers for parsing sockaddr from quiche_connect/accept args ---

/**
 * Parse a struct sockaddr into IP:port.
 * Supports AF_INET (family=2) and AF_INET6 (family=10/30).
 */
function parseSockaddr(ptr: NativePointer, len: number): { addr: string; port: number; family: string } {
    if (ptr.isNull() || len < 4) {
        return { addr: "0.0.0.0", port: 0, family: "AF_INET" };
    }
    const family = ptr.readU16();
    if (family === 2 && len >= 16) {
        // AF_INET: { u16 family, u16 port(network), u8[4] addr }
        const port = ptr.add(2).readU16();
        // Port is in network byte order (big endian)
        const portHost = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
        const a = ptr.add(4).readU8();
        const b = ptr.add(5).readU8();
        const c = ptr.add(6).readU8();
        const d = ptr.add(7).readU8();
        return { addr: a + "." + b + "." + c + "." + d, port: portHost, family: "AF_INET" };
    }
    if ((family === 10 || family === 30) && len >= 28) {
        // AF_INET6: { u16 family, u16 port(network), u32 flowinfo, u8[16] addr }
        const port = ptr.add(2).readU16();
        const portHost = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF);
        const addrBytes = ptr.add(8).readByteArray(16);
        if (addrBytes) {
            const hex = Array.from(new Uint8Array(addrBytes))
                .map(b => b.toString(16).padStart(2, "0"))
                .join("");
            // Group into IPv6 notation
            const groups: string[] = [];
            for (let i = 0; i < 32; i += 4) {
                groups.push(hex.substring(i, i + 4));
            }
            return { addr: groups.join(":"), port: portHost, family: "AF_INET6" };
        }
    }
    return { addr: "0.0.0.0", port: 0, family: "AF_INET" };
}

/**
 * Create the extra hook that tracks connections from quiche_connect().
 *
 * quiche_connect(server_name, scid, scid_len, local, local_len, peer, peer_len, config)
 *               -> quiche_conn*
 */
function createConnectTracker(ref: ResolvedRef,
                               keylogPipeWriteFd: number): ExtraHookDef {
    return {
        install(addresses, moduleName, resolvedFns, _enableDefaultFd) {
            const addr = addresses[moduleName]?.["quiche_connect"];
            if (!addr || addr.isNull()) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    this.serverName = args[0].isNull() ? "" : (args[0].readCString() || "");
                    const scidPtr = args[1];
                    const scidLen = args[2].toUInt32();
                    this.scid = (scidLen > 0 && !scidPtr.isNull())
                        ? readHexFromPointer(scidPtr, scidLen) : "";
                    // Parse local address (args[3] = local sockaddr, args[4] = local_len)
                    const localPtr = args[3];
                    const localLen = args[4].toUInt32();
                    this.local = parseSockaddr(localPtr, localLen);
                    // Parse peer address (args[5] = peer sockaddr, args[6] = peer_len)
                    const peerPtr = args[5];
                    const peerLen = args[6].toUInt32();
                    this.peer = parseSockaddr(peerPtr, peerLen);
                    // Config is args[7] - enable keylog
                    this.config = args[7];
                },
                onLeave(retval) {
                    if (retval.isNull()) return;
                    const connKey = retval.toString();
                    const info: QuicConnectionInfo = {
                        serverName: this.serverName,
                        localAddr: this.local.addr,
                        localPort: this.local.port,
                        peerAddr: this.peer.addr,
                        peerPort: this.peer.port,
                        ssFamily: this.peer.family,
                        scid: this.scid,
                        dcid: "",
                    };
                    quicConnectionTracker.register(connKey, info);

                    if (ref.configLogKeys && !this.config.isNull()) {
                        try { ref.configLogKeys(this.config); }
                        catch (e) { devlog("[quiche] failed to enable config keylog: " + e); }
                    }
                    if (ref.setKeylogFd && keylogPipeWriteFd >= 0) {
                        try { ref.setKeylogFd(retval, keylogPipeWriteFd); }
                        catch (e) { devlog("[quiche] failed to set keylog fd: " + e); }
                    }

                    sendConnectionLifecycle("created", buildQuicMessage(info, connKey, "quiche_connect"));
                },
            });
        },
    };
}

/**
 * Create the extra hook that tracks connections from quiche_accept().
 *
 * quiche_accept(scid, scid_len, odcid, odcid_len, local, local_len, peer, peer_len, config)
 *               -> quiche_conn*
 */
function createAcceptTracker(ref: ResolvedRef,
                              keylogPipeWriteFd: number): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            const addr = addresses[moduleName]?.["quiche_accept"];
            if (!addr || addr.isNull()) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    const scidPtr = args[0];
                    const scidLen = args[1].toUInt32();
                    this.scid = (scidLen > 0 && !scidPtr.isNull())
                        ? readHexFromPointer(scidPtr, scidLen) : "";
                    const odcidPtr = args[2];
                    const odcidLen = args[3].toUInt32();
                    this.dcid = (odcidLen > 0 && !odcidPtr.isNull())
                        ? readHexFromPointer(odcidPtr, odcidLen) : "";
                    // Parse local address (args[4] = local, args[5] = local_len)
                    const localPtr = args[4];
                    const localLen = args[5].toUInt32();
                    this.local = parseSockaddr(localPtr, localLen);
                    // Parse peer address (args[6] = peer, args[7] = peer_len)
                    const peerPtr = args[6];
                    const peerLen = args[7].toUInt32();
                    this.peer = parseSockaddr(peerPtr, peerLen);
                    // Config is args[8]
                    this.config = args[8];
                },
                onLeave(retval) {
                    if (retval.isNull()) return;
                    const connKey = retval.toString();
                    const info: QuicConnectionInfo = {
                        serverName: "",
                        localAddr: this.local.addr,
                        localPort: this.local.port,
                        peerAddr: this.peer.addr,
                        peerPort: this.peer.port,
                        ssFamily: this.peer.family,
                        scid: this.scid,
                        dcid: this.dcid,
                    };
                    quicConnectionTracker.register(connKey, info);

                    if (ref.configLogKeys && !this.config.isNull()) {
                        try { ref.configLogKeys(this.config); }
                        catch (e) { devlog("[quiche] failed to enable config keylog: " + e); }
                    }
                    if (ref.setKeylogFd && keylogPipeWriteFd >= 0) {
                        try { ref.setKeylogFd(retval, keylogPipeWriteFd); }
                        catch (e) { devlog("[quiche] failed to set keylog fd: " + e); }
                    }

                    sendConnectionLifecycle("created", buildQuicMessage(info, connKey, "quiche_accept"));
                },
            });
        },
    };
}

/**
 * Create stream recv hook as ExtraHookDef.
 *
 * quiche_conn_stream_recv(conn, stream_id, out, buf_len, fin, out_error_code) -> ssize_t
 */
function createStreamRecvHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            if (!pcap_enabled) return;
            const addr = addresses[moduleName]?.["quiche_conn_stream_recv"];
            if (!addr || addr.isNull()) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    this.conn = args[0];
                    this.streamId = args[1].toInt32();
                    this.buf = args[2];
                    this.finPtr = args[4];
                },
                onLeave(retval) {
                    const n = retval.toInt32();
                    if (n < 0) return;  // error or QUICHE_ERR_DONE
                    const connKey = this.conn.toString();
                    const connInfo = quicConnectionTracker.get(connKey);
                    if (!connInfo) return;
                    const message = buildQuicMessage(connInfo, connKey, "quiche_stream_recv");
                    if (n > 0) {
                        sendQuicDatalog(message, this.buf.readByteArray(n), this.streamId, connInfo.scid, connInfo.dcid);
                    }
                    // Check fin flag for stream completion
                    if (this.finPtr && !this.finPtr.isNull()) {
                        try {
                            if (this.finPtr.readU8() !== 0) {
                                sendConnectionLifecycle("stream_fin", {
                                    ...message,
                                    stream_id: this.streamId,
                                });
                            }
                        } catch (_e) { /* fin pointer may be invalid */ }
                    }
                },
            });
            log("[*] Hooked quiche_conn_stream_recv for plaintext capture");
        },
    };
}

/**
 * Create stream send hook as ExtraHookDef.
 *
 * quiche_conn_stream_send(conn, stream_id, buf, buf_len, fin, out_error_code) -> ssize_t
 */
function createStreamSendHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            if (!pcap_enabled) return;
            const addr = addresses[moduleName]?.["quiche_conn_stream_send"];
            if (!addr || addr.isNull()) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    this.conn = args[0];
                    this.streamId = args[1].toInt32();
                    this.buf = args[2];
                    this.bufLen = args[3].toUInt32();
                    this.fin = args[4].toInt32() !== 0;
                },
                onLeave(retval) {
                    const n = retval.toInt32();
                    if (n < 0) return;  // error or QUICHE_ERR_DONE
                    const connKey = this.conn.toString();
                    const connInfo = quicConnectionTracker.get(connKey);
                    if (!connInfo) return;
                    // For write, use the actual bytes written (retval), not buf_len
                    const bytesToCapture = n > 0 ? n : 0;
                    if (bytesToCapture > 0) {
                        const message = buildQuicMessage(connInfo, connKey, "quiche_stream_send");
                        sendQuicDatalog(message, this.buf.readByteArray(bytesToCapture), this.streamId, connInfo.scid, connInfo.dcid);
                    }
                    if (this.fin) {
                        const message = buildQuicMessage(connInfo, connKey, "quiche_stream_send");
                        sendConnectionLifecycle("stream_fin", {
                            ...message,
                            stream_id: this.streamId,
                        });
                    }
                },
            });
            log("[*] Hooked quiche_conn_stream_send for plaintext capture");
        },
    };
}

/**
 * Create connection free hook for cleanup.
 *
 * quiche_conn_free(conn) -> void
 */
function createConnFreeHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, _resolvedFns, _enableDefaultFd) {
            const addr = addresses[moduleName]?.["quiche_conn_free"];
            if (!addr || addr.isNull()) return;

            Interceptor.attach(addr, {
                onEnter(args) {
                    const connKey = args[0].toString();
                    const info = quicConnectionTracker.remove(connKey);
                    if (info) {
                        sendConnectionLifecycle("destroyed", buildQuicMessage(info, connKey, "quiche_conn_free"));
                    }
                },
            });
        },
    };
}

/**
 * Create the keylog pipe reader hook.
 *
 * This hooks quiche_config_new to force-enable keylogging on every config,
 * and intercepts quiche_conn_set_keylog_fd / quiche_conn_set_keylog_path
 * to capture any application-initiated keylogs.
 */
function createKeylogConfigHook(): ExtraHookDef {
    return {
        install(addresses, moduleName, resolvedFns, _enableDefaultFd) {
            // Hook quiche_config_new to force-enable keylog on every config
            const configNewAddr = addresses[moduleName]?.["quiche_config_new"];
            const configLogKeysAddr = addresses[moduleName]?.["quiche_config_log_keys"];

            if (configNewAddr && !configNewAddr.isNull() && configLogKeysAddr && !configLogKeysAddr.isNull()) {
                const configLogKeys = new NativeFunction(configLogKeysAddr, "void", ["pointer"]);
                Interceptor.attach(configNewAddr, {
                    onLeave(retval) {
                        if (!retval.isNull()) {
                            try {
                                configLogKeys(retval);
                                devlog("[quiche] enabled keylog on new config " + retval);
                            } catch (e) {
                                devlog("[quiche] failed to enable keylog on config: " + e);
                            }
                        }
                    },
                });
                log("[*] Hooked quiche_config_new for automatic keylog enablement");
            }

            // Intercept quiche_conn_set_keylog_path to read from the path
            const setKeylogPathAddr = addresses[moduleName]?.["quiche_conn_set_keylog_path"];
            if (setKeylogPathAddr && !setKeylogPathAddr.isNull()) {
                Interceptor.attach(setKeylogPathAddr, {
                    onEnter(args) {
                        const path = args[1].readCString();
                        devlog("[quiche] app set keylog path: " + path);
                        // We can't easily read from the path in realtime,
                        // but the fd-based approach will handle our injected keys
                    },
                });
            }
        },
    };
}

/**
 * Try to create a pipe for keylog fd injection.
 * Returns [readFd, writeFd] or [-1, -1] on failure.
 */
function createKeylogPipe(): [number, number] {
    try {
        const pipeFn = new NativeFunction(
            (Module as any).findExportByName(null, "pipe")!,
            "int",
            ["pointer"],
        );
        const pipefd = Memory.alloc(8); // int[2]
        const result = pipeFn(pipefd) as number;
        if (result === 0) {
            const readFd = pipefd.readS32();
            const writeFd = pipefd.add(4).readS32();
            devlog("[quiche] created keylog pipe: read=" + readFd + " write=" + writeFd);
            return [readFd, writeFd];
        }
    } catch (e) {
        devlog("[quiche] failed to create pipe: " + e);
    }
    return [-1, -1];
}

/**
 * Start a background thread that reads SSLKEYLOGFILE lines from the pipe.
 */
function startKeylogPipeReader(readFd: number): void {
    if (readFd < 0) return;

    const readFn = new NativeFunction(
        (Module as any).findExportByName(null, "read")!,
        "ssize_t",
        ["int", "pointer", "size_t"],
    );
    const bufSize = 4096;
    const buf = Memory.alloc(bufSize);

    // Use a dedicated thread to read from the pipe
    const threadFn = new NativeCallback(
        function (_arg: NativePointer): NativePointer {
            let partial = "";
            while (true) {
                const n = (readFn(readFd, buf, bufSize - 1) as unknown) as number;
                if (n <= 0) break;  // pipe closed or error
                const chunk = partial + buf.readUtf8String(n)!;
                const lines = chunk.split("\n");
                // Last element is partial (may be "")
                partial = lines.pop()!;
                for (const line of lines) {
                    const trimmed = line.trim();
                    if (trimmed.length > 0) {
                        sendQuicKeylog(trimmed);
                    }
                }
            }
            // Flush any remaining partial line
            if (partial.trim().length > 0) {
                sendQuicKeylog(partial.trim());
            }
            return NULL;
        },
        "pointer",
        ["pointer"],
    );

    // Create a pthread to run the reader
    try {
        const pthreadCreate = new NativeFunction(
            (Module as any).findExportByName(null, "pthread_create")!,
            "int",
            ["pointer", "pointer", "pointer", "pointer"],
        );
        const threadId = Memory.alloc(Process.pointerSize);
        pthreadCreate(threadId, NULL, threadFn, NULL);
        devlog("[quiche] started keylog pipe reader thread");
    } catch (e) {
        devlog_error("[quiche] failed to start keylog pipe reader: " + e);
    }
}


export function createQuicheDefinition(): HookDefinition {
    // Create pipe for keylog fd injection
    const [pipeReadFd, pipeWriteFd] = createKeylogPipe();

    // Start the background reader if pipe was created
    if (pipeReadFd >= 0) {
        startKeylogPipeReader(pipeReadFd);
    }

    // Mutable container so closures in ExtraHookDefs see resolved functions.
    // Populated by onNativeFunctionsResolved after symbol resolution.
    const resolvedRef: {
        configLogKeys: NativeFunction<void, [NativePointer]> | null;
        setKeylogFd: NativeFunction<void, [NativePointer, number]> | null;
    } = { configLogKeys: null, setKeylogFd: null };

    return {
        libraryId: "quiche",
        offsetKey: "quiche",
        functions: {
            librarySymbols: [
                "quiche_conn_stream_recv",
                "quiche_conn_stream_send",
                "quiche_connect",
                "quiche_accept",
                "quiche_config_new",
                "quiche_config_log_keys",
                "quiche_conn_set_keylog_fd",
                "quiche_conn_set_keylog_path",
                "quiche_conn_free",
                "quiche_conn_source_id",
            ],
            socketSymbols: [],  // QUIC doesn't use socket fds
        },
        nativeFunctions: [
            { symbol: "quiche_config_log_keys", retType: "void", argTypes: ["pointer"] },
            { symbol: "quiche_conn_set_keylog_fd", retType: "void", argTypes: ["pointer", "int"] },
        ],
        fdDecoder: (_sslCtx, _fns) => -1,
        sessionIdDecoder: (sslCtx, _fns) => sslCtx.toString(),
        keylog: { kind: "none" },
        extraHooks: [
            createConnectTracker(resolvedRef, pipeWriteFd),
            createAcceptTracker(resolvedRef, pipeWriteFd),
            createStreamRecvHook(),
            createStreamSendHook(),
            createConnFreeHook(),
            createKeylogConfigHook(),
        ],
        onNativeFunctionsResolved: (fns) => {
            if (fns["quiche_config_log_keys"]) {
                resolvedRef.configLogKeys = fns["quiche_config_log_keys"] as NativeFunction<void, [NativePointer]>;
            }
            if (fns["quiche_conn_set_keylog_fd"]) {
                resolvedRef.setKeylogFd = fns["quiche_conn_set_keylog_fd"] as NativeFunction<void, [NativePointer, number]>;
            }
        },
    };
}
