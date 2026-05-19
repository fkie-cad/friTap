// agent/quic/definitions/google_quiche.ts
//
// Hooks for Google QUICHE (Chrome/Chromium/Cronet) QUIC stream read/write.
// Uses C++ mangled symbol lookup with pattern-scan fallback for stripped builds.
//
// Target functions:
//   - QuicSpdyStream::Readv(const struct iovec* iov, size_t iov_len) -> size_t
//   - QuicSpdyStream::WriteOrBufferBody(absl::string_view data, bool fin) -> void
//
// These are virtual methods on QuicSpdyStream, which inherits from QuicStream.

import { sendQuicDatalog } from "../../shared/shared_structures.js";
import { log, devlog, devlog_error } from "../../util/log.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { MANGLED_SYMBOLS } from "../shared/google_quiche_offsets.js";
import { quicConnectionTracker, buildQuicMessage, QuicConnectionInfo } from "../shared/quic_connection_tracker.js";

/**
 * Read data from an iovec scatter-gather list.
 *
 * struct iovec { void* iov_base; size_t iov_len; }
 * Size: 2 * pointerSize per entry
 */
function readIovec(iovPtr: NativePointer, iovLen: number, maxBytes: number): ArrayBuffer | null {
    if (iovPtr.isNull() || iovLen === 0 || maxBytes === 0) return null;

    const ptrSize = Process.pointerSize;
    const iovecSize = ptrSize * 2;  // iov_base (pointer) + iov_len (size_t)
    let remaining = maxBytes;
    const parts: ArrayBuffer[] = [];

    for (let i = 0; i < iovLen && remaining > 0; i++) {
        const entry = iovPtr.add(i * iovecSize);
        const base = entry.readPointer();
        const len = (entry.add(ptrSize).readULong() as unknown) as number;
        if (base.isNull() || len === 0) continue;
        const toRead = Math.min(len, remaining);
        const chunk = base.readByteArray(toRead);
        if (chunk) {
            parts.push(chunk);
            remaining -= toRead;
        }
    }

    if (parts.length === 0) return null;
    if (parts.length === 1) return parts[0];

    // Concatenate multiple chunks
    const totalLen = maxBytes - remaining;
    const result = new ArrayBuffer(totalLen);
    const view = new Uint8Array(result);
    let offset = 0;
    for (const part of parts) {
        view.set(new Uint8Array(part), offset);
        offset += part.byteLength;
    }
    return result;
}

/**
 * Get the platform-specific mangled symbol name.
 */
function getMangledSymbol(key: keyof typeof MANGLED_SYMBOLS): string {
    const platform = Process.platform;
    const symbols = MANGLED_SYMBOLS[key];
    if (platform === "darwin") return symbols.macos;
    if (platform === "windows") return symbols.windows;
    return symbols.linux;
}

/**
 * Try to resolve a symbol address by mangled name lookup, then pattern scan fallback.
 */
function resolveQuicheSymbol(moduleName: string, key: keyof typeof MANGLED_SYMBOLS): NativePointer | null {
    const mangledName = getMangledSymbol(key);

    // Try direct symbol lookup first (debug builds, some Android builds)
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod) {
            const addr = mod.findExportByName(mangledName);
            if (addr && !addr.isNull()) {
                devlog("[Google QUICHE] found " + key + " via symbol export in " + moduleName);
                return addr;
            }
        }
    } catch (_e) { /* continue to fallback */ }

    // Try pattern scan from default_patterns.json (populated by pattern pipeline)
    // The pipeline will try patterns registered under "google_quiche" key
    devlog("[Google QUICHE] " + key + " not found via export in " + moduleName + ", will try pattern scan");
    return null;
}

// String xref scanning for WriteOrBufferBody is not yet implemented.
// When byte patterns are added to default_patterns.json, the pipeline
// will resolve them automatically via PatternStrategy.

/**
 * Install Google QUICHE hooks on a Chrome/Cronet module.
 *
 * This is NOT a standard HookDefinition — it uses a custom installation
 * approach because the target functions are C++ mangled virtual methods
 * that don't fit the standard symbol resolution pipeline.
 */
export function installGoogleQuicheHooks(moduleName: string): void {
    if (!pcap_enabled) return;
    log("[*] Google QUICHE: attempting to hook QuicSpdyStream in " + moduleName);

    // Resolve Readv
    const readvAddr = resolveQuicheSymbol(moduleName, "readv");
    // Resolve WriteOrBufferBody
    const writeAddr = resolveQuicheSymbol(moduleName, "writeOrBufferBody");

    if (!readvAddr && !writeAddr) {
        devlog("[Google QUICHE] could not resolve any stream functions in " + moduleName);
        devlog("[Google QUICHE] note: stripped release builds require byte patterns in default_patterns.json");
        return;
    }

    // Hook Readv: QuicSpdyStream::Readv(this, iov, iov_len) -> size_t
    if (readvAddr && !readvAddr.isNull()) {
        try {
            Interceptor.attach(readvAddr, {
                onEnter(args) {
                    this.streamObj = args[0];  // QuicSpdyStream* this
                    this.iov = args[1];        // const struct iovec*
                    this.iovLen = args[2].toUInt32();  // iov_len is typically small
                },
                onLeave(retval) {
                    const bytesRead = retval.toUInt32();  // size_t but HTTP/3 reads are bounded
                    if (bytesRead === 0) return;

                    const data = readIovec(this.iov, this.iovLen, bytesRead);
                    if (!data) return;

                    const sessionId = this.streamObj.toString();
                    // Use the connection tracker if available, otherwise use basic info
                    const connInfo = quicConnectionTracker.get(sessionId);
                    const message = connInfo
                        ? buildQuicMessage(connInfo, sessionId, "QuicSpdyStream_Readv")
                        : {
                            src_addr: "0.0.0.0", src_port: 0,
                            dst_addr: "0.0.0.0", dst_port: 0,
                            ss_family: "AF_INET",
                            ssl_session_id: sessionId,
                            function: "QuicSpdyStream_Readv",
                        };

                    // Stream ID extraction from object would require known struct offsets.
                    // For now, use -1 to indicate unknown stream ID.
                    sendQuicDatalog(message, data, -1);
                },
            });
            log("[*] Hooked QuicSpdyStream::Readv for plaintext capture");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook Readv: " + e);
        }
    }

    // Hook WriteOrBufferBody: QuicSpdyStream::WriteOrBufferBody(this, data_ptr, data_len, fin) -> void
    // On x86-64 SysV ABI: absl::string_view is decomposed to two registers (ptr=rsi, len=rdx)
    // On ARM64: this=x0, data.ptr=x1, data.length=x2, fin=w3
    if (writeAddr && !writeAddr.isNull()) {
        try {
            Interceptor.attach(writeAddr, {
                onEnter(args) {
                    this.streamObj = args[0];       // QuicSpdyStream* this
                    const dataPtr = args[1];         // absl::string_view.ptr
                    const dataLen = args[2].toUInt32(); // size_t but HTTP/3 bodies are bounded in practice
                    this.dataLen = dataLen;

                    if (dataLen === 0 || dataPtr.isNull()) {
                        this.data = null;
                        return;
                    }

                    // Read the data NOW (before the function potentially modifies it)
                    this.data = dataPtr.readByteArray(dataLen);
                },
                onLeave(_retval) {
                    if (!this.data || this.dataLen === 0) return;

                    const sessionId = this.streamObj.toString();
                    const connInfo = quicConnectionTracker.get(sessionId);
                    const message = connInfo
                        ? buildQuicMessage(connInfo, sessionId, "QuicSpdyStream_WriteOrBufferBody")
                        : {
                            src_addr: "0.0.0.0", src_port: 0,
                            dst_addr: "0.0.0.0", dst_port: 0,
                            ss_family: "AF_INET",
                            ssl_session_id: sessionId,
                            function: "QuicSpdyStream_WriteOrBufferBody",
                        };

                    sendQuicDatalog(message, this.data, -1);
                },
            });
            log("[*] Hooked QuicSpdyStream::WriteOrBufferBody for plaintext capture");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook WriteOrBufferBody: " + e);
        }
    }
}
