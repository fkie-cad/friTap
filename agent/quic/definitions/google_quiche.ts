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
import { findNonExportedSymbols, underscoreVariants } from "../../shared/shared_functions.js";

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
 * Batch-resolve all QUICHE mangled symbols in a single pass using the same
 * multi-strategy approach as Neqo. Returns a map of key → NativePointer.
 *
 * Strategies tried in order:
 * 1. Export table (works in unstripped builds; rare for release Chrome/Cronet)
 * 2. Symbol table via single enumerateSymbols() pass (works on Mainline Cronet
 *    APEX builds where the QUICHE C++ symbols are imported into the dynsym
 *    table but not exported — confirmed via runtime inspection of
 *    libmainlinecronet.<ver>.so on Pixel 5 / Cronet 141)
 * 3. DebugSymbol (if debug info is available)
 */
function resolveQuicheSymbols(moduleName: string): Map<keyof typeof MANGLED_SYMBOLS, NativePointer> {
    const resolved = new Map<keyof typeof MANGLED_SYMBOLS, NativePointer>();
    const keys = Object.keys(MANGLED_SYMBOLS) as Array<keyof typeof MANGLED_SYMBOLS>;
    const remaining: Array<keyof typeof MANGLED_SYMBOLS> = [];

    // Strategy 1: export table
    let mod: Module | null = null;
    try {
        mod = Process.findModuleByName(moduleName);
    } catch (_e) { /* ignore */ }

    for (const key of keys) {
        const mangledName = getMangledSymbol(key);
        if (mod) {
            try {
                const addr = mod.findExportByName(mangledName);
                if (addr && !addr.isNull()) {
                    devlog("[Google QUICHE] found " + key + " via symbol export in " + moduleName);
                    resolved.set(key, addr);
                    continue;
                }
            } catch (_e) { /* fall through */ }
        }
        remaining.push(key);
    }
    if (remaining.length === 0) return resolved;

    // Strategy 2: single batch symbol table enumeration. Underscore-tolerant
    // matching is handled inside findNonExportedSymbols.
    const symResults = findNonExportedSymbols(moduleName, remaining.map(getMangledSymbol));
    for (const key of remaining) {
        const addr = symResults.get(getMangledSymbol(key));
        if (addr && !addr.isNull()) {
            devlog("[Google QUICHE] found " + key + " via symbol table in " + moduleName);
            resolved.set(key, addr);
        }
    }

    // Strategy 3: DebugSymbol for any still-unresolved (try underscore variants).
    for (const key of remaining) {
        if (resolved.has(key)) continue;
        for (const variant of underscoreVariants(getMangledSymbol(key))) {
            try {
                const matches = DebugSymbol.findFunctionsNamed(variant);
                if (matches.length > 0) {
                    devlog("[Google QUICHE] found " + key + " via DebugSymbol in " + moduleName);
                    resolved.set(key, matches[0]);
                    break;
                }
            } catch (_e) { /* DebugSymbol may be unavailable */ }
        }
    }

    return resolved;
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

    // Batched resolution: single enumerateSymbols() pass for all QUICHE symbols.
    const resolved = resolveQuicheSymbols(moduleName);
    const readvAddr = resolved.get("readv") || null;
    const writeAddr = resolved.get("writeOrBufferBody") || null;

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
