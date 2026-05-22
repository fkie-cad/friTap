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
import { log, devlog, devlog_debug, devlog_error } from "../../util/log.js";
import { pcap_enabled, getParsedPatterns, offsets, quic_capture_mode } from "../../fritap_agent.js";
import { MANGLED_SYMBOLS, LABEL_TO_KEY, KEY_TO_LABEL } from "../shared/google_quiche_offsets.js";
import { quicConnectionTracker, buildQuicMessage, QuicConnectionInfo, ObservedPeer } from "../shared/quic_connection_tracker.js";
import { findNonExportedSymbols, underscoreVariants, getBaseAddress, decodeSockaddr } from "../../shared/shared_functions.js";
import { PatternStrategy } from "../../shared/strategies/pattern_strategy.js";

/**
 * Build the datalog message for a stream-level QUIC hook. Resolves the stream
 * pointer to its connection (when known), then to a guaranteed-parseable
 * 4-tuple (registered → synthetic), so a flow is never emitted as 0.0.0.0:0.
 */
function resolveQuicMessage(streamPtr: string, label: string): { [key: string]: any } {
    const connPtr = quicConnectionTracker.resolveStream(streamPtr) ?? streamPtr;
    return buildQuicMessage(quicConnectionTracker.resolveInfo(connPtr), connPtr, label);
}

/**
 * Parse a sockaddr into the pcap-writer address encoding (AF_INET → host-order
 * integer, AF_INET6 → 32-char uppercase hex), mirroring getPortsAndAddresses.
 */
function parseObservedPeer(sa: NativePointer): ObservedPeer | null {
    // Byte math (no libc ntoh* available inside this connect() hook). The shared
    // decoder folds v4-mapped IPv6 to AF_INET, so a single loopback check covers both.
    const decoded = decodeSockaddr(sa);
    if (!decoded || decoded.port === 0) return null;
    if (decoded.family === "AF_INET" &&
        ((decoded.addr as number) >>> 24) === 127) return null; // loopback, not a server
    return decoded;
}

// Best-effort real-peer recovery installs the libc socket()/connect() observer
// exactly once for the whole process (installGoogleQuicheHooks runs per Cronet
// module). QUIC's UDP fd is not reachable from the C++ stream objects without
// version-fragile struct walks, so we record the server address at the socket
// layer instead and fold it into the synthetic flows.
let socketObserverInstalled = false;

function installQuicSocketObserver(): void {
    if (socketObserverInstalled) return;
    socketObserverInstalled = true;

    const udpFds = new Set<number>();
    const socketAddr = Module.findGlobalExportByName("socket");
    const connectAddr = Module.findGlobalExportByName("connect");
    const closeAddr = Module.findGlobalExportByName("close");

    if (socketAddr) {
        Interceptor.attach(socketAddr, {
            onEnter(args) { this.sockType = args[1].toInt32(); },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd >= 0 && (this.sockType & 0x7f) === 2) udpFds.add(fd); // SOCK_DGRAM
            },
        });
    }
    if (connectAddr) {
        Interceptor.attach(connectAddr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (!udpFds.has(fd)) return;
                try {
                    const peer = parseObservedPeer(args[1]);
                    if (peer) quicConnectionTracker.setObservedPeer(peer);
                } catch (e) { /* best-effort */ }
            },
        });
    }
    if (closeAddr) {
        Interceptor.attach(closeAddr, {
            onEnter(args) { udpFds.delete(args[0].toInt32()); },
        });
    }
    devlog("[Google QUICHE] installed libc UDP socket observer for real-peer recovery");
}

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
        // Per-entry try: a single unmapped iov_base must not abort the whole read
        // (an uncaught throw in onLeave is swallowed by Frida → silent no-data).
        try {
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
        } catch (e) {
            devlog_error(`[Google QUICHE] readIovec entry ${i} threw: ${e}`);
            continue;
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
 * Read a libc++ (std::__Cr) std::string. 24 bytes, SSO union discriminated by
 * the low bit of the first byte:
 *   - long form (bit set):   size_t cap@+0 (low bit=1), size_t size@+8, char* data@+16
 *   - short form (bit clear): length = firstByte >> 1, inline data @ +1
 * Bounds-checked so an implausible layout yields "" rather than a wild read
 * (an uncaught throw in a Frida callback is silently swallowed → no data).
 */
function readLibcxxString(p: NativePointer): string {
    try {
        const first = p.readU8();
        if (first & 1) {                                 // long form
            const size = (p.add(8).readULong() as unknown) as number;
            const dataPtr = p.add(16).readPointer();
            if (dataPtr.isNull() || size <= 0 || size > (1 << 20)) return "";
            return dataPtr.readUtf8String(size) ?? "";
        }
        const size = first >> 1;                          // short / SSO
        if (size <= 0 || size > 22) return "";
        return p.add(1).readUtf8String(size) ?? "";
    } catch (e) {
        return "";
    }
}

/**
 * Walk a QuicHeaderList (the by-value temp passed to OnHeadersDecoded).
 *
 * QuicHeaderList begins with a QuicheCircularDeque<std::pair<string,string>>:
 *   +0x00 size_t begin_ ; +0x08 size_t end_ ; +0x10 pair* data ; +0x18 size_t capacity
 *   size = end_ - begin_ ; element i at data + ((begin_+i) % capacity) * 48
 *   (48 = 2 * 24-byte libc++ string: name then value).
 * Returns [[name, value], ...]. On any implausible layout we emit nothing
 * rather than garbage.
 */
function readQuicHeaderList(hl: NativePointer, maxPairs = 256): [string, string][] {
    const out: [string, string][] = [];
    try {
        const begin = (hl.readULong() as unknown) as number;
        const end   = (hl.add(8).readULong() as unknown) as number;
        const data  = hl.add(16).readPointer();
        const cap   = (hl.add(24).readULong() as unknown) as number;
        if (data.isNull() || cap <= 0 || cap > 65536) return out;
        const n = Math.min(end - begin, maxPairs);
        if (n <= 0) return out;
        for (let i = 0; i < n; i++) {
            const slot = data.add(((begin + i) % cap) * 48);
            out.push([readLibcxxString(slot), readLibcxxString(slot.add(24))]);
        }
    } catch (e) {
        // implausible layout: emit nothing rather than garbage
    }
    return out;
}

/** Read an absl::string_view {const char* ptr; size_t len}. Bounds-checked. */
function readStringView(p: NativePointer): string {
    try {
        const ptr = p.readPointer();
        const len = (p.add(8).readULong() as unknown) as number;
        if (ptr.isNull() || len <= 0 || len > (1 << 20)) return "";
        return ptr.readUtf8String(len) ?? "";
    } catch (e) {
        return "";
    }
}

/**
 * Read the value out of an HttpHeaderBlock::HeaderValue:
 *   +0  HttpHeaderStorage* storage_
 *   +8  Fragments fragments_  (absl::InlinedVector<absl::string_view, 1>):
 *         +0 metadata = (size << 1) | is_allocated ; +8 inline string_view {ptr,len}
 * Single-value headers (the common request case, e.g. :method=GET) keep the
 * value in fragments_[0] from construction, so we read it directly without
 * triggering lazy consolidation. Multi-fragment values are best-effort (we read
 * the first fragment). Implausible layout -> "".
 */
function readHeaderValue(hv: NativePointer): string {
    try {
        const meta = (hv.add(8).readULong() as unknown) as number;   // fragments_ metadata
        const allocated = meta & 1;
        const count = meta >> 1;
        if (count <= 0) return "";
        let svPtr: NativePointer;
        if (!allocated) {
            svPtr = hv.add(16);                      // inline string_view[0]
        } else {
            svPtr = hv.add(16).readPointer();        // heap array of string_view
            if (svPtr.isNull()) return "";
        }
        return readStringView(svPtr);
    } catch (e) {
        return "";
    }
}

/** True if `listObj` looks like a well-formed libc++ std::list object. */
function _looksLikeStdList(listObj: NativePointer): boolean {
    try {
        const size = (listObj.add(16).readULong() as unknown) as number;
        if (size <= 0 || size > 1000) return false;
        const sentinel = listObj;                     // address of __end_
        const first = listObj.add(8).readPointer();   // __end_.__next_ (first node)
        if (first.isNull() || first.equals(sentinel)) return false;
        // first node's __prev_ (at +0) must point back to the sentinel node
        return first.readPointer().equals(sentinel);
    } catch (e) {
        return false;
    }
}

/**
 * Walk a quiche::HttpHeaderBlock (the by-value temp passed to WriteHeaders) and
 * return [[name, value], ...].
 *
 *   HttpHeaderBlock +0: MapType map_  (a QuicheLinkedHashMap)
 *   QuicheLinkedHashMap: absl::flat_hash_map (Abseil-version-dependent size),
 *     then std::list<pair<absl::string_view, HeaderValue>> list_.
 *   We SELF-LOCATE list_ by probing offsets and validating a well-formed libc++
 *   circular list, so the flat_hash_map size never has to be hardcoded.
 *   std::list: +0 __end_.__prev_ ; +8 __end_.__next_ (first node) ; +16 size.
 *   __list_node: __prev_@+0, __next_@+8, __value_@+16 (the pair).
 *   pair: key absl::string_view @+0 ; HeaderValue @+16.
 * Bounds-checked throughout; implausible layout -> emit nothing.
 */
function readHttpHeaderBlock(hhb: NativePointer, maxPairs = 256): [string, string][] {
    const out: [string, string][] = [];
    try {
        for (const off of [16, 24, 32, 40, 48, 56, 64]) {
            const listObj = hhb.add(off);
            if (!_looksLikeStdList(listObj)) continue;
            const sentinel = listObj;
            let node = listObj.add(8).readPointer();   // first real node
            let guard = 0;
            while (!node.isNull() && !node.equals(sentinel) && guard < maxPairs) {
                const pair = node.add(16);             // __value_ = pair<string_view, HeaderValue>
                const key = readStringView(pair);      // key absl::string_view @ +0
                const val = readHeaderValue(pair.add(16)); // HeaderValue @ +16
                if (key.length > 0) out.push([key, val]);
                node = node.add(8).readPointer();      // __next_
                guard++;
            }
            if (out.length > 0) return out;
        }
    } catch (e) {
        // implausible layout: emit nothing rather than garbage
    }
    return out;
}

/**
 * Shared Readv-style hook body. All three Readv targets
 * (QuicSpdyStream::Readv, QuicStream::Readv, QuicStreamSequencer::Readv) have
 * the same (this, iovec*, iov_len) ABI and return size_t bytes_read. Extracted
 * so we can attach to whichever one survives Chrome's release-build
 * devirtualisation without duplicating the iovec-walk / message-build logic
 * three times.
 *
 * `label` is what shows up in the emitted message["function"] field and in
 * the diagnostic devlog lines below — keep it stable (downstream tooling
 * filters by these names).
 */
function installReadvHook(addr: NativePointer, label: string): void {
    let callCount = 0;
    const MAX_DEBUG_CALLS = 5;

    Interceptor.attach(addr, {
        onEnter(args) {
            this.streamObj = args[0];
            this.iov = args[1];
            this.iovLen = args[2].toUInt32();
        },
        onLeave(retval) {
            // Outer try: an uncaught throw in tracker lookup or message build is
            // swallowed by Frida, so log it rather than lose the hook silently.
            try {
                const bytesRead = retval.toUInt32();
                if (callCount < MAX_DEBUG_CALLS) {
                    callCount++;
                    devlog_debug(`[${label}] call #${callCount}: bytesRead=${bytesRead} iovLen=${this.iovLen}`);
                }
                if (bytesRead === 0) return;

                const data = readIovec(this.iov, this.iovLen, bytesRead);
                if (!data) return;

                const message = resolveQuicMessage(this.streamObj.toString(), label);
                sendQuicDatalog(message, data, -1);
            } catch (e) {
                devlog_error(`[${label}] onLeave threw: ${e}`);
            }
        },
    });
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
    // DebugSymbol.findFunctionsNamed searches ALL loaded modules, so a match can
    // belong to a *different* module that happens to export the same C++ symbol
    // (e.g. libmonochrome_64.so has no QUICHE symbols of its own, but the symbol
    // name resolves to libmainlinecronet's address). Constrain matches to the
    // target module's [base, base+size) range, otherwise we'd hook the wrong
    // library at an address its own code never executes.
    const modBase = mod ? mod.base : null;
    const modEnd = mod ? mod.base.add(mod.size) : null;
    for (const key of remaining) {
        if (resolved.has(key)) continue;
        for (const variant of underscoreVariants(getMangledSymbol(key))) {
            try {
                const matches = DebugSymbol.findFunctionsNamed(variant);
                const inModule = (modBase && modEnd)
                    ? matches.find(a => a.compare(modBase) >= 0 && a.compare(modEnd) < 0)
                    : matches[0];
                if (inModule) {
                    devlog("[Google QUICHE] found " + key + " via DebugSymbol in " + moduleName);
                    resolved.set(key, inModule);
                    break;
                }
                if (matches.length > 0) {
                    devlog("[Google QUICHE] DebugSymbol match for " + key +
                           " is outside " + moduleName + " (belongs to another module); ignoring");
                }
            } catch (_e) { /* DebugSymbol may be unavailable */ }
        }
    }

    // --- Strategy 4: byte-pattern scan (stripped libs, e.g. libmonochrome) ---
    // Symbols (1-3) always win; patterns only fill still-missing keys. Reuses the
    // PatternStrategy libtype lookup + Memory.scanSync + `?` wildcards verbatim.
    let missing = (Object.keys(MANGLED_SYMBOLS) as (keyof typeof MANGLED_SYMBOLS)[])
        .filter(k => !resolved.has(k));
    if (missing.length > 0) {
        const parsed = getParsedPatterns();
        if (parsed) {
            const labels = missing.map(k => KEY_TO_LABEL[k]).filter(Boolean);
            try {
                const ps = new PatternStrategy(parsed);
                const res = ps.tryHook(moduleName, "google_quiche", labels);
                res.resolvedAddresses.forEach((addr, label) => {
                    const key = LABEL_TO_KEY[label];
                    if (key && !resolved.has(key)) {
                        resolved.set(key, addr);
                        devlog(`[Google QUICHE] found ${key} via pattern in ${moduleName}`);
                    }
                });
            } catch (e) {
                devlog_debug(`[Google QUICHE] pattern strategy failed: ${e}`);
            }
        }
    }

    // --- Strategy 5: static offsets (manual override / fallback) ---
    // Mirrors resolveOffsets() inline (our `resolved` is a Map, not the
    // object-of-objects resolveOffsets expects). Fills only still-missing keys.
    missing = (Object.keys(MANGLED_SYMBOLS) as (keyof typeof MANGLED_SYMBOLS)[])
        .filter(k => !resolved.has(k));
    if (missing.length > 0 && (offsets as any) !== "{OFFSETS}" && (offsets as any).google_quiche) {
        const base = getBaseAddress(moduleName);
        const gq = (offsets as any).google_quiche;
        for (const k of missing) {
            const entry = gq[KEY_TO_LABEL[k]];
            if (!entry) continue;
            const a = ptr(entry.address);
            resolved.set(k, (entry.absolute || base == null) ? a : base.add(a));
            devlog(`[Google QUICHE] applied offset for ${k} in ${moduleName}`);
        }
    }

    return resolved;
}

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

    // Best-effort real-peer recovery (process-wide, installed once).
    installQuicSocketObserver();

    // Batched resolution: single enumerateSymbols() pass for all QUICHE symbols.
    const resolved = resolveQuicheSymbols(moduleName);
    const readvAddr = resolved.get("readv") || null;
    const quicStreamReadvAddr = resolved.get("quicStreamReadv") || null;
    const sequencerReadvAddr = resolved.get("sequencerReadv") || null;
    const onBodyAvailableAddr = resolved.get("onBodyAvailable") || null;
    const writeAddr = resolved.get("writeOrBufferBody") || null;
    const onDataFramePayloadAddr = resolved.get("onDataFramePayload") || null;
    const onHeadersDecodedAddr = resolved.get("onHeadersDecoded") || null;
    const writeHeadersAddr = resolved.get("writeHeaders") || null;

    if (!readvAddr && !writeAddr && !quicStreamReadvAddr && !sequencerReadvAddr && !onDataFramePayloadAddr) {
        devlog("[Google QUICHE] could not resolve any stream functions in " + moduleName);
        devlog("[Google QUICHE] note: stripped release builds require byte patterns in default_patterns.json");
        return;
    }

    // Attach to every Readv variant that resolves. Cronet's release ARM64 builds
    // inline QuicSpdyStream::Readv — QuicStreamSequencer::Readv is the non-virtual
    // post-decrypt entry that survives devirtualisation, so it's the reliable one.
    // The raw lower-boundary Readv hooks belong to the "stream" capture mode.
    // In "app-api" mode we capture at the application-API boundary
    // (OnDataFramePayload / WriteOrBufferBody) instead, so skip the raw-readv
    // install loop entirely. The app-API hooks below run in both modes.
    log(`[*] Google QUICHE: quic_capture_mode = "${quic_capture_mode}"`);
    if (quic_capture_mode !== "app-api") {
        const readvTargets: Array<[NativePointer | null, string, string]> = [
            [readvAddr, "QuicSpdyStream_Readv", "QuicSpdyStream::Readv"],
            [quicStreamReadvAddr, "QuicStream_Readv", "QuicStream::Readv"],
            [sequencerReadvAddr, "QuicStreamSequencer_Readv", "QuicStreamSequencer::Readv"],
        ];
        for (const [addr, label, prettyName] of readvTargets) {
            if (!addr || addr.isNull()) continue;
            try {
                installReadvHook(addr, label);
                log(`[*] Hooked ${prettyName} for plaintext capture`);
            } catch (e) {
                devlog_error(`[Google QUICHE] failed to hook ${prettyName}: ${e}`);
            }
        }
    }

    // PRIMARY INCOMING PATH: QuicSpdyStream::HttpDecoderVisitor::OnDataFramePayload.
    // Chrome's OnDataAvailable() drains the sequencer via GetReadableRegion()+
    // MarkConsumed() and runs HttpDecoder, so QuicStreamSequencer::Readv is never
    // on the body path and QuicSpdyStream::Readv is inlined in release ARM64. This
    // visitor callback delivers the clean, de-framed HTTP/3 DATA body and survives
    // devirtualisation (it's dispatched through the HttpDecoder::Visitor* vtable
    // across the decoder TU boundary). args[0] is the HttpDecoderVisitor sub-object
    // (used here only as a stable per-stream session key); on ARM64 the by-value
    // std::__Cr::basic_string_view occupies x1 (data ptr) and x2 (length).
    if (onDataFramePayloadAddr && !onDataFramePayloadAddr.isNull()) {
        try {
            let odfpCount = 0;
            Interceptor.attach(onDataFramePayloadAddr, {
                onEnter(args) {
                    try {
                        const dataPtr = args[1];
                        const dataLen = args[2].toUInt32();
                        if (odfpCount < 8) {
                            odfpCount++;
                            devlog_debug(`[OnDataFramePayload] call #${odfpCount} in ${moduleName}: len=${dataLen} ptr=${dataPtr}`);
                        }
                        if (dataLen === 0 || dataPtr.isNull()) return;
                        const data = dataPtr.readByteArray(dataLen);
                        if (!data) return;
                        const message = resolveQuicMessage(args[0].toString(), "QuicSpdyStream_OnDataFramePayload");
                        sendQuicDatalog(message, data, -1);
                    } catch (e) {
                        devlog_error("[QuicSpdyStream_OnDataFramePayload] onEnter threw: " + e);
                    }
                },
            });
            log("[*] Hooked QuicSpdyStream::OnDataFramePayload for plaintext capture (incoming HTTP/3 body)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook OnDataFramePayload: " + e);
        }
    }

    // Diagnostic-only: prove the HTTP/3 stream reached the body stage even when
    // every Readv variant stays silent. Helps the next "no plaintext" report
    // distinguish "hook never fired" (attach problem) from "hook fired but
    // bytesRead=0 / iovec empty" (devirtualisation or wrong API).
    if (onBodyAvailableAddr && !onBodyAvailableAddr.isNull()) {
        try {
            let onBodyCount = 0;
            Interceptor.attach(onBodyAvailableAddr, {
                onEnter(args) {
                    if (onBodyCount < 5) {
                        onBodyCount++;
                        devlog_debug(`[QuicSpdyStream_OnBodyAvailable] call #${onBodyCount}: this=${args[0]}`);
                    }
                },
            });
            devlog("[*] Hooked QuicSpdyStream::OnBodyAvailable (diagnostic)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook OnBodyAvailable: " + e);
        }
    }

    // APP-API HEADERS PATH: QuicSpdyStream::OnHeadersDecoded.
    // Reliable incoming/response decoded-headers path. Corrected current-QUICHE
    // signature (verified):
    //   void QuicSpdyStream::OnHeadersDecoded(QuicHeaderList headers /*BY VALUE*/,
    //                                         bool header_list_size_limit_exceeded)
    // There is NO QuicStreamId argument. ARM64: x0 = this (QuicSpdyStream*),
    // x1 = pointer to the by-value QuicHeaderList temp, w2 = bool. We recover the
    // stream_id from `this`; QuicStream::id_'s struct offset is version-fragile
    // and not currently populated by the offsets config, so we fall back to the
    // existing -1 sentinel and rely on Python connection/flow correlation.
    //
    // Only installed in "app-api" capture mode (the default "stream" mode keeps
    // the raw-readv lower-boundary behaviour unchanged).
    //
    // The outgoing request-headers twin is QuicSpdyStream::WriteHeaders, hooked
    // separately below.
    if (quic_capture_mode === "app-api" && onHeadersDecodedAddr && !onHeadersDecodedAddr.isNull()) {
        try {
            let ohdCount = 0;
            Interceptor.attach(onHeadersDecodedAddr, {
                onEnter(args) {
                    try {
                        this.streamObj = args[0];          // QuicSpdyStream* this
                        this.headerList = args[1];          // pointer to by-value QuicHeaderList temp
                    } catch (e) {
                        devlog_error("[QuicSpdyStream_OnHeadersDecoded] onEnter threw: " + e);
                    }
                },
                onLeave(_retval) {
                    try {
                        if (!this.headerList || this.headerList.isNull()) return;
                        const headers = readQuicHeaderList(this.headerList);
                        if (headers.length === 0) return;
                        if (ohdCount < 8) {
                            ohdCount++;
                            devlog_debug(`[OnHeadersDecoded] call #${ohdCount} in ${moduleName}: ${headers.length} header(s)`);
                        }
                        // The real QUIC stream id would require a build-specific
                        // QuicStream::id_ offset. Instead use the QuicSpdyStream
                        // pointer's low 32 bits as a stable, per-stream surrogate
                        // key: distinct live streams have distinct addresses, and
                        // Python only needs a distinct positive integer to remap
                        // onto dense flow ids (the raw value is never displayed).
                        // This is what makes concurrent responses multiplex into
                        // separate flows instead of collapsing onto one.
                        const streamId = this.streamObj.toUInt32();
                        const message = resolveQuicMessage(this.streamObj.toString(), "QuicSpdyStream_OnHeadersDecoded");
                        sendQuicDatalog(message, null, streamId, undefined, undefined, "udp", headers);
                    } catch (e) {
                        devlog_error("[QuicSpdyStream_OnHeadersDecoded] onLeave threw: " + e);
                    }
                },
            });
            log("[*] Hooked QuicSpdyStream::OnHeadersDecoded for HTTP/3 header capture (incoming/response, app-api mode)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook OnHeadersDecoded: " + e);
        }
    }

    // APP-API HEADERS PATH (egress): QuicSpdyStream::WriteHeaders.
    //   size_t WriteHeaders(quiche::HttpHeaderBlock header_block /*BY VALUE*/,
    //                       bool fin, QuicheReferenceCountedPointer<...> ack_listener)
    // The outgoing/request twin of OnHeadersDecoded. ARM64: x0 = this
    // (QuicSpdyStream*) — the SAME stream object as OnHeadersDecoded, so the
    // pointer surrogate below correlates a request with its response into one
    // flow. x1 = pointer to the by-value HttpHeaderBlock temp. We read it before
    // it is QPACK-encoded, so keys + single-value headers (the pseudo-headers)
    // come out in clear. Multi-fragment values are best-effort.
    //
    // The HttpHeaderBlock struct-walk offsets (flat_hash_map size to reach the
    // std::list, and the InlinedVector inline element) are validated/self-located
    // at runtime and must be confirmed against a real libmonochrome arm64 build.
    if (quic_capture_mode === "app-api" && writeHeadersAddr && !writeHeadersAddr.isNull()) {
        try {
            let whCount = 0;
            Interceptor.attach(writeHeadersAddr, {
                onEnter(args) {
                    try {
                        const streamObj = args[0];          // QuicSpdyStream* this
                        const headerBlock = args[1];        // pointer to by-value HttpHeaderBlock temp
                        if (!headerBlock || headerBlock.isNull()) return;
                        const headers = readHttpHeaderBlock(headerBlock);
                        if (headers.length === 0) return;
                        if (whCount < 8) {
                            whCount++;
                            devlog_debug(`[WriteHeaders] call #${whCount} in ${moduleName}: ${headers.length} header(s)`);
                        }
                        // Same per-stream pointer surrogate as OnHeadersDecoded
                        // (this == the QuicSpdyStream), so request + response share
                        // a flow. Function name keeps Python's direction = write.
                        const streamId = streamObj.toUInt32();
                        const message = resolveQuicMessage(streamObj.toString(), "QuicSpdyStream_WriteHeaders");
                        sendQuicDatalog(message, null, streamId, undefined, undefined, "udp", headers);
                    } catch (e) {
                        devlog_error("[QuicSpdyStream_WriteHeaders] onEnter threw: " + e);
                    }
                },
            });
            log("[*] Hooked QuicSpdyStream::WriteHeaders for HTTP/3 header capture (outgoing/request, app-api mode)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook WriteHeaders: " + e);
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
                    const message = resolveQuicMessage(this.streamObj.toString(), "QuicSpdyStream_WriteOrBufferBody");
                    sendQuicDatalog(message, this.data, -1);
                },
            });
            log("[*] Hooked QuicSpdyStream::WriteOrBufferBody for plaintext capture");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook WriteOrBufferBody: " + e);
        }
    }
}
