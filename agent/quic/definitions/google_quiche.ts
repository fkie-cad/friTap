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
import { log, devlog, devlog_debug, devlog_error, hookBreadcrumb, _isShuttingDownNow } from "../../util/log.js";
import { pcap_enabled, getParsedPatterns, offsets, quic_capture_mode, quic_egress_headers_layer, debug_output } from "../../fritap_agent.js";
import { MANGLED_SYMBOLS, LABEL_TO_KEY, KEY_TO_LABEL } from "../shared/google_quiche_offsets.js";
import { quicConnectionTracker, buildQuicMessage, QuicConnectionInfo, ObservedPeer } from "../shared/quic_connection_tracker.js";
import { findNonExportedSymbols, getBaseAddress, decodeSockaddr } from "../../shared/shared_functions.js";
import { PatternStrategy } from "../../shared/strategies/pattern_strategy.js";
import { isReadable, safeReadPointer, safeReadU8, safeReadULong, safeReadUtf8, resetReadableCache } from "../../util/safe_memory.js";

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

// CHROME-SHIM unwrap cache. QuicChromiumClientStream holds the inner
// quic::QuicSpdyStream* at a build-specific small struct offset that drifts
// across Chrome versions. We probe candidate offsets on first invocation and
// cache the winning offset so subsequent unwraps are O(1). Per-process; resets
// only on agent reload. PROBE_FAILED short-circuits subsequent calls when no
// candidate ever satisfies the plausibility test on this build.
const CHROMIUM_INNER_PROBE_FAILED = -2;
let chromiumStreamInnerOffset: number = -1;

/**
 * Recover the inner quic::QuicSpdyStream* from a net::QuicChromiumClientStream*
 * wrapper. Chrome's QuicChromiumClientStream holds the underlying QuicSpdyStream
 * pointer at a build-specific small struct offset (the leading-member layout
 * varies with mojo/base/refcount mix-ins between Chromium versions). On first
 * call we probe a fixed candidate set; the first offset whose dereferenced value
 * passes plausibility checks wins. The winning offset is cached so subsequent
 * unwraps are O(1).
 *
 * Plausibility (in order of cost, cheapest first):
 *   (a) slot at [wrapper+off] is readable;
 *   (b) the alleged inner pointer is non-null and readable;
 *   (c) inner+0 (the vtable pointer) is non-null and readable;
 *   (d) vtable+0 (the first virtual function pointer) is non-null and points
 *       into an r-x range — QuicSpdyStream is polymorphic, so vtable[0] is
 *       always code;
 *   (e) the r-x range hosting vtable[0] lives in the SAME loaded module as
 *       the wrapper, OR in a known Cronet-family module
 *       (libcronet*, libmainlinecronet*, libmonochrome*). This is the
 *       fuzzy-match-trap mitigation: a sibling field that happens to point
 *       at another polymorphic object from libc++ or libutils would pass
 *       (a)–(d) on its own.
 *
 * Everything runs under a try/catch so a wild dereference during probing
 * cannot crash the host process or other concurrent hooks — a failure
 * returns null and the caller (the chrome-shim onEnter) skips the call.
 *
 * Per-probe debug breakdown is gated by `debug_output` (Python `-do` flag)
 * because it walks Process.findRangeByAddress / Process.findModuleByAddress
 * for every candidate, which would be wasteful in normal runs.
 *
 * Returns null when no probe succeeds. Caller MUST guard the result.
 */
function unwrapChromiumClientStream(wrapperPtr: NativePointer): NativePointer | null {
    try {
        if (!wrapperPtr || wrapperPtr.isNull()) return null;
        resetReadableCache();

        const wrapperModule = (() => {
            try { return Process.findModuleByAddress(wrapperPtr); } catch (_e) { return null; }
        })();

        // Cronet ships under three umbrella names depending on host (bundled
        // libcronet inside an app, mainline-Cronet APEX, or the Chrome
        // libmonochrome super-binary). vtable[0] of an inner QuicSpdyStream
        // must land in one of these — or in the wrapper's own module — to
        // count as plausible.
        const isCronetFamilyModule = (m: Module | null): boolean => {
            if (!m) return false;
            const n = m.name.toLowerCase();
            return n.startsWith("libcronet")
                || n.startsWith("libmainlinecronet")
                || n.startsWith("libmonochrome");
        };

        const moduleSameOrCronet = (m: Module | null): boolean => {
            if (!m) return false;
            if (wrapperModule && m.name === wrapperModule.name) return true;
            return isCronetFamilyModule(m);
        };

        // Post-deref plausibility chain: given an alleged inner pointer, verify
        // vtable → vtable[0] → vtable[0]'s module match the wrapper or a known
        // Cronet-family module. Returns the validated inner pointer or null.
        // The `off` parameter is threaded through only so per-failure diagnostic
        // messages can pinpoint which candidate offset is being rejected.
        const validateChromiumInner = (off: number, inner: NativePointer): NativePointer | null => {
            if (!isReadable(inner, Process.pointerSize)) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} inner=${inner} not readable`);
                }
                return null;
            }
            const vtable = safeReadPointer(inner);
            if (vtable === null || vtable.isNull() || !isReadable(vtable, Process.pointerSize)) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} vtable=${vtable} not readable`);
                }
                return null;
            }
            const firstFn = safeReadPointer(vtable);
            if (firstFn === null || firstFn.isNull()) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} vtable[0]=null`);
                }
                return null;
            }
            let r: RangeDetails | null = null;
            try { r = Process.findRangeByAddress(firstFn); } catch (_e) { r = null; }
            if (!r || r.protection.indexOf("x") < 0) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} vtable[0]=${firstFn} not in r-x range`);
                }
                return null;
            }
            let vtblModule: Module | null = null;
            try { vtblModule = Process.findModuleByAddress(firstFn); } catch (_e) { vtblModule = null; }
            if (!moduleSameOrCronet(vtblModule)) {
                if (debug_output) {
                    const where = vtblModule
                        ? `${vtblModule.name}+0x${firstFn.sub(vtblModule.base).toString(16)}`
                        : `<unknown range>`;
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} vtable[0]=${firstFn} ` +
                                 `(in ${where}) is NOT in wrapper module (${wrapperModule ? wrapperModule.name : "?"}) ` +
                                 `or a Cronet-family module — rejecting as false positive`);
                }
                return null;
            }
            if (debug_output) {
                const where = vtblModule
                    ? `${vtblModule.name}+0x${firstFn.sub(vtblModule.base).toString(16)}`
                    : `<unknown>`;
                devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} PLAUSIBLE inner=${inner} ` +
                             `vtable=${vtable} vtable[0]=${firstFn} (in ${where})`);
            }
            return inner;
        };

        // Single per-probe routine. Returns the inner pointer if plausible,
        // null otherwise. The slot-readability + slot-dereference live here
        // because they are coupled to the candidate offset; the post-deref
        // plausibility chain is delegated to validateChromiumInner.
        const tryOffset = (off: number): NativePointer | null => {
            const slot = wrapperPtr.add(off);
            if (!isReadable(slot, Process.pointerSize)) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} slot=${slot} not readable`);
                }
                return null;
            }
            const inner = safeReadPointer(slot);
            if (inner === null || inner.isNull()) {
                if (debug_output) {
                    devlog_debug(`[unwrapChromiumClientStream] off=0x${off.toString(16)} inner=null`);
                }
                return null;
            }
            return validateChromiumInner(off, inner);
        };

        if (chromiumStreamInnerOffset >= 0) {
            const cached = tryOffset(chromiumStreamInnerOffset);
            if (cached) return cached;
            // Cache stale (rare; e.g. host loaded two Cronet builds). Re-probe
            // silently rather than returning null on a transient unmapped page.
            devlog_debug(
                `[unwrapChromiumClientStream] cached offset 0x${chromiumStreamInnerOffset.toString(16)} ` +
                `failed plausibility for wrapper=${wrapperPtr}; re-probing`
            );
        }
        if (chromiumStreamInnerOffset === CHROMIUM_INNER_PROBE_FAILED) return null;

        for (const off of [8, 16, 24, 32, 40, 48]) {
            const inner = tryOffset(off);
            if (inner) {
                chromiumStreamInnerOffset = off;
                devlog(`[unwrapChromiumClientStream] resolved inner QuicSpdyStream offset = 0x${off.toString(16)}` +
                       ` (wrapper module = ${wrapperModule ? wrapperModule.name : "?"})`);
                return inner;
            }
        }
        chromiumStreamInnerOffset = CHROMIUM_INNER_PROBE_FAILED;
        devlog(`[unwrapChromiumClientStream] no candidate offset matched for wrapper=${wrapperPtr}; ` +
               `chain fallback will use the wrapper ptr as streamKey (degraded correlation)`);
        return null;
    } catch (e) {
        // Outer guard: any unexpected fault (e.g. Process.findRangeByAddress
        // throwing on a permission edge case) MUST NOT crash the host or
        // affect sibling hooks. Mark the cache as probe-failed so we don't
        // re-attempt every call, log once, and return null.
        chromiumStreamInnerOffset = CHROMIUM_INNER_PROBE_FAILED;
        devlog_error(`[unwrapChromiumClientStream] unexpected fault: ${e} (probing disabled for this attach)`);
        return null;
    }
}

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
    resetReadableCache();

    for (let i = 0; i < iovLen && remaining > 0; i++) {
        // Per-entry guard: a single unmapped iov_base/garbage entry must not
        // SIGSEGV the target (JS try/catch won't catch a native fault) nor abort
        // the whole read. isReadable validates before each dereference.
        try {
            const entry = iovPtr.add(i * iovecSize);
            if (!isReadable(entry, iovecSize)) continue;
            const base = entry.readPointer();
            const len = (entry.add(ptrSize).readULong() as unknown) as number;
            if (base.isNull() || len === 0) continue;
            const toRead = Math.min(len, remaining);
            if (!isReadable(base, toRead)) continue;
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
/** Diagnostic: hex of the first N bytes at p, or a sentinel on fault/null. */
function _hexHead(p: NativePointer, n = 32): string {
    try {
        if (!p || p.isNull()) return "<null>";
        // hexdump dereferences p natively; guard readability first so a bad
        // diagnostic pointer cannot SIGSEGV the target (try/catch won't save us).
        if (!isReadable(p, n)) return "<unreadable>";
        return hexdump(p, { length: n, header: false, ansi: false }).replace(/\n/g, " | ");
    } catch (e) {
        return "<unreadable>";
    }
}

function readLibcxxString(p: NativePointer): string {
    try {
        const first = safeReadU8(p);
        if (first === null) return "";
        if (first & 1) {                                 // long form
            const size = safeReadULong(p.add(8));
            const dataPtr = safeReadPointer(p.add(16));
            if (size === null || dataPtr === null || dataPtr.isNull() || size <= 0 || size > (1 << 20)) return "";
            return safeReadUtf8(dataPtr, size);
        }
        const size = first >> 1;                          // short / SSO
        if (size <= 0 || size > 22) return "";
        return safeReadUtf8(p.add(1), size);
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
    resetReadableCache();
    try {
        const begin = safeReadULong(hl);
        const end   = safeReadULong(hl.add(8));
        const data  = safeReadPointer(hl.add(16));
        const cap   = safeReadULong(hl.add(24));
        if (begin === null || end === null || cap === null) return out;
        if (data === null || data.isNull() || cap <= 0 || cap > 65536) return out;
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
        const ptr = safeReadPointer(p);
        const len = safeReadULong(p.add(8));
        if (ptr === null || len === null || ptr.isNull() || len <= 0 || len > (1 << 20)) return "";
        return safeReadUtf8(ptr, len);
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
        const meta = safeReadULong(hv.add(8));   // fragments_ metadata
        if (meta === null) return "";
        const allocated = meta & 1;
        const count = meta >> 1;
        if (count <= 0) return "";
        let svPtr: NativePointer;
        if (!allocated) {
            svPtr = hv.add(16);                      // inline string_view[0]
        } else {
            const heap = safeReadPointer(hv.add(16));        // heap array of string_view
            if (heap === null || heap.isNull()) return "";
            svPtr = heap;
        }
        return readStringView(svPtr);
    } catch (e) {
        return "";
    }
}

/** True if `listObj` looks like a well-formed libc++ std::list object. */
function _looksLikeStdList(listObj: NativePointer): boolean {
    try {
        const size = safeReadULong(listObj.add(16));
        if (size === null || size <= 0 || size > 1000) return false;
        const sentinel = listObj;                     // address of __end_
        const first = safeReadPointer(listObj.add(8));   // __end_.__next_ (first node)
        if (first === null || first.isNull() || first.equals(sentinel)) return false;
        // first node's __prev_ (at +0) must point back to the sentinel node.
        // first is a GUESSED offset here (7-probe self-location) — safeReadPointer
        // prevents a SIGSEGV when the guess lands on unmapped memory.
        const prev = safeReadPointer(first);
        return prev !== null && prev.equals(sentinel);
    } catch (e) {
        return false;
    }
}

/**
 * Diagnostic: emit the "read 0 headers" probe line shared by the three egress-
 * headers installers (quiche-internal, chrome-shim, session-level). Walks the
 * same candidate offsets `readHttpHeaderBlock` self-locates against so the user
 * can see which slot (if any) looked like a std::list on this build.
 */
function _dumpEmptyHeaderBlockProbe(label: string, headerBlock: NativePointer): void {
    const probes = [16, 24, 32, 40, 48, 56, 64]
        .map(o => `${o}:${_looksLikeStdList(headerBlock.add(o)) ? "list" : "-"}`).join(" ");
    devlog_debug(`[${label}] read 0 headers; raw=${_hexHead(headerBlock)} probes=[${probes}]`);
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
    resetReadableCache();
    try {
        for (const off of [16, 24, 32, 40, 48, 56, 64]) {
            const listObj = hhb.add(off);
            if (!_looksLikeStdList(listObj)) continue;
            const sentinel = listObj;
            let node = safeReadPointer(listObj.add(8));   // first real node
            if (node === null) continue;
            let guard = 0;
            while (!node.isNull() && !node.equals(sentinel) && guard < maxPairs) {
                const pair = node.add(16);             // __value_ = pair<string_view, HeaderValue>
                const key = readStringView(pair);      // key absl::string_view @ +0
                const val = readHeaderValue(pair.add(16)); // HeaderValue @ +16
                if (key.length > 0) out.push([key, val]);
                const next = safeReadPointer(node.add(8));      // __next_
                if (next === null) break;
                node = next;
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
            // Detach-time short-circuit: bail before the iovec walk + message
            // build so callbacks already queued at gracefulDetach drain in
            // microseconds instead of doing heavy work the result of which is
            // discarded by the sendDatalog gate anyway.
            if (_isShuttingDownNow()) return;
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

// Per-chain-label keyword filters used by dumpChainCandidatesDebug to narrow
// the dynsym scan to symbols that even *look* like the function we're after.
// A loose filter (e.g. just "WriteHeaders") returns thousands of hits on
// libmonochrome — too noisy to be useful. The token sets below are derived
// from each function's fully qualified C++ name.
const CHAIN_CANDIDATE_KEYWORDS: Partial<Record<keyof typeof MANGLED_SYMBOLS, string[][]>> = {
    // QuicSpdyStream::WriteHeaders — must contain BOTH "QuicSpdyStream" and "WriteHeaders".
    writeHeaders: [["QuicSpdyStream", "WriteHeaders"]],
    // net::QuicChromiumClientStream::WriteHeaders — chrome shim.
    quicChromiumClientStreamWriteHeaders: [["ChromiumClientStream", "WriteHeaders"]],
    // QuicSpdySession::WriteHeadersOnHeadersStream — session-level gQUIC.
    quicSpdySessionWriteHeadersOnHeadersStream: [["WriteHeadersOnHeadersStream"]],
};

const CHAIN_LABEL_PRETTY: Partial<Record<keyof typeof MANGLED_SYMBOLS, string>> = {
    writeHeaders: "QuicSpdyStream::WriteHeaders",
    quicChromiumClientStreamWriteHeaders: "net::QuicChromiumClientStream::WriteHeaders",
    quicSpdySessionWriteHeadersOnHeadersStream: "quic::QuicSpdySession::WriteHeadersOnHeadersStream",
};

/**
 * Per-range async scan helper used by the chain debug dump. Collects ALL match
 * addresses in [base, base+size) via the non-blocking Memory.scan so the -do
 * diagnostic never holds the JS thread (and thus the gracefulDetach RPC) across
 * a full r-x sweep of a ~193 MB stripped module.
 */
function scanRangeAllAsync(base: NativePointer, size: number, pattern: string): Promise<NativePointer[]> {
    return new Promise((resolve) => {
        const acc: NativePointer[] = [];
        try {
            Memory.scan(base, size, pattern, {
                onMatch: (address) => { acc.push(address); },
                onError: () => { /* skip unreadable pages */ },
                onComplete: () => resolve(acc),
            });
        } catch (_e) {
            resolve(acc);
        }
    });
}

/**
 * Debug-only enumeration of every plausible candidate for the three chain
 * labels (quiche-internal WriteHeaders, chrome-shim WriteHeaders, session-
 * level WriteHeadersOnHeadersStream). Walks the export table, the dynsym
 * table (filtered through CHAIN_CANDIDATE_KEYWORDS), and an async Memory.scan
 * for every pattern listed under that label in quic_patterns.json, then
 * prints a per-label summary so the user can sanity-check why a particular
 * address was picked — especially useful when the mangled name is a best-
 * effort guess and the symbol-table strategy resolves to something wrong.
 *
 * Gated by `debug_output` because the dynsym walk on libmonochrome (~193 MB)
 * is expensive — wasteful when the user did not pass `-do`. Skipped silently
 * otherwise.
 */
async function dumpChainCandidatesDebug(
    moduleName: string,
    resolved: Map<keyof typeof MANGLED_SYMBOLS, NativePointer>
): Promise<void> {
    if (!debug_output) return;
    // Bail if a detach is already in flight: this -do-only diagnostic sweeps
    // every r-x range. Scanning is async (Memory.scan) so it no longer blocks
    // the gracefulDetach RPC, but there is no point starting the walk once
    // detach has begun.
    if (_isShuttingDownNow()) return;
    let mod: Module | null = null;
    try { mod = Process.findModuleByName(moduleName); } catch (_e) { mod = null; }
    if (!mod) {
        devlog_debug(`[chain-debug] module ${moduleName} not loaded; skipping enumeration`);
        return;
    }

    const chainKeys = Object.keys(CHAIN_CANDIDATE_KEYWORDS) as Array<keyof typeof MANGLED_SYMBOLS>;

    // Walk dynsym ONCE, bucketing matches per chain key. Avoids three full
    // enumerateSymbols() passes on huge stripped binaries.
    const symHitsByKey: Map<keyof typeof MANGLED_SYMBOLS, Array<{ name: string; address: NativePointer }>> =
        new Map(chainKeys.map(k => [k, [] as Array<{ name: string; address: NativePointer }>]));
    try {
        for (const sym of mod.enumerateSymbols()) {
            if (!sym.name || !sym.address || sym.address.isNull()) continue;
            for (const key of chainKeys) {
                const tokenSets = CHAIN_CANDIDATE_KEYWORDS[key] || [];
                const matched = tokenSets.find(tokens => tokens.every(t => sym.name.includes(t)));
                if (matched) {
                    symHitsByKey.get(key)!.push({ name: sym.name, address: sym.address });
                }
            }
        }
    } catch (e) {
        devlog_debug(`[chain-debug] enumerateSymbols failed in ${moduleName}: ${e}`);
    }

    // Pattern enumeration per chain label. Replays the same scan that
    // PatternStrategy does (now via async Memory.scan), but counts ALL matches
    // rather than stopping at the first one. Helps surface the blog's
    // "uniqueness failure" hazard (two pattern hits would land separate
    // addresses for the same label).
    const parsed = getParsedPatterns();
    let ranges: RangeDetails[] = [];
    try { ranges = mod.enumerateRanges("r-x"); } catch (_e) { ranges = []; }

    for (const key of chainKeys) {
        const pretty = CHAIN_LABEL_PRETTY[key] || (key as string);
        const label = KEY_TO_LABEL[key];
        const picked = resolved.get(key);
        const pickedStr = picked ? picked.toString() : "<unresolved>";

        // 1. Exports
        const mangled = getMangledSymbol(key);
        let exportHit: NativePointer | null = null;
        try {
            exportHit = mangled ? mod.findExportByName(mangled) : null;
        } catch (_e) { exportHit = null; }

        // 2. Dynsym hits (already bucketed above)
        const symHits = symHitsByKey.get(key) || [];

        // 3. Pattern hits — walk every pattern for this label and count matches.
        let patternMatchCount = 0;
        const patternMatches: NativePointer[] = [];
        if (parsed && label && ranges.length > 0) {
            const lib = parsed[moduleName] || parsed["google_quiche"];
            const arch = lib && (lib[Process.arch] || lib["default"]);
            const labelPatterns = arch && arch[label];
            const patternsList = Array.isArray(labelPatterns) ? labelPatterns : (labelPatterns ? [labelPatterns] : []);
            for (const pattern of patternsList) {
                for (const range of ranges) {
                    if (_isShuttingDownNow()) break;
                    try {
                        const ms = await scanRangeAllAsync(range.base, range.size, pattern);
                        for (const m of ms) {
                            patternMatchCount++;
                            if (patternMatches.length < 8) patternMatches.push(m);
                        }
                    } catch (_e) { /* skip unreadable range */ }
                }
            }
        }

        devlog_debug(
            `[chain-debug] label=${label || "?"} (${pretty})` +
            ` picked=${pickedStr}` +
            ` exports=${exportHit ? exportHit.toString() : "<none>"}` +
            ` symtab_hits=${symHits.length}` +
            ` pattern_hits=${patternMatchCount}`
        );
        dumpHits("symtab", symHits, 5, s => `${s.address} ${s.name}`);
        // Pattern hits use the SHOWN count (cap=8) as the "shown" universe but
        // the TRUE total for the "... and N more" line, since we stopped pushing
        // into patternMatches after 8 to bound memory. Pass patternMatchCount via
        // a wrapper array so dumpHits prints the right delta.
        dumpHits("pattern", patternMatches, 8, a => `${a}`);
        if (patternMatchCount > patternMatches.length) {
            devlog_debug(`[chain-debug]    pattern: ... and ${patternMatchCount - patternMatches.length} more`);
        }
        if (patternMatchCount > 1) {
            devlog_debug(`[chain-debug]    WARNING: pattern matched ${patternMatchCount} sites — ` +
                         `uniqueness failure risk (see blog's PersistentSampleVector case)`);
        }
    }
}

/**
 * Emit up to `maxShown` rendered hits with a "... and N more" trailer when the
 * list was truncated. Centralises the bucket-printing pattern shared by the
 * symtab and pattern enumeration in dumpChainCandidatesDebug. The uniqueness-
 * failure WARNING stays at the call site — it is a different concern from the
 * truncation trailer.
 */
function dumpHits<T>(linePrefix: string, hits: T[], maxShown: number, render: (h: T) => string): void {
    if (hits.length === 0) return;
    const shown = hits.slice(0, maxShown);
    for (const h of shown) {
        devlog_debug(`[chain-debug]    ${linePrefix}: ${render(h)}`);
    }
    if (hits.length > shown.length) {
        devlog_debug(`[chain-debug]    ${linePrefix}: ... and ${hits.length - shown.length} more`);
    }
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
 * 3. Byte-pattern scan (stripped libs, e.g. libmonochrome / libcronet)
 *
 * NOTE: a DebugSymbol.findFunctionsNamed() strategy was intentionally removed —
 * on Android/Cronet it triggers cross-module debug-info parsing that SIGSEGVs the
 * target process (uncatchable native fault; reproduced on YouTube/libmainlinecronet
 * via research/quiche_repro/). Symbol-table + byte-pattern cover resolution without it.
 */
async function resolveQuicheSymbols(moduleName: string): Promise<Map<keyof typeof MANGLED_SYMBOLS, NativePointer>> {
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

    // (Former Strategy 3 — DebugSymbol.findFunctionsNamed — removed: it SIGSEGVs the
    // Cronet target on Android. Resolution now relies on the symbol table above and
    // the byte-pattern scan below.)

    // --- Strategy 3: byte-pattern scan (stripped libs, e.g. libmonochrome/libcronet) ---
    // Symbols (1-2) always win; patterns only fill still-missing keys. Reuses the
    // PatternStrategy libtype lookup + async Memory.scan (tryHookAsync) + `?`
    // wildcards verbatim.
    let missing = (Object.keys(MANGLED_SYMBOLS) as (keyof typeof MANGLED_SYMBOLS)[])
        .filter(k => !resolved.has(k));
    if (missing.length > 0) {
        const parsed = getParsedPatterns();
        if (parsed) {
            const labels = missing.map(k => KEY_TO_LABEL[k]).filter(Boolean);
            try {
                const ps = new PatternStrategy(parsed);
                const res = await ps.tryHookAsync(moduleName, "google_quiche", labels);
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

    // --- Strategy 4: static offsets (manual override / fallback) ---
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

    // Debug-only: dump every candidate considered for the three chain labels
    // (exports + symtab hits + pattern hits) plus which one we picked. No-op
    // when `-do` / debug_output is off, so the expensive dynsym walk only
    // runs when the user actually wants the diagnostic.
    await dumpChainCandidatesDebug(moduleName, resolved);

    return resolved;
}

/**
 * Install Google QUICHE hooks on a Chrome/Cronet module.
 *
 * This is NOT a standard HookDefinition — it uses a custom installation
 * approach because the target functions are C++ mangled virtual methods
 * that don't fit the standard symbol resolution pipeline.
 */
export async function installGoogleQuicheHooks(moduleName: string): Promise<void> {
    if (!pcap_enabled) return;
    log("[*] Google QUICHE: attempting to hook QuicSpdyStream in " + moduleName);

    // Best-effort real-peer recovery (process-wide, installed once). Kept BEFORE
    // the await: it is a cheap synchronous libc Interceptor.attach with no scan
    // dependency, and we want the UDP-peer observer live during the (now async)
    // symbol-resolution window.
    installQuicSocketObserver();

    // Batched resolution: single enumerateSymbols() pass for all QUICHE symbols.
    // Awaited because the pattern-scan fallback (Strategy 3) now uses the async
    // Memory.scan so the JS thread can service a gracefulDetach RPC mid-scan.
    const resolved = await resolveQuicheSymbols(moduleName);
    const readvAddr = resolved.get("readv") || null;
    const quicStreamReadvAddr = resolved.get("quicStreamReadv") || null;
    const sequencerReadvAddr = resolved.get("sequencerReadv") || null;
    const onBodyAvailableAddr = resolved.get("onBodyAvailable") || null;
    const writeAddr = resolved.get("writeOrBufferBody") || null;
    const onDataFramePayloadAddr = resolved.get("onDataFramePayload") || null;
    const onHeadersDecodedAddr = resolved.get("onHeadersDecoded") || null;
    const writeHeadersAddr = resolved.get("writeHeaders") || null;
    // PHASE-2 CHAIN-FALLBACK addresses. Resolved through the same pattern path
    // as writeHeadersAddr (Strategy 3 in resolveQuicheSymbols); attached
    // selectively below as a winner-takes-all chain. Patterns live in
    // quic_patterns.json; mangled names in MANGLED_SYMBOLS are best-effort and
    // only matter on unstripped builds (every Cronet release strips them).
    const chromiumWriteHeadersAddr = resolved.get("quicChromiumClientStreamWriteHeaders") || null;
    const sessionWriteHeadersOnHeadersStreamAddr = resolved.get("quicSpdySessionWriteHeadersOnHeadersStream") || null;

    // FORCE-MODE shadowing for --quic-egress-headers-layer. The flag selects
    // exactly one layer of the egress-headers chain; the other two are null'd
    // out before any installer runs so the existing winner-takes-all guards
    // produce the intended single-layer attach without further branching.
    // "auto" leaves all three addresses untouched (default chain behaviour).
    // An unrecognised value falls through to "auto" with a one-line warning
    // — this keeps a typo from silently disabling all three layers.
    let effectiveWriteHeadersAddr: NativePointer | null = writeHeadersAddr;
    let effectiveChromiumWriteHeadersAddr: NativePointer | null = chromiumWriteHeadersAddr;
    let effectiveSessionWriteHeadersOnHeadersStreamAddr: NativePointer | null = sessionWriteHeadersOnHeadersStreamAddr;
    const requestedLayer = quic_egress_headers_layer || "auto";
    let forcedLayerActive = false;
    switch (requestedLayer) {
        case "auto":
            break;
        case "quiche-internal":
            effectiveChromiumWriteHeadersAddr = null;
            effectiveSessionWriteHeadersOnHeadersStreamAddr = null;
            forcedLayerActive = true;
            break;
        case "chrome-shim":
            effectiveWriteHeadersAddr = null;
            effectiveSessionWriteHeadersOnHeadersStreamAddr = null;
            forcedLayerActive = true;
            break;
        case "session-level":
            effectiveWriteHeadersAddr = null;
            effectiveChromiumWriteHeadersAddr = null;
            forcedLayerActive = true;
            break;
        default:
            log(`[!] Google QUICHE: unrecognised --quic-egress-headers-layer="${requestedLayer}"; ` +
                `falling back to "auto" (chain behaviour unchanged)`);
            break;
    }
    if (forcedLayerActive) {
        log(`[*] Google QUICHE: --quic-egress-headers-layer=${requestedLayer} (forced; ` +
            `other egress-headers layers will NOT be installed even if their patterns resolve)`);
    }

    // "Are ANY useful hooks installable?" gate. Previously this only inspected the
    // five stream-level addresses (readv, write, quicStreamReadv, sequencerReadv,
    // onDataFramePayload). That bug discarded already-resolved chain candidates on
    // stripped libmonochrome — where the chain-fallback patterns resolve but the
    // five primaries don't — and silently produced an empty pcap. Include the
    // app-api header addresses AND the two chain candidates so the chain installer
    // gets a chance to run when those are the only things we resolved.
    const hasAnyResolvedAddress = !!(
        readvAddr || writeAddr || quicStreamReadvAddr || sequencerReadvAddr || onDataFramePayloadAddr
        || onHeadersDecodedAddr || writeHeadersAddr
        || chromiumWriteHeadersAddr || sessionWriteHeadersOnHeadersStreamAddr
    );
    if (!hasAnyResolvedAddress) {
        devlog("[Google QUICHE] could not resolve any stream functions in " + moduleName);
        devlog("[Google QUICHE] note: stripped release builds require byte patterns in default_patterns.json");
        // Emit a chain-summary line so the user sees an explicit "NONE" outcome
        // for this module rather than silence. Mirrors the per-attach summary at
        // the end of installGoogleQuicheHooks for consistency.
        if (quic_capture_mode === "app-api") {
            log(`[*] Google QUICHE egress headers chain in ${moduleName}: active layer = NONE (no addresses resolved on this module)`);
        }
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
                    if (_isShuttingDownNow()) return;
                    try {
                        const dataPtr = args[1];
                        const dataLen = args[2].toUInt32();
                        if (odfpCount < 8) {
                            odfpCount++;
                            devlog_debug(`[OnDataFramePayload] call #${odfpCount} in ${moduleName}: len=${dataLen} ptr=${dataPtr}`);
                        }
                        if (dataLen === 0 || dataPtr.isNull()) return;
                        // Symbol-resolved Cronet addresses can yield garbage
                        // args; guard the read so a bad ptr/len skips instead of
                        // SIGSEGV-ing the target (JS try/catch won't catch that).
                        resetReadableCache();
                        if (dataLen > (16 << 20) || !isReadable(dataPtr, dataLen)) {
                            devlog_debug(`[OnDataFramePayload] unreadable data ptr=${dataPtr} len=${dataLen} -> skip`);
                            return;
                        }
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
                    if (_isShuttingDownNow()) return;
                    try {
                        this.streamObj = args[0];          // QuicSpdyStream* this
                        this.headerList = args[1];          // pointer to by-value QuicHeaderList temp
                        // FIRED log makes "never-fired" distinguishable from
                        // "fired-but-read-0-headers" (which was previously silent).
                        devlog_debug(`[OnHeadersDecoded] FIRED this=${this.streamObj} headerList=${this.headerList}`);
                    } catch (e) {
                        devlog_error("[QuicSpdyStream_OnHeadersDecoded] onEnter threw: " + e);
                    }
                },
                onLeave(_retval) {
                    if (_isShuttingDownNow()) return;
                    try {
                        if (!this.headerList || this.headerList.isNull()) {
                            devlog_debug("[OnHeadersDecoded] headerList null -> skip");
                            return;
                        }
                        hookBreadcrumb(`QuicSpdyStream::OnHeadersDecoded reading QuicHeaderList this=${this.streamObj} headerList=${this.headerList}`);
                        const headers = readQuicHeaderList(this.headerList);
                        if (headers.length === 0) {
                            // Dump the raw struct + computed deque fields so the
                            // QuicHeaderList offsets can be validated on-device.
                            const hl = this.headerList;
                            let begin = -1, end = -1, cap = -1, data = "<?>";
                            try {
                                resetReadableCache();
                                const b = safeReadULong(hl);              if (b !== null) begin = b;
                                const e2 = safeReadULong(hl.add(8));      if (e2 !== null) end = e2;
                                const d = safeReadPointer(hl.add(16));    if (d !== null) data = d.toString();
                                const c = safeReadULong(hl.add(24));      if (c !== null) cap = c;
                            } catch (e) { /* keep sentinels */ }
                            devlog_debug(`[OnHeadersDecoded] read 0 headers; raw=${_hexHead(hl)} begin=${begin} end=${end} data=${data} cap=${cap} size=${end - begin}`);
                            return;
                        }
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
    if (quic_capture_mode === "app-api" && effectiveWriteHeadersAddr && !effectiveWriteHeadersAddr.isNull()) {
        try {
            let whCount = 0;
            Interceptor.attach(effectiveWriteHeadersAddr, {
                onEnter(args) {
                    if (_isShuttingDownNow()) return;
                    try {
                        const streamObj = args[0];          // QuicSpdyStream* this
                        const headerBlock = args[1];        // pointer to by-value HttpHeaderBlock temp
                        devlog_debug(`[WriteHeaders] FIRED this=${streamObj} headerBlock=${headerBlock}`);
                        if (!headerBlock || headerBlock.isNull()) return;
                        hookBreadcrumb(`QuicSpdyStream::WriteHeaders reading HttpHeaderBlock this=${streamObj} headerBlock=${headerBlock}`);
                        const headers = readHttpHeaderBlock(headerBlock);
                        if (headers.length === 0) {
                            // Show which probe offsets looked like a std::list so
                            // the HttpHeaderBlock layout can be validated on-device.
                            _dumpEmptyHeaderBlockProbe("WriteHeaders", headerBlock);
                            return;
                        }
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

    // PHASE-2 CHAIN FALLBACK #1: net::QuicChromiumClientStream::WriteHeaders.
    // Chrome shim that wraps the quiche-internal QuicSpdyStream::WriteHeaders.
    // Only installed when the quiche-internal hook above did NOT resolve —
    // winner-takes-all topology, so a given target sees exactly one egress-
    // headers interceptor and the Python flow collector never sees duplicate
    // header chunks for the same (stream, request) pair.
    //
    // ABI gotcha: args[0] is the QuicChromiumClientStream* wrapper, NOT the
    // inner QuicSpdyStream*. We unwrap to recover the inner pointer and use
    // ITS low 32 bits as the surrogate stream id, so the request (here) and
    // the response (OnHeadersDecoded on the inner QuicSpdyStream) collapse
    // into one flow on Python's conn.map_qsid.
    //
    // HttpHeaderBlock is the SECOND arg (args[1]) — same layout as the
    // quiche-internal hook — because the chrome shim's signature mirrors the
    // quiche method's exactly.
    const wroteWriteHeadersHook = !!effectiveWriteHeadersAddr && !effectiveWriteHeadersAddr.isNull();
    if (quic_capture_mode === "app-api" && !wroteWriteHeadersHook
        && effectiveChromiumWriteHeadersAddr && !effectiveChromiumWriteHeadersAddr.isNull()) {
        try {
            let cwhCount = 0;
            Interceptor.attach(effectiveChromiumWriteHeadersAddr, {
                onEnter(args) {
                    if (_isShuttingDownNow()) return;
                    try {
                        const wrapperObj = args[0];          // QuicChromiumClientStream*
                        const headerBlock = args[1];         // pointer to by-value HttpHeaderBlock temp
                        devlog_debug(`[ChromiumClientStream_WriteHeaders] FIRED wrapper=${wrapperObj} headerBlock=${headerBlock}`);
                        if (!headerBlock || headerBlock.isNull()) return;
                        const innerStream = unwrapChromiumClientStream(wrapperObj);
                        if (!innerStream) {
                            devlog_debug(`[ChromiumClientStream_WriteHeaders] unwrap failed for wrapper=${wrapperObj} -> skip`);
                            return;
                        }
                        hookBreadcrumb(`QuicChromiumClientStream::WriteHeaders reading HttpHeaderBlock wrapper=${wrapperObj} inner=${innerStream} headerBlock=${headerBlock}`);
                        const headers = readHttpHeaderBlock(headerBlock);
                        if (headers.length === 0) {
                            _dumpEmptyHeaderBlockProbe("ChromiumClientStream_WriteHeaders", headerBlock);
                            return;
                        }
                        if (cwhCount < 8) {
                            cwhCount++;
                            devlog_debug(`[ChromiumClientStream_WriteHeaders] call #${cwhCount} in ${moduleName}: ${headers.length} header(s)`);
                        }
                        // Inner QuicSpdyStream pointer's low 32 bits — SAME
                        // surrogate that OnHeadersDecoded emits, so request
                        // pairs with its response in Python's map_qsid.
                        const streamId = innerStream.toUInt32();
                        const message = resolveQuicMessage(innerStream.toString(), "QuicChromiumClientStream_WriteHeaders");
                        sendQuicDatalog(message, null, streamId, undefined, undefined, "udp", headers);
                    } catch (e) {
                        devlog_error("[QuicChromiumClientStream_WriteHeaders] onEnter threw: " + e);
                    }
                },
            });
            log("[*] Hooked net::QuicChromiumClientStream::WriteHeaders for HTTP/3 header capture (outgoing/request, app-api mode, chain-fallback)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook QuicChromiumClientStream::WriteHeaders: " + e);
        }
    }

    // PHASE-2 CHAIN FALLBACK #2: quic::QuicSpdySession::WriteHeadersOnHeadersStream.
    // Session-level gQUIC path used when BOTH the quiche-internal
    // QuicSpdyStream::WriteHeaders and the chrome shim above failed to resolve.
    //
    // ABI (ARM64):
    //   args[0] = QuicSpdySession*  (NOT a stream — we use it only as the
    //                                resolveQuicMessage key; coarse but it's
    //                                the only handle available at this layer)
    //   args[1] = QuicStreamId      (uint32_t — read low 32 bits; this is the
    //                                REAL stream id from quiche, used directly
    //                                as the surrogate)
    //   args[2] = HttpHeaderBlock*  (NOTE: shifted right by one slot vs the
    //                                stream-level hook — ABI gotcha)
    //   args[3] = bool fin
    //
    // CAVEAT: the surrogate (QuicStreamId from args[1]) lives in a DIFFERENT
    // namespace from the QuicSpdyStream-pointer surrogate used by
    // OnHeadersDecoded, so when this layer wins the request and response will
    // appear as two separate flows in the Python output. This is acceptable —
    // the session-level hook is the lowest tier of defense and only fires when
    // both higher layers have already missed.
    const wroteAnyEgressHeaders = wroteWriteHeadersHook
        || (!!effectiveChromiumWriteHeadersAddr && !effectiveChromiumWriteHeadersAddr.isNull());
    if (quic_capture_mode === "app-api" && !wroteAnyEgressHeaders
        && effectiveSessionWriteHeadersOnHeadersStreamAddr && !effectiveSessionWriteHeadersOnHeadersStreamAddr.isNull()) {
        try {
            let swhCount = 0;
            Interceptor.attach(effectiveSessionWriteHeadersOnHeadersStreamAddr, {
                onEnter(args) {
                    if (_isShuttingDownNow()) return;
                    try {
                        const sessionObj = args[0];                 // QuicSpdySession*
                        const streamIdRaw = args[1].toUInt32();     // QuicStreamId (real id from quiche)
                        const headerBlock = args[2];                // pointer to by-value HttpHeaderBlock temp
                        devlog_debug(`[SpdySession_WriteHeadersOnHeadersStream] FIRED session=${sessionObj} streamId=${streamIdRaw} headerBlock=${headerBlock}`);
                        if (!headerBlock || headerBlock.isNull()) return;
                        hookBreadcrumb(`QuicSpdySession::WriteHeadersOnHeadersStream reading HttpHeaderBlock session=${sessionObj} streamId=${streamIdRaw} headerBlock=${headerBlock}`);
                        const headers = readHttpHeaderBlock(headerBlock);
                        if (headers.length === 0) {
                            _dumpEmptyHeaderBlockProbe("SpdySession_WriteHeadersOnHeadersStream", headerBlock);
                            return;
                        }
                        if (swhCount < 8) {
                            swhCount++;
                            devlog_debug(`[SpdySession_WriteHeadersOnHeadersStream] call #${swhCount} in ${moduleName}: ${headers.length} header(s)`);
                        }
                        // Use the session pointer as the resolveQuicMessage
                        // key (best available — no per-stream `this` here).
                        // streamIdRaw is the REAL QuicStreamId from quiche,
                        // not a pointer cast — it does NOT correlate with the
                        // QuicSpdyStream-pointer surrogate used by
                        // OnHeadersDecoded, so request/response will split
                        // into two flows. Acceptable per the chain design.
                        const message = resolveQuicMessage(sessionObj.toString(), "QuicSpdySession_WriteHeadersOnHeadersStream");
                        sendQuicDatalog(message, null, streamIdRaw, undefined, undefined, "udp", headers);
                    } catch (e) {
                        devlog_error("[QuicSpdySession_WriteHeadersOnHeadersStream] onEnter threw: " + e);
                    }
                },
            });
            log("[*] Hooked quic::QuicSpdySession::WriteHeadersOnHeadersStream for HTTP/3 header capture (outgoing/request, app-api mode, chain-fallback level 2 — surrogate may not pair with OnHeadersDecoded)");
        } catch (e) {
            devlog_error("[Google QUICHE] failed to hook QuicSpdySession::WriteHeadersOnHeadersStream: " + e);
        }
    }

    // Hook WriteOrBufferBody: QuicSpdyStream::WriteOrBufferBody(this, data_ptr, data_len, fin) -> void
    // On x86-64 SysV ABI: absl::string_view is decomposed to two registers (ptr=rsi, len=rdx)
    // On ARM64: this=x0, data.ptr=x1, data.length=x2, fin=w3
    if (writeAddr && !writeAddr.isNull()) {
        try {
            Interceptor.attach(writeAddr, {
                onEnter(args) {
                    if (_isShuttingDownNow()) { this.data = null; this.dataLen = 0; return; }
                    this.streamObj = args[0];       // QuicSpdyStream* this
                    const dataPtr = args[1];         // absl::string_view.ptr
                    const dataLen = args[2].toUInt32(); // size_t but HTTP/3 bodies are bounded in practice
                    this.dataLen = dataLen;

                    if (dataLen === 0 || dataPtr.isNull()) {
                        this.data = null;
                        return;
                    }

                    // Guard against garbage args from a symbol-resolved Cronet
                    // address: a bad ptr/len must skip, not SIGSEGV the target.
                    resetReadableCache();
                    if (dataLen > (16 << 20) || !isReadable(dataPtr, dataLen)) {
                        devlog_debug(`[WriteOrBufferBody] unreadable data ptr=${dataPtr} len=${dataLen} -> skip`);
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

    // Chain-summary line — one per attach so the user can tell at a glance
    // which egress-headers layer is the active one (and which fallbacks were
    // silent because a higher layer already won, their pattern did not resolve
    // on this build, or --quic-egress-headers-layer forced a specific layer).
    // Uses the EFFECTIVE addresses so a forced layer that failed to resolve
    // reads as NONE rather than "would-have-won if not forced".
    if (quic_capture_mode === "app-api") {
        const activeLayer = wroteWriteHeadersHook
            ? "quiche-internal (QuicSpdyStream::WriteHeaders)"
            : (effectiveChromiumWriteHeadersAddr && !effectiveChromiumWriteHeadersAddr.isNull())
                ? "chrome-shim (QuicChromiumClientStream::WriteHeaders)"
                : (effectiveSessionWriteHeadersOnHeadersStreamAddr && !effectiveSessionWriteHeadersOnHeadersStreamAddr.isNull())
                    ? "session-level (QuicSpdySession::WriteHeadersOnHeadersStream)"
                    : "NONE (no egress HTTP/3 header capture)";
        const forcedSuffix = forcedLayerActive ? ` [forced via --quic-egress-headers-layer=${requestedLayer}]` : "";
        log(`[*] Google QUICHE egress headers chain in ${moduleName}: active layer = ${activeLayer}${forcedSuffix}`);

        // If the user FORCED a layer that did not resolve on this build, give
        // them a clear pointer to what's available, so they don't sit puzzling
        // over a silent capture.
        if (forcedLayerActive && activeLayer.startsWith("NONE")) {
            const available: string[] = [];
            if (writeHeadersAddr && !writeHeadersAddr.isNull()) available.push("quiche-internal");
            if (chromiumWriteHeadersAddr && !chromiumWriteHeadersAddr.isNull()) available.push("chrome-shim");
            if (sessionWriteHeadersOnHeadersStreamAddr && !sessionWriteHeadersOnHeadersStreamAddr.isNull()) available.push("session-level");
            log(`[!] Google QUICHE: forced layer "${requestedLayer}" did not resolve in ${moduleName}; ` +
                `layers that WOULD have resolved if --quic-egress-headers-layer=auto: ` +
                `[${available.length > 0 ? available.join(", ") : "none"}]`);
        }
    }
}
