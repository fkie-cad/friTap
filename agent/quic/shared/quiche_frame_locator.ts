// agent/quic/shared/quiche_frame_locator.ts
//
// Locate Google QUICHE's two STREAM-frame boundary functions in a STRIPPED
// arm64 build (Chrome's libmonochrome_64.so, Cronet) without symbols or
// per-version byte patterns:
//
//   bool QuicConnection::OnStreamFrame(const QuicStreamFrame& frame)
//       every decrypted incoming STREAM frame (all streams: request streams,
//       control, QPACK encoder/decoder), x0 = QuicConnection*, x1 = &frame;
//   WriteStreamDataResult QuicSession::WriteStreamData(QuicStreamId id,
//       QuicStreamOffset offset, QuicByteCount data_length, QuicDataWriter* writer)
//       every outgoing STREAM frame payload copied into a packet before
//       encryption, x0 = QuicSession*, w1 = id, x2 = offset, x3 = length, x4 = writer.
//
// Hooking at the frame boundary yields the raw HTTP/3 stream bytes — HEADERS
// (QPACK field sections), DATA, and the unidirectional control / QPACK encoder
// / decoder streams — so the host's HTTP/3 + QPACK decoder (dynamic table
// included) recovers the full request line, status and header fields.
//
// ANCHORS: each function passes a fixed QUIC error-detail literal to
// CloseConnection / QUIC_BUG. These literals are runtime data (sent on the wire
// or logged), so release builds keep them:
//   QuicConnection::OnStreamFrame: "Unencrypted stream data seen." and
//                                  "Received crypto frame on non crypto stream."
//   QuicSession::WriteStreamData:  " does not exist when trying to write data."
//   QuicConnection::OnCryptoFrame: "Processing CRYPTO frame when connection is closed.
//                                   Received packet info: " (x0 = QuicConnection*; the
//                                   TLS handshake runs inside it, see quic_ssl_binding.ts)
//   TlsClientHandshaker::CryptoConnect: the client handshake setup failures below
//                                   (x0 = TlsClientHandshaker*; a 0-RTT early secret is
//                                   logged here, before any CRYPTO frame arrives)
// Every load site of an anchor must lie in ONE function (bounded through the
// module's .eh_frame_hdr, or by landing pads where no FDE covers the site or the
// module has no .eh_frame_hdr — eh_frame.ts functionBoundsFor), and both
// OnStreamFrame anchors must agree. CryptoConnect's literals vary per build
// (ECH, PSK), so any two of them that are present must agree.
//
// Verified on Chrome 133.0.6943.137 libmonochrome_64.so (OnStreamFrame
// +0x54e74b4, WriteStreamData +0x551c06c) and mainline Cronet 133.0.6876.3
// (checked against its .gnu_debugdata symbols: +0x4709b0 / +0x4b3ae4).

import { devlog, devlog_debug } from "../../util/log.js";
import {
    AnchorSite, anchorSiteFunctions, moduleOffsetLabel, type ScanStatus,
} from "../../shared/arm64_xref.js";
import { functionBoundsFor } from "../../shared/eh_frame.js";
import {
    hasLearnedMiss, learnedFunction, learnedMissName, missFingerprint, reportLearned,
    reportLearnedMisses,
} from "../../shared/learned_module_cache.js";
import { memoizePerMapping } from "../../shared/module_mapping.js";

export const ON_STREAM_FRAME_ANCHORS = [
    "Unencrypted stream data seen.",
    "Received crypto frame on non crypto stream.",
];
export const WRITE_STREAM_DATA_ANCHORS = [
    " does not exist when trying to write data.",
];
export const ON_CRYPTO_FRAME_ANCHORS = [
    "Processing CRYPTO frame when connection is closed. Received packet info: ",
];
export const CRYPTO_CONNECT_ANCHORS = [
    "Client failed to set ALPN",
    "Client failed to set Transport Parameters",
    "Client failed to set ECHConfigList",
    "QUIC client pre-shared keys not yet supported with TLS",
];
/** CryptoConnect anchors that must be present (and agree) before it is hooked. */
export const MIN_CRYPTO_CONNECT_ANCHORS = 2;

// QuicStreamFrame { QuicFrameType type; bool fin; QuicPacketLength data_length;
//                   QuicStreamId stream_id; const char* data_buffer; QuicStreamOffset offset; }
export const STREAM_FRAME_FIN = 1;
export const STREAM_FRAME_DATA_LENGTH = 2;
export const STREAM_FRAME_STREAM_ID = 4;
export const STREAM_FRAME_DATA_BUFFER = 8;
export const STREAM_FRAME_OFFSET = 16;
// QuicheDataWriter { char* buffer_; size_t capacity_; size_t length_; Endianness }
export const DATA_WRITER_BUFFER = 0;
export const DATA_WRITER_LENGTH = 16;

/** Upper bound on either function's size: both are small dispatchers. */
export const MAX_FUNCTION_BYTES = 0x1000;

// ---------------------------------------------------------------------------
// Pure logic (unit-tested under Node)
// ---------------------------------------------------------------------------

/** A function containing an anchor load site: start offset and size (null when unknown). */
export interface SiteFunction { start: number; size: number | null; }

/**
 * The single function every anchor's load sites resolve to, or null when an
 * anchor has no site, a site has no function, sites of one anchor span several
 * functions, anchors disagree, or the function is implausibly large.
 */
export function agreeOnFunction(sitesPerAnchor: (SiteFunction | null)[][]): number | null {
    let agreed: number | null = null;
    for (const sites of sitesPerAnchor) {
        if (sites.length === 0) return null;
        for (const fn of sites) {
            if (fn === null) return null;
            if (fn.size !== null && fn.size > MAX_FUNCTION_BYTES) return null;
            if (agreed === null) agreed = fn.start;
            else if (agreed !== fn.start) return null;
        }
    }
    return agreed;
}

/**
 * Like agreeOnFunction, but anchors without any load site are skipped (literals
 * a build dropped); at least `minAnchors` must be present. Any disagreement
 * among the present ones still picks nothing.
 */
export function agreeOnFunctionPartial(sitesPerAnchor: (SiteFunction | null)[][], minAnchors: number): number | null {
    const present = sitesPerAnchor.filter((sites) => sites.length > 0);
    return present.length < minAnchors ? null : agreeOnFunction(present);
}

// ---------------------------------------------------------------------------
// Frida-side discovery
// ---------------------------------------------------------------------------

export interface LocatedFrameApi {
    onStreamFrame: NativePointer | null;
    writeStreamData: NativePointer | null;
    onCryptoFrame: NativePointer | null;
    cryptoConnect: NativePointer | null;
}

/** An anchor load site's function as a module-relative SiteFunction (null when unbounded). */
function siteFunction(mod: Module, site: AnchorSite): SiteFunction | null {
    const fn = site.fn;
    if (!fn) return null;
    return { start: fn.start.sub(mod.base).toInt32(), size: fn.end ? fn.end.sub(fn.start).toInt32() : null };
}

const NO_FRAME_API: LocatedFrameApi = { onStreamFrame: null, writeStreamData: null, onCryptoFrame: null, cryptoConnect: null };

type FrameField = keyof LocatedFrameApi;

interface FrameFunction {
    field: FrameField;
    /** Learned-cache item name. */
    name: string;
    anchors: string[];
    /** installQuicheFrameHooks hooks nothing without every non-optional one, so a cache hit needs them all. */
    optional: boolean;
    /** Set when only this many of the anchors need to be present (and agree); else all must agree. */
    minAnchors?: number;
}

/** The located functions, in scan order. */
const FRAME_FUNCTIONS: FrameFunction[] = [
    { field: "onStreamFrame", name: "quiche.frame.OnStreamFrame", anchors: ON_STREAM_FRAME_ANCHORS, optional: false },
    { field: "writeStreamData", name: "quiche.frame.WriteStreamData", anchors: WRITE_STREAM_DATA_ANCHORS,
      optional: false },
    { field: "onCryptoFrame", name: "quiche.frame.OnCryptoFrame", anchors: ON_CRYPTO_FRAME_ANCHORS, optional: true },
    { field: "cryptoConnect", name: "quiche.frame.CryptoConnect", anchors: CRYPTO_CONNECT_ANCHORS, optional: true,
      minAnchors: MIN_CRYPTO_CONNECT_ANCHORS },
];
const MANDATORY_FRAME_API = FRAME_FUNCTIONS.filter((f) => !f.optional);
const OPTIONAL_FRAME_API = FRAME_FUNCTIONS.filter((f) => f.optional);

/** Learned-cache item names of the located functions. */
export const LEARNED_FRAME_API_NAMES = Object.fromEntries(FRAME_FUNCTIONS.map((f) => [f.field, f.name])) as
    Record<FrameField, string>;

/** Miss-marker value of an optional function: it only holds for the anchors it was scanned with. */
export function frameApiMissFingerprint(field: FrameField): number {
    return missFingerprint(FRAME_FUNCTIONS.find((f) => f.field === field)!.anchors);
}

/** One anchor scan; `complete` is false when part of it failed (its misses then prove nothing). */
export interface FrameApiScan {
    api: LocatedFrameApi;
    complete: boolean;
}

/** What locateQuicheFrameApi() needs besides the learned cache (injectable for tests). */
export interface FrameApiSources {
    scan: (mod: Module) => Promise<FrameApiScan>;
}

function defaultFrameApiSources(): FrameApiSources {
    return { scan: scanQuicheFrameApi };
}

/** The cached functions when all mandatory ones verify, else null ("scan"). */
function learnedFrameApi(mod: Module): LocatedFrameApi | null {
    const api = { ...NO_FRAME_API };
    for (const f of FRAME_FUNCTIONS) {
        api[f.field] = learnedFunction(mod, f.name);
        if (!f.optional && api[f.field] === null) return null;
    }
    return api;
}

/** An optional function absent from the cache without a matching miss marker: scan for it. */
function optionalFieldsToScan(mod: Module, api: LocatedFrameApi): FrameField[] {
    return OPTIONAL_FRAME_API.filter((f) => api[f.field] === null
        && !hasLearnedMiss(mod, learnedMissName(f.name), frameApiMissFingerprint(f.field))).map((f) => f.field);
}

function reportFrameApi(mod: Module, scan: FrameApiScan): void {
    const { api } = scan;
    if (MANDATORY_FRAME_API.some((f) => api[f.field] === null)) return;
    const functions: Record<string, NativePointer> = {};
    for (const f of FRAME_FUNCTIONS) {
        const addr = api[f.field];
        if (addr !== null) functions[f.name] = addr;
    }
    reportLearned(mod, { functions });
    reportLearnedMisses(mod, Object.fromEntries(OPTIONAL_FRAME_API.filter((f) => api[f.field] === null)
        .map((f) => [learnedMissName(f.name), frameApiMissFingerprint(f.field)])), scan);
}

/** Cached mandatory functions plus a fresh scan's optional ones (the scan's mandatory hits are not needed). */
function withScannedOptionals(cached: LocatedFrameApi, scanned: LocatedFrameApi): LocatedFrameApi {
    const api = { ...cached };
    for (const { field } of OPTIONAL_FRAME_API) api[field] = cached[field] ?? scanned[field];
    return api;
}

async function resolveFrameApi(mod: Module, sources: FrameApiSources): Promise<LocatedFrameApi> {
    const startedAt = Date.now();
    const cached = learnedFrameApi(mod);
    const unknownOptionals = cached === null ? [] : optionalFieldsToScan(mod, cached);
    let api: LocatedFrameApi;
    if (cached !== null && unknownOptionals.length === 0) {
        api = cached;
    } else {
        const scan = await sources.scan(mod);
        api = cached === null ? scan.api : withScannedOptionals(cached, scan.api);
        reportFrameApi(mod, { api, complete: scan.complete });
    }
    const source = cached === null ? "anchor scan"
        : unknownOptionals.length === 0 ? "from learned cache"
        : `from learned cache, anchor scan for ${unknownOptionals.join(", ")}`;
    devlog_debug(`[Google QUICHE] ${mod.name}: STREAM-frame API resolved in ${Date.now() - startedAt} ms (${source})`);
    return api;
}

// One lookup per loaded mapping: installGoogleQuicheHooks may run again for the same module.
const frameApiByModule = new Map<string, Promise<LocatedFrameApi>>();

/**
 * Locate the frame-boundary functions in `mod` (arm64 only): learned cache first,
 * else the anchor scan, whose result is reported to the cache. Memoized per
 * mapping. Never throws; null fields when not found.
 */
export function locateQuicheFrameApi(mod: Module, sources: FrameApiSources = defaultFrameApiSources()):
        Promise<LocatedFrameApi> {
    if (Process.arch !== "arm64") return Promise.resolve({ ...NO_FRAME_API });
    return memoizePerMapping(frameApiByModule, mod, () => resolveFrameApi(mod, sources).catch((e) => {
        devlog(`[Google QUICHE] ${mod.name}: STREAM-frame lookup failed: ${e}`);
        return { ...NO_FRAME_API };
    }));
}

/** The anchor scan for all four functions in `mod`. Never throws; null fields when not found. */
async function scanQuicheFrameApi(mod: Module): Promise<FrameApiScan> {
    const status: ScanStatus = { complete: true };
    try {
        // One scan for all anchors; results are split back per function below.
        const anchors = FRAME_FUNCTIONS.flatMap((f) => f.anchors);
        // The NUL pins the literal's end; its start is the hit itself (the code
        // references exactly that address even when the literal is tail-merged).
        // FDE bounds where .eh_frame covers a site; landing-pad bounds elsewhere.
        const table = functionBoundsFor(mod);
        const sites = await anchorSiteFunctions(mod, table, anchors.map((text) => ({ text })), status);
        const functions = sites.map((list) => list.map((site) => siteFunction(mod, site)));
        const api: LocatedFrameApi = { ...NO_FRAME_API };
        let start = 0;
        for (const f of FRAME_FUNCTIONS) {
            const group = functions.slice(start, start + f.anchors.length);
            start += f.anchors.length;
            const off = f.minAnchors === undefined ? agreeOnFunction(group) : agreeOnFunctionPartial(group, f.minAnchors);
            api[f.field] = off === null ? null : mod.base.add(off);
        }
        devlog(`[Google QUICHE] ${mod.name}: STREAM-frame anchors -> ` +
               `QuicConnection::OnStreamFrame ${moduleOffsetLabel(mod, api.onStreamFrame)}, ` +
               `QuicSession::WriteStreamData ${moduleOffsetLabel(mod, api.writeStreamData)}, ` +
               `QuicConnection::OnCryptoFrame ${moduleOffsetLabel(mod, api.onCryptoFrame)}, ` +
               `TlsClientHandshaker::CryptoConnect ${moduleOffsetLabel(mod, api.cryptoConnect)}`);
        return { api, complete: status.complete };
    } catch (e) {
        devlog(`[Google QUICHE] ${mod.name}: STREAM-frame locator failed: ${e}`);
        return { api: { ...NO_FRAME_API }, complete: false };
    }
}
