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
// Every load site of an anchor must lie in ONE function (bounded through the
// module's .eh_frame_hdr, or by landing pads where no FDE covers the site or the
// module has no .eh_frame_hdr — eh_frame.ts functionBoundsFor), and both
// OnStreamFrame anchors must agree.
//
// Verified on Chrome 133.0.6943.137 libmonochrome_64.so (OnStreamFrame
// +0x54e74b4, WriteStreamData +0x551c06c) and mainline Cronet 133.0.6876.3
// (checked against its .gnu_debugdata symbols: +0x4709b0 / +0x4b3ae4).

import { devlog } from "../../util/log.js";
import { AnchorSite, anchorSiteFunctions, moduleOffsetLabel } from "../../shared/arm64_xref.js";
import { functionBoundsFor } from "../../shared/eh_frame.js";

export const ON_STREAM_FRAME_ANCHORS = [
    "Unencrypted stream data seen.",
    "Received crypto frame on non crypto stream.",
];
export const WRITE_STREAM_DATA_ANCHORS = [
    " does not exist when trying to write data.",
];

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

// ---------------------------------------------------------------------------
// Frida-side discovery
// ---------------------------------------------------------------------------

export interface LocatedFrameApi {
    onStreamFrame: NativePointer | null;
    writeStreamData: NativePointer | null;
}

/** An anchor load site's function as a module-relative SiteFunction (null when unbounded). */
function siteFunction(mod: Module, site: AnchorSite): SiteFunction | null {
    const fn = site.fn;
    if (!fn) return null;
    return { start: fn.start.sub(mod.base).toInt32(), size: fn.end ? fn.end.sub(fn.start).toInt32() : null };
}

/** Locate both functions in `mod` (arm64 only). Never throws; null fields when not found. */
export async function locateQuicheFrameApi(mod: Module): Promise<LocatedFrameApi> {
    const none: LocatedFrameApi = { onStreamFrame: null, writeStreamData: null };
    if (Process.arch !== "arm64") return none;
    try {
        const anchors = [...ON_STREAM_FRAME_ANCHORS, ...WRITE_STREAM_DATA_ANCHORS];
        // The NUL pins the literal's end; its start is the hit itself (the code
        // references exactly that address even when the literal is tail-merged).
        // FDE bounds where .eh_frame covers a site; landing-pad bounds elsewhere.
        const table = functionBoundsFor(mod);
        const sites = await anchorSiteFunctions(mod, table, anchors.map((text) => ({ text })));
        const functions = sites.map((list) => list.map((site) => siteFunction(mod, site)));
        const pick = (group: (SiteFunction | null)[][]) => {
            const off = agreeOnFunction(group);
            return off === null ? null : mod.base.add(off);
        };
        const onStreamFrame = pick(functions.slice(0, ON_STREAM_FRAME_ANCHORS.length));
        const writeStreamData = pick(functions.slice(ON_STREAM_FRAME_ANCHORS.length));
        devlog(`[Google QUICHE] ${mod.name}: STREAM-frame anchors -> ` +
               `QuicConnection::OnStreamFrame ${moduleOffsetLabel(mod, onStreamFrame)}, ` +
               `QuicSession::WriteStreamData ${moduleOffsetLabel(mod, writeStreamData)}`);
        return { onStreamFrame, writeStreamData };
    } catch (e) {
        devlog(`[Google QUICHE] ${mod.name}: STREAM-frame locator failed: ${e}`);
        return none;
    }
}
