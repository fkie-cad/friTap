// agent/quic/shared/quiche_connection_capture.ts
//
// Per-connection choice between the two Google QUICHE capture paths:
//
//   "frames"  raw HTTP/3 stream bytes from the STREAM-frame hooks. Complete
//             (headers + bodies) but only decodable when the connection was
//             observed from its start: QPACK header blocks reference the
//             dynamic table built by the encoder streams' earlier instructions.
//   "bodies"  the de-framed DATA payload hooks (OnDataFramePayload /
//             WriteOrBufferBody). No headers, but independent of QPACK state.
//
// A connection is "frames" only when the first event seen for it is a
// unidirectional stream at offset 0 — the control streams (SETTINGS) are the
// first stream data either endpoint sends, so every later stream (QPACK
// encoder/decoder, requests) is then observed from offset 0 too. Any other first event
// (a request stream, a mid-stream offset, a body hook) means the hooks were
// installed after the connection started (attach mode, or a connection that
// raced hook installation at spawn): that connection uses "bodies" for its
// whole life, so no byte is ever reported by both paths.
//
// Exception, per stream: on a "bodies" connection a bidirectional stream whose
// first contiguous chunk is at offset 0 (a request opened after the hooks) is
// owned by the frame path ("midstream": its headers may reference QPACK state
// that was never seen). A stream the body hook reports first stays "bodies".

import { LruMap } from "../../shared/lru.js";

export type ConnectionCapture = "frames" | "bodies";
/** Path reporting one stream: "midstream" = frame path on a "bodies" connection. */
export type StreamCapture = "frames" | "midstream" | "bodies";

/** Connections remembered at once (least recently used evicted first). */
export const MAX_TRACKED_CONNECTIONS = 1024;
/** Per-stream owners of "bodies" connections remembered at once (LRU). */
export const MAX_TRACKED_STREAM_OWNERS = 4096;

/** RFC 9000 2.1: bit 1 of a stream id marks a unidirectional stream. */
export function isUniStream(streamId: number): boolean {
    return (streamId & 0x2) !== 0;
}

export class QuicheConnectionCapture {
    private readonly modes = new LruMap<string, ConnectionCapture>(MAX_TRACKED_CONNECTIONS);
    private readonly streamOwners = new LruMap<string, ConnectionCapture>(MAX_TRACKED_STREAM_OWNERS);
    /** "bodies" connections with at least one frame-owned stream. */
    private readonly frameOwning = new LruMap<string, true>(MAX_TRACKED_CONNECTIONS);

    /** Capture path already decided for `connection`, or undefined (does not decide). */
    modeOf(connection: string): ConnectionCapture | undefined {
        return this.modes.get(connection);
    }

    /** Capture path of `connection` for a STREAM-frame event (decided on first sight). */
    onFrame(connection: string, streamId: number, offset: number): ConnectionCapture {
        let mode = this.modes.get(connection);
        if (mode === undefined) {
            mode = isUniStream(streamId) && offset === 0 ? "frames" : "bodies";
            this.modes.set(connection, mode);
        }
        return mode;
    }

    /** Capture path of `connection` for a de-framed body event (decided on first sight). */
    onBody(connection: string): ConnectionCapture {
        let mode = this.modes.get(connection);
        if (mode === undefined) {
            mode = "bodies";
            this.modes.set(connection, mode);
        }
        return mode;
    }

    /** Path reporting `streamId` for its STREAM-frame chunk at `offset` (decided on first sight). */
    onStreamFrame(connection: string, streamId: number, offset: number): StreamCapture {
        return this.onStreamFrameKeys(streamFrameKeys(connection, streamId), offset);
    }

    /** onStreamFrame with the fragment's precomputed keys (hot path). */
    onStreamFrameKeys(keys: StreamFrameKeys, offset: number): StreamCapture {
        // A decided mode never changes, so the one mayReportFrameKeys saw is still valid.
        const mode = keys.mode ?? this.onFrame(keys.connection, keys.streamId, offset);
        if (mode === "frames") return "frames";
        if (isUniStream(keys.streamId)) return "bodies";
        const capture = this.decideStreamOwner(keys.owner, offset === 0 ? "frames" : "bodies");
        if (capture === "midstream") this.frameOwning.set(keys.connection, true);
        return capture;
    }

    /** Path reporting a de-framed body of `streamId` (null: stream unknown, see onUnknownBodyStream). */
    onBodyStream(connection: string, streamId: number | null): StreamCapture {
        if (streamId === null) return this.onUnknownBodyStream(connection);
        return this.onBodyStreamKeys(streamFrameKeys(connection, streamId));
    }

    /** onBodyStream with the same precomputed keys the frame path decides on. */
    onBodyStreamKeys(keys: StreamFrameKeys): StreamCapture {
        if (this.onBody(keys.connection) === "frames") return "frames";
        if (isUniStream(keys.streamId)) return "bodies";
        return this.decideStreamOwner(keys.owner, "bodies");
    }

    /**
     * Path for a de-framed body whose stream id is not known: the body path only
     * while the frame path owns no stream of the connection — the body could be
     * one of those streams' bytes, and a dropped body beats a duplicated one.
     */
    onUnknownBodyStream(connection: string): StreamCapture {
        if (this.onBody(connection) === "frames") return "frames";
        return this.frameOwning.get(connection) === true ? "midstream" : "bodies";
    }

    /** False when no STREAM-frame chunk of `streamId` can be reported any more (does not decide). */
    mayReportFrame(connection: string, streamId: number): boolean {
        return this.mayReportFrameKeys(streamFrameKeys(connection, streamId));
    }

    /** mayReportFrame with the fragment's precomputed keys; remembers a decided mode in `keys`. */
    mayReportFrameKeys(keys: StreamFrameKeys): boolean {
        const mode = this.modes.get(keys.connection);
        if (mode !== undefined) keys.mode = mode;
        if (mode !== "bodies") return true;
        if (isUniStream(keys.streamId)) return false;
        return this.streamOwners.get(keys.owner) !== "bodies";
    }

    private decideStreamOwner(key: string, firstSight: ConnectionCapture): StreamCapture {
        let owner = this.streamOwners.get(key);
        if (owner === undefined) {
            owner = firstSight;
            this.streamOwners.set(key, owner);
        }
        return owner === "frames" ? "midstream" : "bodies";
    }
}

/** One STREAM fragment's keys, built once so the hot path never rebuilds key strings. */
export interface StreamFrameKeys {
    readonly connection: string;
    readonly streamId: number;
    /** Per-stream owner key ("<connection>|<streamId>"). */
    readonly owner: string;
    /** Connection mode already looked up for this fragment, if decided. */
    mode?: ConnectionCapture;
}

export function streamFrameKeys(connection: string, streamId: number): StreamFrameKeys {
    return { connection, streamId, owner: streamOwnerKey(connection, streamId) };
}

function streamOwnerKey(connection: string, streamId: number): string {
    return `${connection}|${streamId}`;
}
