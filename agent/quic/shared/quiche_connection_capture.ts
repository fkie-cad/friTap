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

import { LruMap } from "../../shared/lru.js";

export type ConnectionCapture = "frames" | "bodies";

/** Connections remembered at once (least recently used evicted first). */
export const MAX_TRACKED_CONNECTIONS = 1024;

/** RFC 9000 2.1: bit 1 of a stream id marks a unidirectional stream. */
export function isUniStream(streamId: number): boolean {
    return (streamId & 0x2) !== 0;
}

export class QuicheConnectionCapture {
    private readonly modes = new LruMap<string, ConnectionCapture>(MAX_TRACKED_CONNECTIONS);

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
}
