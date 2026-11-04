// agent/quic/shared/quic_stream_reassembler.ts
//
// In-order, exactly-once delivery of QUIC stream bytes observed as
// (offset, data) fragments. Pure logic (no Frida APIs) so it runs under Node.
//
// Why: the Google QUICHE STREAM-frame hooks (QuicConnection::OnStreamFrame for
// ingress, QuicSession::WriteStreamData for egress) see every frame as it is
// received or packetised — including retransmissions, overlaps and frames that
// arrive out of order. HTTP/3 framing and QPACK need each stream's bytes once
// and in order, starting at offset 0 (a unidirectional stream's first byte is
// its stream type). This class turns the fragment feed into exactly that.
//
// Delivery always starts at offset 0. A stream whose offset 0 is never seen was
// joined late (e.g. attached to a running process mid-transfer): its prefix is
// unknowable, so its fragments wait only within a small budget and the stream
// is then ignored rather than handing a framing parser bytes from the middle.

import { LruMap } from "../../shared/lru.js";

/** Bytes buffered ahead of the in-order point, per stream, before it is abandoned. */
export const MAX_PENDING_BYTES_PER_STREAM = 1 << 20;
/** Out-of-order fragments buffered per stream, before it is abandoned. */
export const MAX_PENDING_FRAGMENTS_PER_STREAM = 256;
/** Tighter budget while offset 0 has not been seen (reordered start vs late join). */
export const MAX_UNSTARTED_PENDING_BYTES = 64 * 1024;
export const MAX_UNSTARTED_PENDING_FRAGMENTS = 64;
/** Streams tracked at once (least recently used evicted first). */
export const MAX_TRACKED_STREAMS = 4096;
/** Bytes buffered across ALL streams; the stream that overflows it is abandoned. */
export const MAX_PENDING_BYTES_TOTAL = 16 << 20;

interface Fragment {
    offset: number;
    data: Uint8Array;
}

interface StreamState {
    /** Next stream offset to deliver; -1 once the stream is ignored. */
    next: number;
    pending: Fragment[];
    pendingBytes: number;
    /** Stream length once a FIN was seen (offset + length of the FIN frame). */
    finalSize: number | null;
    /** True once offset 0 was delivered. */
    started: boolean;
}

const IGNORED = -1;

export interface ReassembledChunk {
    /** Stream offset of `data[0]`. */
    offset: number;
    data: Uint8Array;
}

/**
 * Per-(connection, direction, stream) in-order reassembly of QUIC stream fragments.
 * Ownership: pushed `data` is kept (buffered or returned as a subarray), never
 * copied — callers hand over a buffer they no longer modify.
 */
export class QuicStreamReassembler {
    private readonly streams: LruMap<string, StreamState>;
    private pendingTotal = 0;

    constructor(maxStreams: number = MAX_TRACKED_STREAMS,
                private readonly maxPendingTotal: number = MAX_PENDING_BYTES_TOTAL) {
        this.streams = new LruMap(maxStreams, (_key, state) => { this.pendingTotal -= state.pendingBytes; });
    }

    /** Number of streams currently tracked (tests / diagnostics). */
    get trackedStreams(): number {
        return this.streams.size;
    }

    /** Bytes buffered ahead of the in-order point across every stream (tests / diagnostics). */
    get pendingBytes(): number {
        return this.pendingTotal;
    }

    /**
     * False when a fragment of `length` bytes at `offset` (no FIN) cannot yield
     * new bytes: the stream is ignored or the range was already delivered
     * (a retransmission). Lets callers skip copying the payload at all.
     */
    canDeliver(key: string, offset: number, length: number): boolean {
        const state = this.streams.get(key);
        if (state === undefined) return true;
        return state.next !== IGNORED && offset + length > state.next;
    }

    /**
     * Feed one fragment of stream `key`; returns the newly contiguous bytes
     * (possibly several chunks when buffered fragments become deliverable).
     */
    push(key: string, offset: number, data: Uint8Array, fin: boolean = false): ReassembledChunk[] {
        let state = this.streams.get(key);
        if (state === undefined) {
            state = { next: 0, pending: [], pendingBytes: 0, finalSize: null, started: false };
            this.streams.set(key, state);
        }
        if (state.next === IGNORED) return [];
        if (fin) state.finalSize = offset + data.length;
        const out: ReassembledChunk[] = [];
        if (data.length > 0) {
            if (offset > state.next) this.buffer(state, offset, data);
            else this.deliver(state, offset, data, out);
            this.drain(state, out);
        }
        if (state.next !== IGNORED && state.finalSize !== null && state.next >= state.finalSize) {
            // Complete: forget it (late retransmissions then look like a late join and are dropped).
            this.ignore(state);
        }
        return out;
    }

    private ignore(state: StreamState): void {
        state.next = IGNORED;
        this.pendingTotal -= state.pendingBytes;
        state.pending = [];
        state.pendingBytes = 0;
    }

    /** Emit the part of [offset, offset+len) at or after `state.next` (offset <= next). */
    private deliver(state: StreamState, offset: number, data: Uint8Array, out: ReassembledChunk[]): void {
        const end = offset + data.length;
        if (end <= state.next) return;                       // pure retransmission
        const fresh = data.subarray(state.next - offset);
        out.push({ offset: state.next, data: fresh });
        state.next = end;
        state.started = true;
    }

    private buffer(state: StreamState, offset: number, data: Uint8Array): void {
        if (state.pending.some((f) => f.offset === offset && f.data.length >= data.length)) return;
        state.pending.push({ offset, data });
        state.pendingBytes += data.length;
        this.pendingTotal += data.length;
        const maxBytes = state.started ? MAX_PENDING_BYTES_PER_STREAM : MAX_UNSTARTED_PENDING_BYTES;
        const maxFragments = state.started ? MAX_PENDING_FRAGMENTS_PER_STREAM : MAX_UNSTARTED_PENDING_FRAGMENTS;
        if (state.pendingBytes > maxBytes || state.pending.length > maxFragments ||
                this.pendingTotal > this.maxPendingTotal) {
            // A gap that never fills (late join / lost observation), or the
            // process-wide budget is spent: give up on the stream rather than
            // buffer without bound or emit out of order.
            this.ignore(state);
        }
    }

    private drain(state: StreamState, out: ReassembledChunk[]): void {
        let progressed = true;
        while (progressed && state.next !== IGNORED && state.pending.length > 0) {
            progressed = false;
            for (let i = 0; i < state.pending.length; i++) {
                const f = state.pending[i];
                if (f.offset > state.next) continue;
                state.pending.splice(i, 1);
                state.pendingBytes -= f.data.length;
                this.pendingTotal -= f.data.length;
                this.deliver(state, f.offset, f.data, out);
                progressed = true;
                break;
            }
        }
    }
}
