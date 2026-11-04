// agent/quic/shared/quiche_frame_capture.ts
//
// STREAM-frame capture for Google QUICHE (QuicConnection::OnStreamFrame /
// QuicSession::WriteStreamData, located by quiche_frame_locator.ts).
//
// Raw, de-duplicated, in-order HTTP/3 stream bytes per real QUIC stream id —
// HEADERS (QPACK) + DATA on request streams and the control / QPACK encoder /
// decoder unidirectional streams — so the host decodes request line, status
// and every header field (dynamic table included).
//
// Per frame the payload is copied only when it can still be reported: the
// connection uses the frame path (see quiche_connection_capture.ts) and the
// bytes are not a retransmission of already delivered stream data.

import { log, devlog_error, hookBreadcrumb, _isShuttingDownNow } from "../../util/log.js";
import { sendQuicDatalog } from "../../shared/shared_structures.js";
import { LruMap } from "../../shared/lru.js";
import { isReadable, resetReadableCache } from "../../util/safe_memory.js";
import { QuicDirection } from "./quic_connection_tracker.js";
import { Address } from "./quiche_layout.js";
import { QuicStreamReassembler } from "./quic_stream_reassembler.js";
import { QuicheConnectionCapture } from "./quiche_connection_capture.js";
import {
    DATA_WRITER_BUFFER, DATA_WRITER_LENGTH, STREAM_FRAME_DATA_BUFFER, STREAM_FRAME_DATA_LENGTH, STREAM_FRAME_FIN,
    STREAM_FRAME_OFFSET, STREAM_FRAME_STREAM_ID, locateQuicheFrameApi,
} from "./quiche_frame_locator.js";
import {
    QuicheLayoutState, QuicMessage, QuicRecord, quicheLayoutState, resolveConnectionRecord, sessionConnection,
    toAddress, unresolvedConnectionRecord,
} from "./quiche_records.js";

const FRAME_IN_LABEL = "QuicConnection_OnStreamFrame";
const FRAME_OUT_LABEL = "QuicSession_WriteStreamData";
/** Egress chunks held per session while its connection cannot be resolved yet. */
const MAX_DEFERRED_CHUNKS = 256;
/** Sessions with held egress chunks (LRU; bounds the held bytes to ~32 x 256 packets). */
const MAX_DEFERRED_SESSIONS = 32;

const frameReassembler = new QuicStreamReassembler();
const frameCapture = new QuicheConnectionCapture();
const deferredEgress = new LruMap<string, EgressFragment[]>(MAX_DEFERRED_SESSIONS);

/** A raw egress fragment held while its session's connection is not resolvable yet. */
interface EgressFragment { streamId: number; offset: number; bytes: Uint8Array; }

/**
 * Per-connection key shared by reassembly, capture-path choice and the host:
 * the tracker's connection key, which gains a "#<generation>" suffix when a
 * new connection reuses a freed QuicConnection's memory — so a reused address
 * never inherits the old connection's stream offsets.
 */
function recordKey(record: QuicRecord): string {
    return String(record.message["ssl_session_id"]);
}

function streamKey(direction: QuicDirection, record: QuicRecord): string {
    return `${direction}|${recordKey(record)}|${record.streamId}`;
}

/** False when a fragment cannot be reported: body-path connection or already delivered bytes. */
function wantsFragment(record: QuicRecord, direction: QuicDirection, offset: number, length: number,
                       fin: boolean): boolean {
    if (frameCapture.modeOf(recordKey(record)) === "bodies") return false;
    return fin || frameReassembler.canDeliver(streamKey(direction, record), offset, length);
}

/** The bytes as an ArrayBuffer, without a copy when they already span their whole buffer. */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    const whole = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength;
    return (whole ? bytes.buffer : bytes.slice().buffer) as ArrayBuffer;
}

/** Copy `length` bytes at `at` (validated), or null when unreadable. */
function copyBytes(at: NativePointer, length: number): Uint8Array | null {
    if (length === 0) return new Uint8Array(0);
    if (at.isNull() || !isReadable(at, length)) return null;
    const buf = at.readByteArray(length);
    return buf ? new Uint8Array(buf) : null;
}

/** Reassemble one fragment and emit its newly contiguous bytes if the connection uses the frame path. */
function emitFragment(record: QuicRecord, direction: QuicDirection, offset: number, bytes: Uint8Array,
                      fin: boolean): void {
    const chunks = frameReassembler.push(streamKey(direction, record), offset, bytes, fin);
    if (chunks.length === 0) return;
    if (frameCapture.onFrame(recordKey(record), record.streamId, chunks[0].offset) !== "frames") return;
    // record.message is this call's own object; every chunk re-stamps the same fields.
    for (const chunk of chunks) {
        sendQuicDatalog(record.message, toArrayBuffer(chunk.data), record.streamId,
                        undefined, undefined, "udp", undefined, "stream");
    }
}

function connectionRecord(state: QuicheLayoutState, connection: Address, streamId: number, label: string,
                          direction: QuicDirection, resolvable: boolean = true): QuicRecord {
    return (resolvable ? resolveConnectionRecord(state, connection, streamId, label, direction) : null)
        ?? unresolvedConnectionRecord(state, connection, streamId, label, direction);
}

function emitIngressFrame(state: QuicheLayoutState, connection: NativePointer, frame: NativePointer): void {
    const length = frame.add(STREAM_FRAME_DATA_LENGTH).readU16();
    const fin = (frame.add(STREAM_FRAME_FIN).readU8() & 1) === 1;
    const streamId = frame.add(STREAM_FRAME_STREAM_ID).readU32();
    const offset = frame.add(STREAM_FRAME_OFFSET).readU64().toNumber();
    const record = connectionRecord(state, toAddress(connection), streamId, FRAME_IN_LABEL, "read");
    if (!wantsFragment(record, "read", offset, length, fin)) return;
    const bytes = copyBytes(length > 0 ? frame.add(STREAM_FRAME_DATA_BUFFER).readPointer() : NULL, length);
    if (bytes) emitFragment(record, "read", offset, bytes, fin);
}

/** One egress STREAM-frame payload written into a packet (QuicSession::WriteStreamData). */
interface EgressWrite { streamId: number; offset: number; length: number; at: NativePointer; }

/**
 * Emit an egress write of `session`. Fast path: the connection resolves and
 * nothing is held — check before copying. Otherwise the copy is held until the
 * session's connection resolves (or the hold budget is spent).
 */
function emitEgressWrite(state: QuicheLayoutState, session: NativePointer, write: EgressWrite): void {
    const key = session.toString();
    const connection = sessionConnection(state, toAddress(session));
    const resolvable = connection !== null && connection !== 0n && state.connLayout !== null;
    const held = deferredEgress.get(key);
    if (resolvable && held === undefined) {
        const record = connectionRecord(state, connection!, write.streamId, FRAME_OUT_LABEL, "write");
        if (!wantsFragment(record, "write", write.offset, write.length, false)) return;
        const bytes = copyBytes(write.at, write.length);
        if (bytes) emitFragment(record, "write", write.offset, bytes, false);
        return;
    }
    const bytes = copyBytes(write.at, write.length);
    if (!bytes) return;
    const pending = held ?? [];
    pending.push({ streamId: write.streamId, offset: write.offset, bytes });
    if (!resolvable && pending.length <= MAX_DEFERRED_CHUNKS) {
        deferredEgress.set(key, pending);
        return;
    }
    deferredEgress.delete(key);
    // Never resolvable: release everything under the session's own key.
    const conn = resolvable ? connection! : toAddress(session);
    for (const f of pending) {
        const record = connectionRecord(state, conn, f.streamId, FRAME_OUT_LABEL, "write", resolvable);
        emitFragment(record, "write", f.offset, f.bytes, false);
    }
}

/**
 * With the STREAM-frame hooks live, a de-framed body record is reported only
 * for a connection captured through the body path (one that started before
 * the hooks). Records without a resolved connection are dropped: they could
 * duplicate bytes the frame hooks already reported.
 */
export function bodyHookReports(record: { message: QuicMessage; connection?: Address }): boolean {
    return record.connection !== undefined
        && frameCapture.onBody(String(record.message["ssl_session_id"])) === "bodies";
}

function onStreamFrameListener(state: QuicheLayoutState): ScriptInvocationListenerCallbacks {
    const crumb = `QuicConnection::OnStreamFrame (${state.moduleName})`;
    return {
        onEnter(args) {
            if (_isShuttingDownNow()) return;
            hookBreadcrumb(crumb);
            try {
                resetReadableCache();
                if (!isReadable(args[1], STREAM_FRAME_OFFSET + 8)) return;
                emitIngressFrame(state, args[0], args[1]);
            } catch (e) {
                devlog_error(`[${FRAME_IN_LABEL}] onEnter threw: ${e}`);
            }
        },
    };
}

function writeStreamDataListener(state: QuicheLayoutState): ScriptInvocationListenerCallbacks {
    const crumb = `QuicSession::WriteStreamData (${state.moduleName})`;
    return {
        onEnter(args) {
            this.writer = null;
            if (_isShuttingDownNow()) return;
            hookBreadcrumb(crumb);
            try {
                resetReadableCache();
                const writer = args[4];
                if (!isReadable(writer, DATA_WRITER_LENGTH + 8)) return;
                this.writer = writer;
                this.session = args[0];
                this.streamId = args[1].toUInt32();
                this.offset = uint64(args[2].toString()).toNumber();
                this.length = uint64(args[3].toString()).toNumber();
                this.before = writer.add(DATA_WRITER_LENGTH).readU64().toNumber();
            } catch (e) {
                this.writer = null;
                devlog_error(`[${FRAME_OUT_LABEL}] onEnter threw: ${e}`);
            }
        },
        onLeave(retval) {
            if (!this.writer || _isShuttingDownNow()) return;
            try {
                // WRITE_SUCCESS == 0; the writer must have grown by exactly the
                // frame length (self-check of the QuicDataWriter layout).
                if (retval.toInt32() !== 0 || this.length === 0) return;
                const writer = this.writer as NativePointer;
                const after = writer.add(DATA_WRITER_LENGTH).readU64().toNumber();
                if (after - this.before !== this.length) return;
                resetReadableCache();
                emitEgressWrite(state, this.session, {
                    streamId: this.streamId, offset: this.offset, length: this.length,
                    at: writer.add(DATA_WRITER_BUFFER).readPointer().add(this.before),
                });
            } catch (e) {
                devlog_error(`[${FRAME_OUT_LABEL}] onLeave threw: ${e}`);
            }
        },
    };
}

/**
 * Hook the STREAM-frame boundary of `moduleName`. Returns true only when BOTH
 * directions are hooked: the caller then skips the de-framed body hooks, whose
 * bytes these hooks already carry (inside HTTP/3 DATA frames).
 */
export async function installQuicheFrameHooks(moduleName: string): Promise<boolean> {
    const mod = Process.findModuleByName(moduleName);
    const state = quicheLayoutState(moduleName);
    if (!mod || !state) return false;
    const api = await locateQuicheFrameApi(mod);
    if (!api.onStreamFrame || !api.writeStreamData) return false;
    const listeners: InvocationListener[] = [];
    try {
        listeners.push(Interceptor.attach(api.onStreamFrame, onStreamFrameListener(state)));
        listeners.push(Interceptor.attach(api.writeStreamData, writeStreamDataListener(state)));
    } catch (e) {
        // One direction alone would duplicate the body hooks' bytes: all or nothing.
        listeners.forEach((l) => l.detach());
        devlog_error(`[Google QUICHE] failed to hook the STREAM-frame boundary in ${moduleName}: ${e}`);
        return false;
    }
    log(`[*] Hooked QuicConnection::OnStreamFrame + QuicSession::WriteStreamData in ${moduleName} ` +
        `(raw HTTP/3 streams: request/response headers via QPACK, bodies, control streams)`);
    return true;
}
