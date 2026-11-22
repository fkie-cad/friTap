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

import { log, devlog_debug, devlog_error, hookBreadcrumb, _isShuttingDownNow } from "../../util/log.js";
import { sendQuicStreamChunk } from "../../shared/shared_structures.js";
import { FifoSet } from "../../shared/lru.js";
import { isReadable, resetReadableCache } from "../../util/safe_memory.js";
import { QuicDirection } from "./quic_connection_tracker.js";
import { Address, toAddress } from "./quiche_layout.js";
import { QuicStreamReassembler } from "./quic_stream_reassembler.js";
import { QuicheConnectionCapture, StreamFrameKeys, isUniStream, streamFrameKeys } from "./quiche_connection_capture.js";
import { installQuicheCryptoBinding } from "./quiche_crypto_binding.js";
import {
    DATA_WRITER_BUFFER, DATA_WRITER_LENGTH, STREAM_FRAME_DATA_BUFFER, STREAM_FRAME_DATA_LENGTH, STREAM_FRAME_FIN,
    STREAM_FRAME_OFFSET, STREAM_FRAME_STREAM_ID, locateQuicheFrameApi,
} from "./quiche_frame_locator.js";
import {
    isSessionLayoutPending, QuicheLayoutState, QuicheStreamRecord, QuicMessage, QuicRecord, quicheLayoutState,
    resolveConnectionRecord, sendQuicheBody, sessionConnection, streamIdLearner, unresolvedConnectionRecord,
} from "./quiche_records.js";
import { PendingBody, QuicheBodyQueue } from "./quiche_body_queue.js";
import { EgressReleaseReason, HeldChunk, QuicheEgressHold } from "./quiche_egress_hold.js";
import { QuicheStreamIdLearner, isStreamIdPending, legacyStreamIdFromWindow } from "./quiche_stream_id.js";

const FRAME_IN_LABEL = "QuicConnection_OnStreamFrame";
const FRAME_OUT_LABEL = "QuicSession_WriteStreamData";
/** Sessions already reported as released unresolved (log once each). */
const MAX_LOGGED_UNRESOLVED = 256;

const frameReassembler = new QuicStreamReassembler();
const frameCapture = new QuicheConnectionCapture();
// Held while the session layout is being learned: released under the session's key,
// a stream's first chunks would split from its later, connection-keyed ones.
const deferredEgress = new QuicheEgressHold<EgressFragment>(releaseHeldEgress, {
    sizeOf: (f) => f.bytes.byteLength,
    holdWhile: (f) => isSessionLayoutPending(f.state),
});
const loggedUnresolved = new FifoSet<string>(MAX_LOGGED_UNRESOLVED);

/** A raw egress fragment held while its session's connection is not resolvable yet. */
interface EgressFragment {
    state: QuicheLayoutState; session: Address; streamId: number; offset: number; bytes: Uint8Array;
}

/**
 * Per-connection key shared by reassembly, capture-path choice and the host:
 * the tracker's connection key, which gains a "#<generation>" suffix when a
 * new connection reuses a freed QuicConnection's memory — so a reused address
 * never inherits the old connection's stream offsets.
 */
function recordKey(record: { message: QuicMessage }): string {
    return String(record.message["ssl_session_id"]);
}

/** Reassembly key of a direction's stream: "<direction>|<connection>|<streamId>". */
function streamKey(direction: QuicDirection, ownerKey: string): string {
    return `${direction}|${ownerKey}`;
}

/** Capture keys plus the reassembly key of one fragment, built once per fragment. */
interface FragmentKeys extends StreamFrameKeys { readonly stream: string; }

/** Per-stream capture keys of any record, frame or body path: the one key both sides decide ownership on. */
function captureKeys(record: { message: QuicMessage }, streamId: number): StreamFrameKeys {
    return streamFrameKeys(recordKey(record), streamId);
}

function fragmentKeys(direction: QuicDirection, record: QuicRecord): FragmentKeys {
    const keys = captureKeys(record, record.streamId);
    return { ...keys, stream: streamKey(direction, keys.owner) };
}

/** False when a fragment cannot be reported: body-path stream or already delivered bytes. */
function wantsFragment(keys: FragmentKeys, offset: number, length: number, fin: boolean): boolean {
    if (!frameCapture.mayReportFrameKeys(keys)) return false;
    return fin || frameReassembler.canDeliver(keys.stream, offset, length);
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

/**
 * Reassemble one fragment and emit its newly contiguous bytes if the stream uses the frame path.
 * Exported for unit tests.
 */
export function emitFragment(record: QuicRecord, direction: QuicDirection, offset: number, bytes: Uint8Array,
                      fin: boolean, keys: FragmentKeys = fragmentKeys(direction, record)): void {
    const chunks = frameReassembler.push(keys.stream, offset, bytes, fin);
    if (chunks.length === 0) return;
    const capture = frameCapture.onStreamFrameKeys(keys, chunks[0].offset);
    if (capture === "bodies") return;
    // record.message is this call's own object; every chunk re-stamps the same fields.
    for (const chunk of chunks) {
        sendQuicStreamChunk(record.message, toArrayBuffer(chunk.data), record.streamId,
                            { offset: chunk.offset, fin: chunk.fin === true, midstream: capture === "midstream" });
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
    const keys = fragmentKeys("read", record);
    noteFrameStream(state, keys);
    if (!wantsFragment(keys, offset, length, fin)) return;
    const bytes = copyBytes(length > 0 ? frame.add(STREAM_FRAME_DATA_BUFFER).readPointer() : NULL, length);
    if (bytes) emitFragment(record, "read", offset, bytes, fin, keys);
}

/** One egress STREAM-frame payload written into a packet (QuicSession::WriteStreamData). */
interface EgressWrite { streamId: number; offset: number; length: number; at: NativePointer; }

/**
 * Emit an egress write of `session`. Fast path: the connection resolves and
 * nothing is held — check before copying. Otherwise the copy is held until the
 * session's connection resolves (or the hold releases it unresolved).
 */
function emitEgressWrite(state: QuicheLayoutState, session: NativePointer, write: EgressWrite): void {
    const key = session.toString();
    const connection = resolvableConnection(state, knownConnection(state, toAddress(session)));
    if (connection !== null && !deferredEgress.has(key)) {
        const record = connectionRecord(state, connection, write.streamId, FRAME_OUT_LABEL, "write");
        const keys = fragmentKeys("write", record);
        noteFrameStream(state, keys);
        if (!wantsFragment(keys, write.offset, write.length, false)) return;
        const bytes = copyBytes(write.at, write.length);
        if (bytes) emitFragment(record, "write", write.offset, bytes, false, keys);
        return;
    }
    const bytes = copyBytes(write.at, write.length);
    if (!bytes) return;
    const fragment = { state, session: toAddress(session), streamId: write.streamId, offset: write.offset, bytes };
    if (connection === null) {
        deferredEgress.hold(key, fragment);
        return;
    }
    emitEgressFragments([...deferredEgress.take(key), { chunk: fragment, heldMs: 0 }], connection, true);
}

/** `connection` when its record can be resolved now, else null. */
function resolvableConnection(state: QuicheLayoutState, connection: Address | null): Address | null {
    return connection !== null && state.connLayout !== null ? connection : null;
}

/** The session's connection pointer when readable, layout resolved or not. */
function knownConnection(state: QuicheLayoutState, session: Address): Address | null {
    const connection = sessionConnection(state, session);
    return connection !== null && connection !== 0n ? connection : null;
}

/** Emit one session's fragments: the connection resolves once, each chunk gets its own message copy. */
function emitEgressFragments(fragments: readonly HeldChunk<EgressFragment>[], connection: Address,
                             resolvable: boolean): void {
    if (fragments.length === 0) return;
    const first = fragments[0].chunk;
    const { message } = connectionRecord(first.state, connection, first.streamId, FRAME_OUT_LABEL, "write", resolvable);
    for (const { chunk: f, heldMs } of fragments) {
        const record = { message: { ...message }, streamId: f.streamId };
        // The host stamps records on receipt: held_ms lets it back-date a held one.
        if (heldMs > 0) record.message.held_ms = Math.round(heldMs);
        emitFragment(record, "write", f.offset, f.bytes, false);
    }
}

/**
 * Release a session's held chunks that never resolved through the normal path:
 * resolved if that became possible meanwhile, else under the connection's (or,
 * unknown, the session's own) key with a synthetic 4-tuple — like ingress.
 * Exported for unit tests.
 */
export function releaseHeldEgress(key: string, fragments: HeldChunk<EgressFragment>[],
                                  reason: EgressReleaseReason): void {
    if (fragments.length === 0) return;
    const { state, session } = fragments[0].chunk;
    const connection = knownConnection(state, session);
    const resolvable = resolvableConnection(state, connection) !== null;
    if (!resolvable && !loggedUnresolved.has(key)) {
        loggedUnresolved.add(key);
        devlog_debug(`[Google QUICHE] releasing ${fragments.length} held egress chunk(s) of session ${key} ` +
                     `with an unresolved connection (${reason})`);
    }
    emitEgressFragments(fragments, connection ?? session, resolvable);
}

/** Tell the stream-id learner a real request-stream id of the connection (its oracle). */
function noteFrameStream(state: QuicheLayoutState, keys: StreamFrameKeys): void {
    if (!isUniStream(keys.streamId)) streamIdLearner(state).noteStream(keys.connection, keys.streamId);
}

/**
 * With the STREAM-frame hooks live, a de-framed body record is reported only
 * for a connection captured through the body path (one that started before
 * the hooks), and not for its streams the frame path owns. Records without a
 * resolved connection are dropped: they could duplicate bytes the frame hooks
 * already reported.
 */
export function bodyHookReports(record: { message: QuicMessage; streamId?: number | null;
                                          connection?: Address }): boolean {
    if (record.connection === undefined) return false;
    const streamId = record.streamId ?? null;
    if (streamId === null || streamId < 0) return frameCapture.onUnknownBodyStream(recordKey(record)) === "bodies";
    return frameCapture.onBodyStreamKeys(captureKeys(record, streamId)) === "bodies";
}

/** Report a held body with the id now known (null: never learned) through the normal ownership decision. */
function releasePendingBody(entry: PendingBody<QuicheStreamRecord>, streamId: number | null, heldMs: number): void {
    // The host stamps records on receipt: held_ms lets it back-date this one.
    const message = { ...entry.record.message, held_ms: Math.round(heldMs) };
    const record: QuicheStreamRecord = { ...entry.record, message, streamId, pending: undefined };
    // Held before the frame hooks were live: the frame path cannot have reported these bytes.
    if (entry.frameHooksLive === false || bodyHookReports(record)) sendQuicheBody(record, entry.data);
}

/** Wire `queue` to the learner: flushed when learning settles, held longer while the id is still pending. */
export function attachBodyQueue<R>(queue: QuicheBodyQueue<R>, learner: QuicheStreamIdLearner): QuicheBodyQueue<R> {
    // Fires inside the record that taught the learner, so held bodies go out before it.
    learner.onLearningSettled = () => queue.flush((window) => learner.streamIdFromWindow(window));
    // Learning needs several ingress ids and took ~6.5 s on Chrome; the hold caps and memory bounds still apply.
    queue.holdWhile = () => isStreamIdPending(learner.learning);
    return queue;
}

/**
 * Keep body stream ids unknown (held) until the STREAM-frame hook install settles.
 * Live: learning takes over, held records get a fresh timeout. Failed: no oracle
 * will ever come, so held records go out with the legacy slot of their window.
 */
export function awaitFrameHookOutcome(learner: QuicheStreamIdLearner, install: Promise<boolean>,
                                      queueOf: () => Pick<QuicheBodyQueue<unknown>, "flush" | "restartTimer"> | undefined): void {
    learner.awaitOracle();
    const settle = (hooked: boolean): void => {
        try {
            if (hooked) {
                learner.enableOracle();
                queueOf()?.restartTimer();
                return;
            }
            if (learner.learning !== "awaiting") return;    // hooks went live, then a later install step threw
            learner.oracleUnavailable();
            queueOf()?.flush(legacyStreamIdFromWindow);
        } catch (e) {
            devlog_error(`[Google QUICHE] releasing held bodies failed: ${e}`);
        }
    };
    install.then(settle, () => settle(false));
}

/** Hold body stream ids of `moduleName` until its STREAM-frame hook install (`install`) settles. */
export function awaitQuicheFrameHooks(moduleName: string, install: Promise<boolean>): void {
    const state = quicheLayoutState(moduleName);
    if (state) awaitFrameHookOutcome(streamIdLearner(state), install, () => state.bodyQueue);
}

/** The module's held-body queue (created on first hold). */
function bodyQueue(state: QuicheLayoutState): QuicheBodyQueue<QuicheStreamRecord> {
    if (state.bodyQueue === undefined) {
        const queue = attachBodyQueue(new QuicheBodyQueue<QuicheStreamRecord>(releasePendingBody),
                                      streamIdLearner(state));
        state.bodyQueue = queue;
    }
    return state.bodyQueue;
}

/**
 * Report a de-framed body record (OnDataFramePayload / WriteOrBufferBody).
 * While id_ is still unknown (frame hooks pending, or learning) the record is
 * held, not sent with id -1 or a guessed id: an id-less body cannot be matched
 * to the frame path's stream ownership, and a wrong one is persisted.
 */
export function reportQuicheBody(record: QuicheStreamRecord, data: ArrayBuffer, frameHooksLive: boolean): void {
    if (record.pending !== undefined) {   // only a linked record (connection known) is ever pending
        // A "frames" connection drops every body at release anyway: skip the copy.
        if (frameHooksLive && frameCapture.modeOf(recordKey(record)) === "frames") return;
        const { state, window } = record.pending;
        bodyQueue(state).push({ record, data, window: window(), frameHooksLive });
        return;
    }
    if (frameHooksLive && !bodyHookReports(record)) return;
    sendQuicheBody(record, data);
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
    // The frame hooks' real stream ids now locate QuicStream::id_ for the body hooks.
    streamIdLearner(state).enableOracle();
    log(`[*] Hooked QuicConnection::OnStreamFrame + QuicSession::WriteStreamData in ${moduleName} ` +
        `(raw HTTP/3 streams: request/response headers via QPACK, bodies, control streams)`);
    // Optional: without it the records just carry no client_random.
    installQuicheCryptoBinding(moduleName, state, api.onCryptoFrame, api.cryptoConnect);
    return true;
}
