// agent/quic/shared/quiche_records.ts
//
// Datalog records for Google QUICHE (Chrome/Chromium/Cronet) hooks: real
// connection addressing (see quiche_layout.ts) on top of Frida memory.
//
// Every hook resolves its `this` to the owning QuicSpdyStream / QuicSession /
// QuicConnection, then — through a per-module layout learned at runtime — to the
// QuicConnection and its real (self, peer) UDP addresses plus the real QUIC
// stream id. All hooks of one connection therefore share one key and one
// 4-tuple, and request/response of a stream carry the same stream id. When the
// layout cannot be learned on a build, records fall back to the canonical
// stream pointer (legacy synthetic tuple).

import { devlog_debug, log } from "../../util/log.js";
import { reportCacheHit } from "../../shared/learned_module_cache.js";
import type { CacheModule } from "../../shared/module_mapping.js";
import { sendQuicDatalog } from "../../shared/shared_structures.js";
import {
    findRange, isReadable, moduleImageBounds, resetReadableCache, safeReadPointer, untag,
} from "../../util/safe_memory.js";
import { buildQuicMessage, LinkedQuicConnection, quicConnectionTracker, QuicDirection } from "./quic_connection_tracker.js";
import {
    Address, QuicheConnectionLayout, QuicheHookObject, QuicheLayout, QuicheMemory, QuicheStreamLink, QuicSocketAddress,
    discoverConnectionLayout, discoverQuicheLayout, discoverSessionLayout, isRoutableEndpoint, readConnectionLink,
    readSessionLink, readStreamLink, streamFromHookObject, findHandshakerConnection, HANDSHAKER_SESSION_OFFSET,
    connectionLayoutHolds, sessionConnectionAt, streamSessionAt, toAddress,
} from "./quiche_layout.js";
import {
    QuicheHintField, QuicheLayoutHints, describeHints, forgetRejectedHint, readQuicheLayoutHints, reportQuicheLayout,
} from "./quiche_layout_hints.js";
import {
    QuicheStreamIdLearner, StreamIdLearning, StreamIdWindowSource, isStreamIdPending, lazyStreamIdWindow,
} from "./quiche_stream_id.js";
import type { QuicheBodyQueue } from "./quiche_body_queue.js";

export type QuicMessage = { [key: string]: any };

/** A datalog message plus the real QUIC stream id it belongs to. */
export interface QuicRecord { message: QuicMessage; streamId: number; }

/** A stream-level record whose id the learner cannot give yet, but will once it has learned id_. */
export interface PendingStreamId {
    /** Module state: its stream-id learner and held-body queue. */
    state: QuicheLayoutState;
    /** The stream's id_ candidate slots; read (once) only for a record that is actually held. */
    window: StreamIdWindowSource;
}

/** Record of a stream-level hook. */
export interface QuicheStreamRecord {
    message: QuicMessage;
    streamId: number | null;
    connection?: Address;
    pending?: PendingStreamId;
}

/** Learning attempts per module before giving up (each probes a distinct object). */
const MAX_LAYOUT_ATTEMPTS = 64;

/** Per-module layout knowledge, shared by every QUICHE hook of the module. */
export interface QuicheLayoutState {
    moduleName: string;
    mem: QuicheMemory;
    /** Full stream -> session -> connection layout (stream-level hooks). */
    layout: QuicheLayout | null;
    attempts: number;
    triedStreams: Set<string>;
    /** Connection addressing; `layout` itself once that is learned. */
    connLayout: QuicheConnectionLayout | null;
    /** QuicSession::connection_ offset; `layout.sessionConnection` once that is learned. */
    sessionConnection: number | null;
    /** Attempts of the connection/session-level learning (independent of `attempts`). */
    connAttempts: number;
    /** TlsClientHandshaker::session_ offset, once a handshaker resolved to a connection. */
    handshakerSession?: number;
    /** A fallback-scan offset seen on one handshaker, awaiting a second one. */
    handshakerCandidate?: { offset: number; handshaker: Address };
    /** Where QuicStream::id_ is, learned against the STREAM-frame hooks (see quiche_stream_id.ts). */
    streamIds?: QuicheStreamIdLearner;
    /** Body records held until `streamIds` settles (created on first hold, see quiche_frame_capture.ts). */
    bodyQueue?: QuicheBodyQueue<QuicheStreamRecord>;
    /** The module, once known: learned values are cached per module across runs. */
    cacheModule?: CacheModule;
    /** Fields holding a cached hint not yet validated live, with their failed checks (the stream-id learner tracks its own). */
    seeded?: Map<QuicheHintField, number>;
}

/** The module's stream-id learner (created on first use). */
export function streamIdLearner(state: QuicheLayoutState): QuicheStreamIdLearner {
    state.streamIds ??= new QuicheStreamIdLearner();
    return state.streamIds;
}

const quicheLayoutStates = new Map<string, QuicheLayoutState | null>();

function toNativePointer(a: Address): NativePointer {
    return ptr("0x" + a.toString(16));
}

/** Range-checked read of up to `length` bytes, clamped at the end of the mapping. */
function readClamped(p: NativePointer, length: number): Uint8Array | null {
    if (isReadable(p, length)) {                       // common case: shares the per-walk cache
        const buf = p.readByteArray(length);
        return buf ? new Uint8Array(buf) : null;
    }
    const range = findRange(p);
    if (range === null || range.protection[0] !== "r") return null;
    // findRange answers for the untagged address (Android TBI).
    const n = Math.min(length, Number(toAddress(range.end) - toAddress(untag(p))));
    if (n <= 0) return null;
    const buf = p.readByteArray(n);
    return buf ? new Uint8Array(buf) : null;
}

/** Frida-backed QuicheMemory: every read is range-checked, never faults. */
function fridaQuicheMemory(module: Module): QuicheMemory {
    const [lo, hi] = moduleImageBounds(module).map(toAddress);
    return {
        pointerSize: Process.pointerSize,
        readPointer(address: Address): Address | null {
            const value = safeReadPointer(toNativePointer(address));
            return value === null ? null : toAddress(value);
        },
        readBytes(address: Address, length: number): Uint8Array | null {
            try {
                return readClamped(toNativePointer(address), length);
            } catch (_e) {
                return null;
            }
        },
        isModuleAddress(address: Address): boolean {
            return address >= lo && address < hi;
        },
    };
}

/** The module's layout state (created on first use), or null when the module is gone. */
export function quicheLayoutState(moduleName: string): QuicheLayoutState | null {
    if (quicheLayoutStates.has(moduleName)) return quicheLayoutStates.get(moduleName)!;
    let state: QuicheLayoutState | null = null;
    try {
        const module = Process.findModuleByName(moduleName);
        if (module) {
            state = { moduleName, mem: fridaQuicheMemory(module), layout: null, attempts: 0,
                      triedStreams: new Set(), connLayout: null, sessionConnection: null, connAttempts: 0 };
            // Hints are optional: a failure here must not disable the module's hooks.
            try { seedQuicheLayout(state, module); } catch (e) {
                devlog_debug(`[Google QUICHE] ${moduleName}: seeding layout hints failed: ${e}`);
            }
        }
    } catch (_e) { state = null; }
    quicheLayoutStates.set(moduleName, state);
    return state;
}

// ---- cross-run hints -----------------------------------------------------------

/**
 * Failed live checks (before any success) that reject a seeded hint. One is not
 * enough: a hook can fire on a torn-down or not-yet-initialised object.
 */
export const SEED_REJECT_FAILURES = 2;

/**
 * Start `state` from the module's cached hints. Each one is used at once but
 * stays a candidate (in `state.seeded`) until a live object validates it; after
 * SEED_REJECT_FAILURES failed checks it is dropped and normal discovery takes over.
 */
export function seedQuicheLayout(state: QuicheLayoutState, mod: CacheModule): void {
    state.cacheModule = mod;
    const hints = readQuicheLayoutHints(mod, (a) => state.mem.isModuleAddress(a));
    const seeded = new Map<QuicheHintField, number>();
    if (hints.connection) {
        state.connLayout = hints.connection;
        seeded.set("connection", 0);
    }
    if (hints.sessionConnection !== undefined) {
        state.sessionConnection = hints.sessionConnection;
        seeded.set("sessionConnection", 0);
    }
    if (hints.streamSession !== undefined && hints.connection && hints.sessionConnection !== undefined) {
        state.layout = { streamSession: hints.streamSession, sessionConnection: hints.sessionConnection, ...hints.connection };
        seeded.set("streamSession", 0);
    } else if (hints.streamSession !== undefined) {
        forgetRejectedHint(mod, "streamSession");      // only validated through the connection hints
    }
    if (hints.handshakerSession !== undefined) {
        state.handshakerSession = hints.handshakerSession;
        seeded.set("handshakerSession", 0);
    }
    const seededStreamId = hints.streamIdFromSession !== undefined && seedStreamIdOffset(state, hints.streamIdFromSession);
    if (hints.streamIdFromSession !== undefined && !seededStreamId) forgetRejectedHint(mod, "streamIdFromSession");
    state.seeded = seeded;
    if (seeded.size > 0 || seededStreamId) {
        devlog_debug(`[Google QUICHE] ${state.moduleName}: seeded cached layout hints (${describeHints(hints)})`);
    }
}

/** The learner validates a seeded id_ offset itself and reports the outcome back. */
function seedStreamIdOffset(state: QuicheLayoutState, offset: number): boolean {
    const learner = streamIdLearner(state);
    if (!learner.seedOffset(offset)) return false;
    learner.onSeedSettled = (holds) => applySeedOutcome(state, "streamIdFromSession", holds);
    return true;
}

function isSeeded(state: QuicheLayoutState, field: QuicheHintField): boolean {
    return state.seeded?.has(field) ?? false;
}

/** State a seeded field's value lives in, cleared when the hint is rejected. */
const CLEAR_SEEDED: Partial<Record<QuicheHintField, (state: QuicheLayoutState) => void>> = {
    connection: (state) => { state.connLayout = null; state.layout = null; },
    sessionConnection: (state) => { state.sessionConnection = null; state.layout = null; },
    streamSession: (state) => { state.layout = null; },
    handshakerSession: (state) => { state.handshakerSession = undefined; },
};

/** Seeded fields whose value was only seeded together with (and validated through) the key field. */
const SEED_DEPENDENTS: Partial<Record<QuicheHintField, QuicheHintField[]>> = {
    connection: ["streamSession"],
    sessionConnection: ["streamSession"],
};

/** Live outcome of a pending seeded field's check; no-op once the field is settled (confirmed seeds are not rechecked). */
function settleSeed(state: QuicheLayoutState, field: QuicheHintField, holds: boolean): void {
    if (!isSeeded(state, field)) return;
    if (!holds) {
        const failures = state.seeded!.get(field)! + 1;
        state.seeded!.set(field, failures);
        if (failures < SEED_REJECT_FAILURES) return;
    }
    decideSeed(state, field, holds);
}

/** Settle a pending seeded field now, without further checks. */
function decideSeed(state: QuicheLayoutState, field: QuicheHintField, holds: boolean): void {
    if (!state.seeded?.delete(field)) return;
    applySeedOutcome(state, field, holds);
}

/** Keep the hint for good, or drop it (and its dependents) and rediscover. */
function applySeedOutcome(state: QuicheLayoutState, field: QuicheHintField, holds: boolean): void {
    if (holds) {
        if (state.cacheModule) reportCacheHit(state.cacheModule);
        return;
    }
    CLEAR_SEEDED[field]?.(state);   // streamIdFromSession: the learner already reverted itself
    if (state.cacheModule) forgetRejectedHint(state.cacheModule, field);
    devlog_debug(`[Google QUICHE] ${state.moduleName}: cached ${field} hint failed live validation; rediscovering`);
    // A dependent was only ever validated through `field`, so it falls with it.
    for (const dependent of SEED_DEPENDENTS[field] ?? []) decideSeed(state, dependent, false);
}

function checkSeededConnection(state: QuicheLayoutState, connection: Address | null): void {
    if (!isSeeded(state, "connection") || connection === null || connection === 0n) return;
    settleSeed(state, "connection", connectionLayoutHolds(state.mem, state.connLayout!, connection));
}

function checkSeededSession(state: QuicheLayoutState, session: Address): void {
    if (!isSeeded(state, "sessionConnection")) return;
    settleSeed(state, "sessionConnection", sessionConnectionAt(state.mem, session, state.sessionConnection!, state.connLayout) !== null);
}

/** Validate the seeded stream -> session -> connection hops on a live stream, each hop on its own. */
function checkSeededStream(state: QuicheLayoutState, stream: Address): void {
    if (!isSeeded(state, "streamSession") || !state.layout) return;
    const session = streamSessionAt(state.mem, stream, state.layout.streamSession);
    settleSeed(state, "streamSession", session !== null);
    if (session === null) return;
    checkSeededSession(state, session);
    if (state.sessionConnection !== null) {
        checkSeededConnection(state, state.mem.readPointer(session + BigInt(state.sessionConnection)));
    }
}

/**
 * Discovery found `learned` while hints were pending: they validate only by agreeing
 * with it. Decided at once: discovery validated a whole live object chain.
 */
function reconcileSeeds(state: QuicheLayoutState, learned: QuicheLayout): void {
    if (isSeeded(state, "connection")) {
        decideSeed(state, "connection", state.connLayout!.connectionAddresses === learned.connectionAddresses
                   && state.connLayout!.connectionVtable === learned.connectionVtable);
    }
    if (isSeeded(state, "sessionConnection")) {
        decideSeed(state, "sessionConnection", state.sessionConnection === learned.sessionConnection);
    }
}

/**
 * Report what `state` learned to the cross-run cache. The cache coalesces
 * reports and drops values it already holds, so calling this per learned value is cheap.
 */
function markLearned(state: QuicheLayoutState): void {
    if (state.cacheModule) reportQuicheLayout(state.cacheModule, validatedLayout(state));
}

/** Values `state` holds that were discovered or validated live (pending seeds excluded). */
function validatedLayout(state: QuicheLayoutState): QuicheLayoutHints {
    const trusted = (field: QuicheHintField) => !isSeeded(state, field);
    return {
        streamSession: state.layout && trusted("streamSession") ? state.layout.streamSession : undefined,
        sessionConnection: state.sessionConnection !== null && trusted("sessionConnection") ? state.sessionConnection : undefined,
        connection: state.connLayout && trusted("connection") ? state.connLayout : undefined,
        handshakerSession: trusted("handshakerSession") ? state.handshakerSession : undefined,
        streamIdFromSession: state.streamIds?.validatedOffset ?? undefined,
    };
}

/**
 * Adopt a stream-learned layout. A connection layout already in use (learned
 * by a connection/session hook) is kept: records keyed with it are live, and
 * switching to a different address-pair offset of the same QuicConnection
 * would re-key every open connection as a new generation mid-flight.
 */
function adoptFullLayout(state: QuicheLayoutState, learned: QuicheLayout): QuicheLayout {
    reconcileSeeds(state, learned);
    const layout = state.connLayout ? { ...learned, ...state.connLayout } : learned;
    state.layout = layout;
    state.connLayout = layout;
    state.sessionConnection = layout.sessionConnection;
    state.triedStreams.clear();
    markLearned(state);
    return layout;
}

/** Try to learn the stream->connection layout from `stream` (bounded, once per stream). */
function learnQuicheLayout(state: QuicheLayoutState, stream: Address): void {
    const key = stream.toString(16);
    if (state.layout || state.attempts >= MAX_LAYOUT_ATTEMPTS || state.triedStreams.has(key)) return;
    state.attempts++;
    state.triedStreams.add(key);
    const learned = discoverQuicheLayout(state.mem, stream);
    if (learned) {
        const layout = adoptFullLayout(state, learned);
        log(`[*] Google QUICHE (${state.moduleName}): resolved real QUIC connection addressing ` +
            `(stream+0x${layout.streamSession.toString(16)} -> session, ` +
            `session+0x${layout.sessionConnection.toString(16)} -> connection, ` +
            `connection+0x${layout.connectionAddresses.toString(16)} -> self/peer address)`);
    } else if (state.attempts >= MAX_LAYOUT_ATTEMPTS) {
        log(`[!] Google QUICHE (${state.moduleName}): could not resolve the QUIC connection layout after ` +
            `${MAX_LAYOUT_ATTEMPTS} streams; flows use synthetic per-stream addresses`);
    }
}

function routable(a: QuicSocketAddress | null): QuicSocketAddress | null {
    return isRoutableEndpoint(a) ? a : null;
}

/** Tracker identity of a link's connection (starts a new generation on address reuse). */
function linkedConnection(link: QuicheStreamLink): LinkedQuicConnection {
    return quicConnectionTracker.resolveLinked(
        "0x" + link.connection.toString(16), routable(link.self), routable(link.peer));
}

/** Record for a resolved stream/connection link (real key, 4-tuple and stream id). */
function linkedRecord(state: QuicheLayoutState, link: QuicheStreamLink, label: string,
                      direction: QuicDirection, linked: LinkedQuicConnection = linkedConnection(link)): QuicRecord {
    quicConnectionTracker.noteLinkedTraffic(linked);
    return {
        message: buildQuicMessage(linked.info, linked.connKey, label, direction, state.moduleName,
                                  linked.clientRandom),
        streamId: link.streamId,
    };
}

/**
 * Message for a stream-level hook without a link: resolves the stream pointer
 * to its connection (when registered), then to a guaranteed-parseable 4-tuple
 * (registered -> synthetic), so a flow is never emitted as 0.0.0.0:0.
 */
function legacyMessage(streamPtr: string, label: string, direction: QuicDirection, library: string): QuicMessage {
    const connPtr = quicConnectionTracker.resolveStream(streamPtr) ?? streamPtr;
    return buildQuicMessage(quicConnectionTracker.resolveInfo(connPtr), connPtr, label, direction, library);
}

/**
 * Datalog message for a QUICHE hook whose `this` is `obj` (of kind `kind`).
 * `streamId` is the real QUIC stream id, or null when the layout is unknown
 * (callers then keep their legacy surrogate / -1 sentinel).
 */
export function resolveQuicheRecord(moduleName: string, obj: NativePointer, kind: QuicheHookObject,
                                    label: string, direction: QuicDirection = "read"): QuicheStreamRecord {
    const state = quicheLayoutState(moduleName);
    let legacyKey = obj.toString();
    if (state) {
        resetReadableCache();
        const stream = streamFromHookObject(state.mem, toAddress(obj), kind);
        if (stream !== null && stream !== 0n) {
            const record = resolveStreamRecord(state, stream, label, direction);
            if (record) return record;
            // Unlinkable, but every hook of this stream still agrees on one key.
            legacyKey = "0x" + stream.toString(16);
        }
    }
    return { message: legacyMessage(legacyKey, label, direction, moduleName), streamId: null };
}

/** Record of a live QuicStream through the learned (or seeded) layout; null when it does not link. */
export function resolveStreamRecord(state: QuicheLayoutState, stream: Address, label: string, direction: QuicDirection):
        (QuicheStreamRecord & { connection: Address }) | null {
    checkSeededStream(state, stream);
    learnQuicheLayout(state, stream);
    const link = state.layout ? readStreamLink(state.mem, state.layout, stream) : null;
    return link ? streamLinkedRecord(state, state.layout!, stream, link, label, direction) : null;
}

/**
 * Record of a stream-level hook whose stream resolved. The stream id comes from
 * the learned id_ slot (null while unknown), keyed by the same connection key
 * the STREAM-frame path uses, so per-stream ownership compares like with like.
 */
function streamLinkedRecord(state: QuicheLayoutState, layout: QuicheLayout, stream: Address, link: QuicheStreamLink,
                            label: string, direction: QuicDirection): QuicheStreamRecord & { connection: Address } {
    const linked = linkedConnection(link);
    const learner = streamIdLearner(state);
    const before = learner.learning;
    const window = lazyStreamIdWindow(state.mem, stream, layout.streamSession);
    const streamId = learner.streamId(state.mem, stream, layout.streamSession, linked.connKey,
                                      direction === "read", window);
    if (learner.learning !== before) logStreamIdLearning(state, learner.learning, learner.offset);
    const record = linkedRecord(state, { ...link, streamId: streamId ?? -1 }, label, direction, linked);
    const result: QuicheStreamRecord & { connection: Address } =
        { message: record.message, streamId, connection: link.connection };
    if (streamId === null && isStreamIdPending(learner.learning)) result.pending = { state, window };
    return result;
}

function logStreamIdLearning(state: QuicheLayoutState, learning: StreamIdLearning, offset: number | null): void {
    if (learning === "learned" && offset !== null) {
        markLearned(state);
        const sign = offset < 0 ? "-" : "+";
        log(`[*] Google QUICHE (${state.moduleName}): learned QuicStream::id_ at session_ ${sign}0x` +
            `${Math.abs(offset).toString(16)} (matched against STREAM-frame stream ids)`);
    } else if (learning === "failed") {
        log(`[!] Google QUICHE (${state.moduleName}): could not locate QuicStream::id_; ` +
            `de-framed bodies are kept only on connections the STREAM-frame path does not report`);
    }
}

/** Like resolveQuicheRecord for session-level hooks (`this` = QuicSession, id from args). */
export function resolveQuicheSessionRecord(moduleName: string, session: NativePointer, streamId: number,
                                           label: string, direction: QuicDirection): QuicRecord {
    const state = quicheLayoutState(moduleName);
    if (state) checkSeededSession(state, toAddress(session));
    if (state && state.layout) {
        resetReadableCache();
        const link = readSessionLink(state.mem, state.layout, toAddress(session), streamId);
        if (link) return linkedRecord(state, link, label, direction);
    }
    return { message: legacyMessage(session.toString(), label, direction, moduleName), streamId };
}

// ---- connection-level hooks (QuicConnection / QuicSession `this`) ------------

function noteConnectionLayout(state: QuicheLayoutState, layout: QuicheConnectionLayout,
                              source: "connection" | "session"): void {
    if (state.connLayout) return;
    state.connLayout = { connectionAddresses: layout.connectionAddresses, connectionVtable: layout.connectionVtable };
    markLearned(state);
    log(`[*] Google QUICHE (${state.moduleName}): resolved QUIC connection addressing from a ${source} ` +
        `(connection+0x${layout.connectionAddresses.toString(16)} -> self/peer address)`);
}

/** The QuicConnection of a QuicSession, learning the session layout on first use. */
export function sessionConnection(state: QuicheLayoutState, session: Address): Address | null {
    checkSeededSession(state, session);
    if (state.sessionConnection === null && state.connAttempts < MAX_LAYOUT_ATTEMPTS) {
        state.connAttempts++;
        const learned = discoverSessionLayout(state.mem, session, state.connLayout);
        if (learned) {
            state.sessionConnection = learned.sessionConnection;
            markLearned(state);
            noteConnectionLayout(state, learned, "session");
        }
    }
    const offset = state.sessionConnection;
    return offset === null ? null : state.mem.readPointer(session + BigInt(offset));
}

/** True while sessionConnection() may still learn the session layout. */
export function isSessionLayoutPending(state: QuicheLayoutState): boolean {
    return state.sessionConnection === null && state.connAttempts < MAX_LAYOUT_ATTEMPTS;
}

/**
 * The QuicConnection of a TlsClientHandshaker (CryptoConnect `this`). Read-only:
 * uses the learned (or seeded) session layout and connection vtable, never the
 * discovery budget; null until both are known.
 */
export function handshakerConnection(state: QuicheLayoutState, handshaker: Address): Address | null {
    if (state.sessionConnection === null || state.connLayout === null) return null;
    const link = { sessionConnection: state.sessionConnection, connectionVtable: state.connLayout.connectionVtable };
    const preferred = state.handshakerSession ?? HANDSHAKER_SESSION_OFFSET;
    const found = findHandshakerConnection(state.mem, handshaker, link, preferred);
    if (found === null) return null;
    // The seeded slot is tried first, so a hit elsewhere means it did not hold.
    if (isSeeded(state, "handshakerSession")) settleSeed(state, "handshakerSession", found.handshakerSession === preferred);
    noteHandshakerSession(state, handshaker, found.handshakerSession);
    return found.connection;
}

/**
 * Keep the preferred session_ offset unless the scan found another one on two
 * different handshakers: a single hit can be a coincidental slot.
 */
function noteHandshakerSession(state: QuicheLayoutState, handshaker: Address, offset: number): void {
    if (offset === (state.handshakerSession ?? HANDSHAKER_SESSION_OFFSET)) {
        if (state.handshakerSession === offset) return;
        state.handshakerSession = offset;
        markLearned(state);
        return;
    }
    const candidate = state.handshakerCandidate;
    if (candidate && candidate.offset === offset && candidate.handshaker !== handshaker) {
        state.handshakerSession = offset;
        state.handshakerCandidate = undefined;
        markLearned(state);
    } else {
        state.handshakerCandidate = { offset, handshaker };
    }
}

/** Link of a connection-level hook's connection, learning the layout on first use; null when not resolvable. */
function connectionLink(state: QuicheLayoutState, connection: Address, streamId: number): QuicheStreamLink | null {
    checkSeededConnection(state, connection);
    if (!state.connLayout && state.connAttempts < MAX_LAYOUT_ATTEMPTS) {
        state.connAttempts++;
        const learned = discoverConnectionLayout(state.mem, connection);
        if (learned) noteConnectionLayout(state, learned, "connection");
    }
    return state.connLayout ? readConnectionLink(state.mem, state.connLayout, connection, streamId) : null;
}

/** Record for a connection-level hook; null when the connection is not resolvable. */
export function resolveConnectionRecord(state: QuicheLayoutState, connection: Address, streamId: number,
                                        label: string, direction: QuicDirection): QuicRecord | null {
    const link = connectionLink(state, connection, streamId);
    return link ? linkedRecord(state, link, label, direction) : null;
}

/**
 * Tracker identity of a connection-level hook's connection, keyed like
 * resolveConnectionRecord / unresolvedConnectionRecord, without building a
 * message (for hooks that need only the key). Uses an already-learned layout
 * only: handshake-time objects must not spend the shared discovery budget
 * that the STREAM-path hooks learn the layout with.
 */
export function resolveConnectionIdentity(state: QuicheLayoutState, connection: Address): LinkedQuicConnection {
    return linkedConnection(connectionOnlyLink(state, connection));
}

/** resolveConnectionIdentity at a client handshake start: a reused pointer gets a new generation. */
export function resolveNewHandshakeIdentity(state: QuicheLayoutState, connection: Address): LinkedQuicConnection {
    const link = connectionOnlyLink(state, connection);
    return quicConnectionTracker.resolveNewHandshake("0x" + connection.toString(16), routable(link.self), routable(link.peer));
}

function connectionOnlyLink(state: QuicheLayoutState, connection: Address): QuicheStreamLink {
    checkSeededConnection(state, connection);
    const link = state.connLayout ? readConnectionLink(state.mem, state.connLayout, connection, 0) : null;
    return link ?? { connection, streamId: 0, self: null, peer: null };
}

/** Same connection key as a resolved record, synthetic 4-tuple (layout unknown). */
export function unresolvedConnectionRecord(state: QuicheLayoutState, connection: Address, streamId: number,
                                           label: string, direction: QuicDirection): QuicRecord {
    return linkedRecord(state, { connection, streamId, self: null, peer: null }, label, direction);
}

/** Send de-framed HTTP/3 body bytes of a resolved record (the host routes them to the stream's flow). */
export function sendQuicheBody(record: { message: QuicMessage; streamId: number | null },
                               data: ArrayBuffer): void {
    sendQuicDatalog(record.message, data, record.streamId ?? -1, undefined, undefined, "udp", undefined, "body");
}
