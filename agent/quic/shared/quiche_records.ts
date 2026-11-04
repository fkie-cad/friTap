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

import { log } from "../../util/log.js";
import { sendQuicDatalog } from "../../shared/shared_structures.js";
import { isReadable, resetReadableCache, safeReadPointer } from "../../util/safe_memory.js";
import { buildQuicMessage, quicConnectionTracker, QuicDirection } from "./quic_connection_tracker.js";
import {
    Address, QuicheConnectionLayout, QuicheHookObject, QuicheLayout, QuicheMemory, QuicheStreamLink, QuicSocketAddress,
    discoverConnectionLayout, discoverQuicheLayout, discoverSessionLayout, isRoutableEndpoint, readConnectionLink,
    readSessionLink, readStreamLink, streamFromHookObject,
} from "./quiche_layout.js";

export type QuicMessage = { [key: string]: any };

/** A datalog message plus the real QUIC stream id it belongs to. */
export interface QuicRecord { message: QuicMessage; streamId: number; }

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
}

const quicheLayoutStates = new Map<string, QuicheLayoutState | null>();

export function toAddress(p: NativePointer): Address {
    return BigInt(p.toString());
}

function toNativePointer(a: Address): NativePointer {
    return ptr("0x" + a.toString(16));
}

/** Range-checked read of up to `length` bytes, clamped at the end of the mapping. */
function readClamped(p: NativePointer, address: Address, length: number): Uint8Array | null {
    if (isReadable(p, length)) {                       // common case: shares the per-walk cache
        const buf = p.readByteArray(length);
        return buf ? new Uint8Array(buf) : null;
    }
    const range = Process.findRangeByAddress(p);
    if (!range || range.protection[0] !== "r") return null;
    const n = Math.min(length, Number(toAddress(range.base) + BigInt(range.size) - address));
    if (n <= 0) return null;
    const buf = p.readByteArray(n);
    return buf ? new Uint8Array(buf) : null;
}

/** Frida-backed QuicheMemory: every read is range-checked, never faults. */
function fridaQuicheMemory(module: Module): QuicheMemory {
    const lo = toAddress(module.base);
    const hi = lo + BigInt(module.size);
    return {
        pointerSize: Process.pointerSize,
        readPointer(address: Address): Address | null {
            const value = safeReadPointer(toNativePointer(address));
            return value === null ? null : toAddress(value);
        },
        readBytes(address: Address, length: number): Uint8Array | null {
            try {
                return readClamped(toNativePointer(address), address, length);
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
        if (module) state = { moduleName, mem: fridaQuicheMemory(module), layout: null, attempts: 0,
                              triedStreams: new Set(), connLayout: null, sessionConnection: null, connAttempts: 0 };
    } catch (_e) { state = null; }
    quicheLayoutStates.set(moduleName, state);
    return state;
}

/**
 * Adopt a stream-learned layout. A connection layout already in use (learned
 * by a connection/session hook) is kept: records keyed with it are live, and
 * switching to a different address-pair offset of the same QuicConnection
 * would re-key every open connection as a new generation mid-flight.
 */
function adoptFullLayout(state: QuicheLayoutState, learned: QuicheLayout): QuicheLayout {
    const layout = state.connLayout ? { ...learned, ...state.connLayout } : learned;
    state.layout = layout;
    state.connLayout = layout;
    state.sessionConnection = layout.sessionConnection;
    state.triedStreams.clear();
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

/** Record for a resolved stream/connection link (real key, 4-tuple and stream id). */
function linkedRecord(state: QuicheLayoutState, link: QuicheStreamLink, label: string,
                      direction: QuicDirection): QuicRecord {
    const linked = quicConnectionTracker.resolveLinked(
        "0x" + link.connection.toString(16), routable(link.self), routable(link.peer));
    return {
        message: buildQuicMessage(linked.info, linked.connKey, label, direction, state.moduleName),
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
                                    label: string, direction: QuicDirection = "read"):
        { message: QuicMessage; streamId: number | null; connection?: Address } {
    const state = quicheLayoutState(moduleName);
    let legacyKey = obj.toString();
    if (state) {
        resetReadableCache();
        const stream = streamFromHookObject(state.mem, toAddress(obj), kind);
        if (stream !== null && stream !== 0n) {
            learnQuicheLayout(state, stream);
            const link = state.layout ? readStreamLink(state.mem, state.layout, stream) : null;
            if (link) return { ...linkedRecord(state, link, label, direction), connection: link.connection };
            // Unlinkable, but every hook of this stream still agrees on one key.
            legacyKey = "0x" + stream.toString(16);
        }
    }
    return { message: legacyMessage(legacyKey, label, direction, moduleName), streamId: null };
}

/** Like resolveQuicheRecord for session-level hooks (`this` = QuicSession, id from args). */
export function resolveQuicheSessionRecord(moduleName: string, session: NativePointer, streamId: number,
                                           label: string, direction: QuicDirection): QuicRecord {
    const state = quicheLayoutState(moduleName);
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
    log(`[*] Google QUICHE (${state.moduleName}): resolved QUIC connection addressing from a ${source} ` +
        `(connection+0x${layout.connectionAddresses.toString(16)} -> self/peer address)`);
}

/** The QuicConnection of a QuicSession, learning the session layout on first use. */
export function sessionConnection(state: QuicheLayoutState, session: Address): Address | null {
    if (state.sessionConnection === null && state.connAttempts < MAX_LAYOUT_ATTEMPTS) {
        state.connAttempts++;
        const learned = discoverSessionLayout(state.mem, session, state.connLayout);
        if (learned) {
            state.sessionConnection = learned.sessionConnection;
            noteConnectionLayout(state, learned, "session");
        }
    }
    const offset = state.sessionConnection;
    return offset === null ? null : state.mem.readPointer(session + BigInt(offset));
}

/** Record for a connection-level hook; null when the connection is not resolvable. */
export function resolveConnectionRecord(state: QuicheLayoutState, connection: Address, streamId: number,
                                        label: string, direction: QuicDirection): QuicRecord | null {
    if (!state.connLayout && state.connAttempts < MAX_LAYOUT_ATTEMPTS) {
        state.connAttempts++;
        const learned = discoverConnectionLayout(state.mem, connection);
        if (learned) noteConnectionLayout(state, learned, "connection");
    }
    const link = state.connLayout ? readConnectionLink(state.mem, state.connLayout, connection, streamId) : null;
    return link ? linkedRecord(state, link, label, direction) : null;
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
