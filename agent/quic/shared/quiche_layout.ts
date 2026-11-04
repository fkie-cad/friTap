// agent/quic/shared/quiche_layout.ts
//
// Runtime discovery of the Google QUICHE (Chrome/Cronet) object layout that
// links a QUIC stream to its connection and that connection's REAL UDP
// 4-tuple. Pure logic over a tiny memory interface so it runs under Node tests;
// google_quiche.ts supplies the Frida-backed QuicheMemory.
//
// Why: every hook used to key its synthetic 4-tuple by whatever `this` it got
// (QuicSpdyStream, its HttpDecoderVisitor, the embedded QuicStreamSequencer),
// so a request and its response landed on different made-up client ports, and
// the "server" came from the most recent UDP connect() (often Chrome's IPv6
// reachability probe 2001:4860:4860::8888, not the QUIC peer at all).
//
// The links, all from QUICHE's own class layout (no per-version offset table):
//   QuicStream:     ... QuicStreamId id_; QuicSession* session_;
//                       StreamDelegateInterface* stream_delegate_; ...
//                   stream_delegate_ is a base sub-object of the SAME session,
//                   so it points a few vptrs past session_.
//   QuicSession:    QuicConnection* connection_  (connection->visitor_ points
//                   back at the session).
//   QuicConnection: default_path_ {self_address, peer_address} and
//                   last_received_packet_info_ {destination, source}: the same
//                   (self, peer) QuicSocketAddress pair is stored twice.
// The offsets are learned once per module from the first stream that satisfies
// all three links, then re-validated on every use (cheap vtable/back-link checks).

import { toHexString } from "../../util/hex.js";

/** Address value; bigint so tagged (TBI) 64-bit pointers keep full precision. */
export type Address = bigint;

/** Read-only view of process memory used by the discovery (Frida or a test fake). */
export interface QuicheMemory {
    readonly pointerSize: number;
    /** Pointer-sized little-endian word at `address`, or null when unreadable. */
    readPointer(address: Address): Address | null;
    /** Up to `length` bytes at `address` (shorter at a mapping end), or null. */
    readBytes(address: Address, length: number): Uint8Array | null;
    /** True when `address` lies inside the hooked QUICHE module (its vtables do). */
    isModuleAddress(address: Address): boolean;
}

export interface QuicheLayout {
    /** Offset of QuicStream::session_; QuicStream::id_ (uint32) sits one pointer before it. */
    streamSession: number;
    /** Offset of QuicSession::connection_. */
    sessionConnection: number;
    /** Offset of the (self, peer) QuicSocketAddress pair inside QuicConnection. */
    connectionAddresses: number;
    /** vptr shared by every QuicConnection of this build (per-use validation). */
    connectionVtable: Address;
}

export type QuicAddressFamily = "AF_INET" | "AF_INET6" | "UNSPEC";

/** A decoded QuicSocketAddress in the pcap-writer address encoding. */
export interface QuicSocketAddress {
    family: QuicAddressFamily;
    /** AF_INET: host-order uint32; AF_INET6: 32-char uppercase hex; UNSPEC: 0. */
    addr: number | string;
    port: number;
}

/** What one hook call resolves to: the owning connection and the real stream. */
export interface QuicheStreamLink {
    connection: Address;
    streamId: number;
    self: QuicSocketAddress | null;
    peer: QuicSocketAddress | null;
}

/**
 * Which object a hook's `this` (args[0]) is:
 *   "stream"          QuicSpdyStream / QuicStream itself;
 *   "decoder-visitor" QuicSpdyStream::HttpDecoderVisitor {vptr; QuicSpdyStream* stream_};
 *   "sequencer"       the QuicStreamSequencer embedded in the stream, whose
 *                     first member is the owning stream (StreamInterface*).
 */
export type QuicheHookObject = "stream" | "decoder-visitor" | "sequencer";

// QuicSocketAddress = { union address_[16]; IpAddressFamily family_ (int);
// uint16_t port_ (host order) } -> 24 bytes. IP_V4 = 0, IP_V6 = 1, IP_UNSPEC = 2.
export const QUIC_SOCKET_ADDRESS_SIZE = 24;
const ADDRESS_PAIR_SIZE = 2 * QUIC_SOCKET_ADDRESS_SIZE;
const FAMILY_OFFSET = 16;
const PORT_OFFSET = 20;

// Scan windows (bytes). QuicStream::session_ follows the embedded sequencer;
// QuicSession::connection_ follows a handful of vptrs/members; the address
// pair and visitor_ back-pointer sit in QuicConnection's first few KiB.
const STREAM_SCAN_BYTES = 0x200;
const SESSION_SCAN_BYTES = 0x200;
export const CONNECTION_SCAN_BYTES = 0x2000;
/** stream_delegate_ - session_: a base sub-object a few vptrs into the session. */
const MAX_SUBOBJECT_DELTA = 0x100n;

function u32le(bytes: Uint8Array, offset: number): number {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)) >>> 0;
}

/** Decode the QuicSocketAddress at `offset`, or null when the family is invalid. */
export function decodeQuicSocketAddress(bytes: Uint8Array, offset: number): QuicSocketAddress | null {
    if (offset < 0 || offset + QUIC_SOCKET_ADDRESS_SIZE > bytes.length) return null;
    const family = u32le(bytes, offset + FAMILY_OFFSET);
    const port = bytes[offset + PORT_OFFSET] | (bytes[offset + PORT_OFFSET + 1] << 8);
    if (family === 0) {
        const addr = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) |
                      (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
        return { family: "AF_INET", addr, port };
    }
    if (family === 1) return { family: "AF_INET6", addr: toHexString(bytes.subarray(offset, offset + 16)).toUpperCase(), port };
    if (family === 2) return { family: "UNSPEC", addr: 0, port };
    return null;
}

/** True for an initialised IPv4/IPv6 endpoint with a non-zero address and port. */
export function isRoutableEndpoint(a: QuicSocketAddress | null): a is QuicSocketAddress {
    if (!a || a.port === 0) return false;
    if (a.family === "AF_INET") return a.addr !== 0;
    if (a.family === "AF_INET6") return typeof a.addr === "string" && /[1-9A-F]/.test(a.addr);
    return false;
}

export function sameEndpoint(a: QuicSocketAddress, b: QuicSocketAddress): boolean {
    return a.family === b.family && a.addr === b.addr && a.port === b.port;
}

function decodeEndpointPair(bytes: Uint8Array, offset: number):
        { self: QuicSocketAddress; peer: QuicSocketAddress } | null {
    const self = decodeQuicSocketAddress(bytes, offset);
    const peer = decodeQuicSocketAddress(bytes, offset + QUIC_SOCKET_ADDRESS_SIZE);
    if (!isRoutableEndpoint(self) || !isRoutableEndpoint(peer)) return null;
    if (self.family !== peer.family || sameEndpoint(self, peer)) return null;
    return { self, peer };
}

/**
 * Offset of the first (self, peer) address pair that `bytes` (a QuicConnection)
 * stores at least twice — default_path_ plus the last-received-packet copy.
 * Requiring the repeat rejects the many accidental "pairs" in unrelated fields.
 */
export function findAddressPairOffset(bytes: Uint8Array): number | null {
    for (let offset = 0; offset + ADDRESS_PAIR_SIZE <= bytes.length; offset += 4) {
        const pair = decodeEndpointPair(bytes, offset);
        if (!pair) continue;
        for (let repeat = offset + ADDRESS_PAIR_SIZE; repeat + ADDRESS_PAIR_SIZE <= bytes.length; repeat += 4) {
            const other = decodeEndpointPair(bytes, repeat);
            if (other && sameEndpoint(pair.self, other.self) && sameEndpoint(pair.peer, other.peer)) {
                return offset;
            }
        }
    }
    return null;
}

/**
 * True iff an aligned little-endian pointer-sized word of `bytes` equals
 * `value`. Compares 32-bit halves (no per-word BigInt): this runs over KiBs of
 * a candidate object inside a hook while the layout is being learned.
 */
export function containsPointer(bytes: Uint8Array, value: Address, pointerSize: number): boolean {
    const wide = pointerSize === 8;
    if (!wide && value > 0xffffffffn) return false;
    const lo = Number(value & 0xffffffffn);
    const hi = Number((value >> 32n) & 0xffffffffn);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let offset = 0; offset + pointerSize <= bytes.length; offset += pointerSize) {
        if (view.getUint32(offset, true) !== lo) continue;
        if (!wide || view.getUint32(offset + 4, true) === hi) return true;
    }
    return false;
}

function hasModuleVtable(mem: QuicheMemory, obj: Address): boolean {
    const vtable = mem.readPointer(obj);
    return vtable !== null && vtable !== 0n && mem.isModuleAddress(vtable);
}

/** `session` at stream+offset is followed by stream_delegate_, a sub-object of it. */
function isSessionSlot(mem: QuicheMemory, stream: Address, offset: number, session: Address): boolean {
    if (session === 0n || session === stream) return false;
    const delegate = mem.readPointer(stream + BigInt(offset + mem.pointerSize));
    if (delegate === null) return false;
    const delta = delegate - session;
    return delta > 0n && delta <= MAX_SUBOBJECT_DELTA && delta % BigInt(mem.pointerSize) === 0n
        && hasModuleVtable(mem, session) && hasModuleVtable(mem, delegate);
}

type ConnectionLink = Omit<QuicheLayout, "streamSession">;

/** Find QuicSession::connection_: a polymorphic object pointing back at the session and holding the address pair. */
function findConnectionLink(mem: QuicheMemory, session: Address): ConnectionLink | null {
    const ps = mem.pointerSize;
    for (let offset = ps; offset + ps <= SESSION_SCAN_BYTES; offset += ps) {
        const connection = mem.readPointer(session + BigInt(offset));
        if (connection === null || connection === 0n || connection === session) continue;
        if (!hasModuleVtable(mem, connection)) continue;
        const bytes = mem.readBytes(connection, CONNECTION_SCAN_BYTES);
        if (!bytes || !containsPointer(bytes, session, ps)) continue;
        const connectionAddresses = findAddressPairOffset(bytes);
        if (connectionAddresses === null) continue;
        return { sessionConnection: offset, connectionAddresses, connectionVtable: mem.readPointer(connection)! };
    }
    return null;
}

/**
 * Learn the stream -> session -> connection -> address-pair offsets from one
 * live QuicStream. Returns null when the stream does not satisfy every link
 * (e.g. a 0-RTT connection whose self address is not known yet) — the caller
 * simply retries on a later stream.
 */
export function discoverQuicheLayout(mem: QuicheMemory, stream: Address): QuicheLayout | null {
    const ps = mem.pointerSize;
    for (let offset = 2 * ps; offset + 2 * ps <= STREAM_SCAN_BYTES; offset += ps) {
        const session = mem.readPointer(stream + BigInt(offset));
        if (session === null || !isSessionSlot(mem, stream, offset, session)) continue;
        const link = findConnectionLink(mem, session);
        if (link) return { streamSession: offset, ...link };
    }
    return null;
}

/** The QuicStream a hook's `this` belongs to (no validation; see readStreamLink). */
export function streamFromHookObject(mem: QuicheMemory, obj: Address, kind: QuicheHookObject): Address | null {
    switch (kind) {
        case "stream": return obj;
        case "decoder-visitor": return mem.readPointer(obj + BigInt(mem.pointerSize));
        case "sequencer": return mem.readPointer(obj);
    }
}

/** Connection + address pair of a validated QuicConnection pointer. */
function readConnectionAddresses(mem: QuicheMemory, layout: Pick<QuicheLayout, "connectionAddresses" | "connectionVtable">,
                                 connection: Address | null):
        { self: QuicSocketAddress | null; peer: QuicSocketAddress | null } | null {
    if (connection === null || connection === 0n) return null;
    if (mem.readPointer(connection) !== layout.connectionVtable) return null;
    const pair = mem.readBytes(connection + BigInt(layout.connectionAddresses), ADDRESS_PAIR_SIZE);
    if (!pair || pair.length < ADDRESS_PAIR_SIZE) return { self: null, peer: null };
    return {
        self: decodeQuicSocketAddress(pair, 0),
        peer: decodeQuicSocketAddress(pair, QUIC_SOCKET_ADDRESS_SIZE),
    };
}

/** Resolve a stream through a learned layout; null when it does not validate. */
export function readStreamLink(mem: QuicheMemory, layout: QuicheLayout, stream: Address): QuicheStreamLink | null {
    const session = mem.readPointer(stream + BigInt(layout.streamSession));
    if (session === null || !isSessionSlot(mem, stream, layout.streamSession, session)) return null;
    const connection = mem.readPointer(session + BigInt(layout.sessionConnection));
    const addresses = readConnectionAddresses(mem, layout, connection);
    const idBytes = mem.readBytes(stream + BigInt(layout.streamSession - mem.pointerSize), 4);
    if (!addresses || !idBytes || idBytes.length < 4) return null;
    return { connection: connection!, streamId: u32le(idBytes, 0), ...addresses };
}

/** Resolve a QuicSession (session-level hooks) to its connection; streamId is the caller's. */
export function readSessionLink(mem: QuicheMemory, layout: QuicheLayout, session: Address, streamId: number):
        QuicheStreamLink | null {
    const connection = mem.readPointer(session + BigInt(layout.sessionConnection));
    const addresses = readConnectionAddresses(mem, layout, connection);
    return addresses ? { connection: connection!, streamId, ...addresses } : null;
}

// ---------------------------------------------------------------------------
// Connection-level hooks (QuicConnection::OnStreamFrame, QuicSession::WriteStreamData)
//
// These hooks get the QuicConnection or QuicSession directly and the real
// stream id from their arguments, so no stream object (and no streamSession
// offset) is involved: only the session -> connection link and the connection's
// address pair are needed. They are learned from whichever object a hook sees
// first and shared with the stream-level layout above.
// ---------------------------------------------------------------------------

/** The part of QuicheLayout that addresses a connection. */
export type QuicheConnectionLayout = Pick<QuicheLayout, "connectionAddresses" | "connectionVtable">;

/** Learn the address-pair offset from a live QuicConnection (`this` of a connection hook). */
export function discoverConnectionLayout(mem: QuicheMemory, connection: Address): QuicheConnectionLayout | null {
    if (connection === 0n || !hasModuleVtable(mem, connection)) return null;
    const bytes = mem.readBytes(connection, CONNECTION_SCAN_BYTES);
    if (!bytes) return null;
    const connectionAddresses = findAddressPairOffset(bytes);
    if (connectionAddresses === null) return null;
    return { connectionAddresses, connectionVtable: mem.readPointer(connection)! };
}

/**
 * Learn QuicSession::connection_ (and the connection layout) from a live
 * QuicSession. With the connection layout already `known` (from a connection
 * hook), the connection is recognised by its exact vtable plus the visitor_
 * back-pointer, so this also works before the address pair is complete (a
 * 0-RTT write precedes the first received packet).
 */
export function discoverSessionLayout(mem: QuicheMemory, session: Address, known: QuicheConnectionLayout | null = null):
        (QuicheConnectionLayout & { sessionConnection: number }) | null {
    if (session === 0n) return null;
    if (!known) return findConnectionLink(mem, session);
    const ps = mem.pointerSize;
    for (let offset = ps; offset + ps <= SESSION_SCAN_BYTES; offset += ps) {
        const connection = mem.readPointer(session + BigInt(offset));
        if (connection === null || connection === 0n || connection === session) continue;
        if (mem.readPointer(connection) !== known.connectionVtable) continue;
        const bytes = mem.readBytes(connection, CONNECTION_SCAN_BYTES);
        if (bytes && containsPointer(bytes, session, ps)) return { sessionConnection: offset, ...known };
    }
    return null;
}

/** Resolve a QuicConnection (connection-level hooks) to its addresses; streamId is the caller's. */
export function readConnectionLink(mem: QuicheMemory, layout: QuicheConnectionLayout, connection: Address,
                                   streamId: number): QuicheStreamLink | null {
    const addresses = readConnectionAddresses(mem, layout, connection);
    return addresses ? { connection, streamId, ...addresses } : null;
}
