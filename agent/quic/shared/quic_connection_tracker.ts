// agent/quic/shared/quic_connection_tracker.ts
//
// Tracks QUIC connection metadata (addresses, connection IDs)
// keyed by the native connection pointer. Shared across all QUIC
// library definitions (Cloudflare quiche, Google QUICHE, msquic).

import { devlog } from "../../util/log.js";
import { LruMap } from "../../shared/lru.js";
import type { QuicSocketAddress } from "./quiche_layout.js";

export interface QuicConnectionInfo {
    serverName: string;
    // Address encoding matches the pcap writer contract (see
    // shared_functions.ts getPortsAndAddresses): AF_INET addresses are a
    // host-order 32-bit integer (number); AF_INET6 addresses are a 32-char
    // uppercase hex string with no separators.
    localAddr: string | number;
    localPort: number;
    peerAddr: string | number;
    peerPort: number;
    ssFamily: string;
    scid: string;
    dcid: string;
    /** Tuple guessed by synthesizeInfo (the connection's own peer was not readable). */
    synthetic?: boolean;
}

/** Which way a QUIC record travels: "read" = server -> device, "write" = device -> server. */
export type QuicDirection = "read" | "write";

/**
 * Build a datalog-compatible message object from connection info.
 * Returns the address fields needed by sendQuicDatalog/sendDatalog.
 *
 * The 4-tuple is oriented like every other datalog record (and like
 * getPortsAndAddresses): a read travels peer -> local, a write local -> peer.
 * The host (friTap/flow/collector.py `_oriented_endpoints`) relies on that to
 * tell the device from the server; emitting writes peer -> local made a
 * request's "server" the device's own (synthetic 10.0.0.1) address.
 *
 * `direction` is also emitted explicitly, so the host never has to infer it
 * from the hook label; `library` (the producing module) lets the host
 * attribute the record without guessing from the last library announcement.
 */
export function buildQuicMessage(
    info: QuicConnectionInfo,
    connKey: string,
    functionLabel: string,
    direction: QuicDirection = "read",
    library?: string,
    clientRandom?: string,
): { [key: string]: any } {
    const isWrite = direction === "write";
    const message: { [key: string]: any } = {
        src_addr: isWrite ? info.localAddr : info.peerAddr,
        src_port: isWrite ? info.localPort : info.peerPort,
        dst_addr: isWrite ? info.peerAddr : info.localAddr,
        dst_port: isWrite ? info.peerPort : info.localPort,
        ss_family: info.ssFamily,
        ssl_session_id: connKey,
        function: functionLabel,
        direction,
    };
    if (library) message.library = library;
    // Same join key as the TCP records: the host keys QUIC flows by it. Not
    // stampRecordClientRandom: record_message.ts pulls Frida-only modules into this pure file.
    if (clientRandom) message.client_random = clientRandom;
    // Lets the host treat the tuple as provisional and swap in the connection's
    // real one once a later record carries it.
    if (info.synthetic) message.endpoints_synthetic = true;
    return message;
}

/** A real UDP peer 4-tuple observed at the socket layer (best-effort). */
export interface ObservedPeer {
    addr: string | number;
    port: number;
    family: string;
}

/** A connection resolved from native memory: its stable key and 4-tuple. */
export interface LinkedQuicConnection {
    connKey: string;
    info: QuicConnectionInfo;
    /** TLS client_random of this generation, once its handshake was observed. */
    clientRandom?: string;
    /**
     * No addresses were readable, so a freed pointer reused by a new
     * connection cannot be told apart: a later handshake may rebind it.
     */
    reuseUndetectable?: boolean;
    /**
     * Same peer, new self address: connection migration (Chrome port
     * migration) keeps the key and client_random; a reused pointer is told
     * apart by its new handshake, which starts a new generation on bind.
     */
    selfChanged?: boolean;
}

interface LinkedEntry extends LinkedQuicConnection {
    generation: number;
    /** Local side synthesized because the library has no self address yet (0-RTT). */
    provisionalLocal: boolean;
    /** A record was built for this generation (the host already has flows under its key). */
    carriedTraffic?: boolean;
    /** This generation's client handshake started (CryptoConnect seen). */
    handshakeStarted?: boolean;
}

/** Bound on remembered native connections (least recently used evicted first). */
const MAX_LINKED_CONNECTIONS = 4096;

/** `self` when it can be the local side of a connection to `peer` (same family), else null. */
function usableSelf(self: QuicSocketAddress | null, peer: QuicSocketAddress): QuicSocketAddress | null {
    return self && self.family === peer.family ? self : null;
}

/** True iff `info`'s local or peer side is the endpoint `e`. */
function infoHasEndpoint(info: QuicConnectionInfo, side: "local" | "peer", e: QuicSocketAddress): boolean {
    return info.ssFamily === e.family &&
        (side === "local" ? info.localAddr === e.addr && info.localPort === e.port
                          : info.peerAddr === e.addr && info.peerPort === e.port);
}

/** Local side of a tuple taken from a real self address. */
function localOf(self: QuicSocketAddress): { localAddr: string | number; localPort: number } {
    return { localAddr: self.addr, localPort: self.port };
}

/** FNV-1a hash of a pointer string → stable unsigned 32-bit value. */
function hashPtr(connPtr: string): number {
    let h = 0x811c9dc5;
    for (let i = 0; i < connPtr.length; i++) {
        h ^= connPtr.charCodeAt(i);
        h = Math.imul(h, 0x01000193);
    }
    return h >>> 0;
}

/**
 * Deterministic synthetic client side for hash `h`: 10.0.0.1 for IPv4, a
 * unique-local fd00::/8 address for IPv6 (so families never mismatch within a
 * flow), with a per-connection ephemeral port.
 */
function syntheticLocal(h: number, family: string): { localAddr: string | number; localPort: number } {
    const localPort = 49152 + (h % 16384);
    if (family === "AF_INET6") {
        return { localAddr: "FD" + "00".repeat(11) + ("00000000" + h.toString(16).toUpperCase()).slice(-8), localPort };
    }
    return { localAddr: 0x0A000001, localPort }; // 10.0.0.1
}

/**
 * Render an address (in the pcap-writer encoding — host-order int for AF_INET,
 * 32-char hex for AF_INET6) as a human-readable string for diagnostic logs only.
 * The pcap itself consumes the raw encoding; this is purely so devlog peer lines
 * read as 192.168.1.1 / 2001:4860:4860::8888 instead of 3232235777 / a hex blob.
 */
function formatAddr(addr: string | number, family: string): string {
    if (family === "AF_INET6" && typeof addr === "string" && addr.length === 32) {
        return (addr.match(/.{1,4}/g) ?? []).join(":").toLowerCase();
    }
    if (typeof addr === "number") {
        return ((addr >>> 24) & 0xff) + "." + ((addr >>> 16) & 0xff) + "." +
               ((addr >>> 8) & 0xff) + "." + (addr & 0xff);
    }
    return String(addr);
}

// Well-known non-QUIC UDP service ports. Browser HTTP/3 runs on 443 (occasionally
// 80); these infrastructure services (DNS, mDNS, LLMNR, NTP, DHCP, NetBIOS, SSDP)
// use the same connected-UDP socket()/connect() pattern the observer watches, so
// without a port filter a routine DNS lookup (e.g. 192.168.1.1:53) becomes the
// "most-recently observed peer" and is mislabeled as the QUIC server in synthesized
// flows. We deny-list infra ports rather than allow-list 443 so non-standard QUIC
// test ports still resolve. (DoH3/DoQ to a resolver on :443 is genuine HTTP/3 and
// is intentionally kept.)
const NON_QUIC_UDP_PORTS = new Set<number>([
    53,   // DNS
    5353, // mDNS
    5355, // LLMNR
    123,  // NTP
    67, 68, // DHCP
    137, 138, // NetBIOS
    1900, // SSDP
]);

export class QuicConnectionTracker {
    private _connections: Map<string, QuicConnectionInfo> = new Map();
    // Maps a QuicSpdyStream*/visitor pointer to its owning connection pointer,
    // so the per-stream read/write hooks can find the registered connection.
    private _streamToConn: Map<string, string> = new Map();
    // Most-recently observed real UDP peer (from the libc socket layer). QUIC
    // does not expose its fd to the C++ stream objects, so we cannot correlate
    // a specific connection to its socket without version-fragile struct walks.
    // Folding the real server address into every synthetic flow is a deliberate
    // best-effort: the per-connection synthetic local port still keeps each
    // connection in its own Wireshark conversation.
    private _observedPeer: ObservedPeer | null = null;
    // Delivers peers a native observer queued since the last read (see setObservedPeerFeed).
    private _observedPeerFeed: (() => void) | null = null;

    // Last peer key (`addr:port`) we emitted a devlog for, per branch. The libc
    // connect() observer fires on EVERY UDP connect() — including every DNS
    // lookup to the resolver — so logging unconditionally floods the JS→Python
    // message channel (hundreds of identical lines) and, at Ctrl+C, the
    // un-drained backlog stalls script.unload()/session.detach(). We therefore
    // log only when the peer actually changes; the stored _observedPeer is
    // updated regardless, so capture behavior is unchanged.
    private _lastLoggedObservedKey: string | null = null;
    private _lastLoggedIgnoredKey: string | null = null;

    // Native connection pointer -> its resolved key/4-tuple (see resolveLinked).
    private _linked = new LruMap<string, LinkedEntry>(MAX_LINKED_CONNECTIONS);
    // client_random of connections without a linked entry (layout unknown or
    // addresses unreadable), keyed by pointer; their connKey is the pointer.
    private _unlinkedClientRandom = new LruMap<string, string>(MAX_LINKED_CONNECTIONS);

    /**
     * Register a new QUIC connection.
     * @param connPtr  Native pointer to the connection object (as hex string key)
     * @param info     Connection metadata
     */
    register(connPtr: string, info: QuicConnectionInfo): void {
        this._connections.set(connPtr, info);
        devlog("[QUIC tracker] registered connection " + connPtr +
               " -> " + formatAddr(info.peerAddr, info.ssFamily) + ":" + info.peerPort);
    }

    /**
     * Look up connection info by pointer.
     */
    get(connPtr: string): QuicConnectionInfo | undefined {
        return this._connections.get(connPtr);
    }

    /**
     * Remove a connection (on free/close).
     */
    remove(connPtr: string): QuicConnectionInfo | undefined {
        const info = this._connections.get(connPtr);
        if (info) {
            this._connections.delete(connPtr);
            devlog("[QUIC tracker] removed connection " + connPtr);
        }
        return info;
    }

    /** Record a stream pointer → connection pointer association. */
    registerStream(streamPtr: string, connPtr: string): void {
        this._streamToConn.set(streamPtr, connPtr);
    }

    /** Resolve a stream pointer back to its connection pointer, if known. */
    resolveStream(streamPtr: string): string | undefined {
        return this._streamToConn.get(streamPtr);
    }

    /**
     * Record the real UDP peer seen at the socket layer (best-effort). Peers on
     * well-known non-QUIC service ports (DNS, mDNS, NTP, …) are ignored so they
     * cannot pollute the synthesized flow's server 4-tuple — see NON_QUIC_UDP_PORTS.
     */
    setObservedPeer(peer: ObservedPeer): void {
        // Cheap dedup key — plain field concat, no formatAddr(). This runs on
        // EVERY connect(); the costly human-readable formatting (IPv6 regex +
        // allocations) is deferred into the rare on-change log branch below.
        const peerKey = peer.family + "|" + peer.addr + "|" + peer.port;
        if (NON_QUIC_UDP_PORTS.has(peer.port)) {
            // Separate ignored/observed dedup streams so repeated DNS/mDNS/NTP
            // connects stay quiet even when interleaved with real QUIC peers.
            if (peerKey !== this._lastLoggedIgnoredKey) {
                this._lastLoggedIgnoredKey = peerKey;
                devlog("[QUIC tracker] ignoring non-QUIC observed peer " +
                       formatAddr(peer.addr, peer.family) + ":" + peer.port);
            }
            return;
        }
        this._observedPeer = peer;  // stored regardless — capture behavior unchanged
        if (peerKey !== this._lastLoggedObservedKey) {
            this._lastLoggedObservedKey = peerKey;
            devlog("[QUIC tracker] observed real UDP peer " +
                   formatAddr(peer.addr, peer.family) + ":" + peer.port);
        }
    }

    /** `feed` runs before each read of the observed peer and calls setObservedPeer for queued peers. */
    setObservedPeerFeed(feed: () => void): void {
        this._observedPeerFeed = feed;
    }

    /**
     * Resolve connection info for a key, always returning a usable, parseable
     * 4-tuple. Prefers a registered connection, then a deterministic synthetic
     * one (so a flow is never emitted as 0.0.0.0:0). The synthetic peer is
     * replaced by the observed real peer when one is known.
     */
    resolveInfo(connPtr: string): QuicConnectionInfo {
        return this._connections.get(connPtr) ?? this.synthesizeInfo(connPtr);
    }

    /**
     * Build a deterministic, stable synthetic 4-tuple for a connection pointer.
     * The peer (server) lands in 240.0.0.0/4 (reserved, non-routable, so it can
     * never be confused with real capture traffic) keyed off the pointer hash;
     * the client gets a fixed address with a per-connection ephemeral port. If a
     * real peer was observed at the socket layer it is folded in for fidelity.
     */
    synthesizeInfo(connPtr: string): QuicConnectionInfo {
        const h = hashPtr(connPtr);
        this._observedPeerFeed?.();
        const peer = this._observedPeer;

        if (peer && peer.family === "AF_INET6") {
            // v6 observed peer: synthesize a matching-family unique-local client
            // (fd00::/8) so families don't mismatch within one flow.
            return {
                serverName: "", scid: "", dcid: "",
                ssFamily: "AF_INET6",
                peerAddr: peer.addr, peerPort: peer.port,
                ...syntheticLocal(h, "AF_INET6"),
                synthetic: true,
            };
        }

        const peerAddr = peer && peer.family === "AF_INET"
            ? peer.addr
            : ((0xF0000000 | (h & 0x0FFFFFFF)) >>> 0);
        const peerPort = peer && peer.family === "AF_INET" ? peer.port : 443;
        return {
            serverName: "", scid: "", dcid: "",
            ssFamily: "AF_INET",
            peerAddr, peerPort,
            ...syntheticLocal(h, "AF_INET"),
            synthetic: true,
        };
    }

    /**
     * Stable 4-tuple for a connection whose addresses were read from the QUIC
     * library's own connection object (Google QUICHE: QuicConnection's path).
     *
     * Every hook of one connection resolves through here with the same native
     * connection pointer, so request and response — and all streams of the
     * connection — share ONE key and ONE 4-tuple:
     *   - self + peer known  -> the real 4-tuple;
     *   - peer only (0-RTT, before the first received packet) -> real peer with
     *     a synthetic client, upgraded in place once the self address appears
     *     (same connKey, so the host keeps it one connection);
     *   - neither -> the deterministic synthetic tuple of the pointer.
     * A different peer behind the same pointer is a new connection reusing
     * freed memory: it gets a new generation and key so it never folds into the
     * previous connection's streams. A different self with the same peer is
     * migration (see selfChanged) until a new handshake proves reuse
     * (resolveNewHandshake, or a different client_random in bindClientRandom).
     */
    resolveLinked(connPtr: string, self: QuicSocketAddress | null, peer: QuicSocketAddress | null): LinkedQuicConnection {
        const prev = this._linked.get(connPtr);
        if (!peer) return prev ?? this.unlinkedConnection(connPtr);
        const local = usableSelf(self, peer);
        if (prev && infoHasEndpoint(prev.info, "peer", peer)) {
            if (!local) return prev;
            if (prev.provisionalLocal) {
                prev.info = { ...prev.info, ...localOf(local), synthetic: false };
                prev.provisionalLocal = false;
                return prev;
            }
            if (infoHasEndpoint(prev.info, "local", local)) return prev;
            // Only one Initial on the wire for such a change: same connection, new local port.
            // Records after the migration must carry the port actually on the wire.
            prev.info = { ...prev.info, ...localOf(local) };
            prev.selfChanged = true;
            return prev;
        }
        const entry = this.startGeneration(connPtr, prev, local, peer);
        // Generation 0 keeps the unlinked key (the pointer), so it is the same
        // connection whose handshake was bound before its addresses were readable.
        const unlinkedClientRandom = prev ? undefined : this._unlinkedClientRandom.get(connPtr);
        if (unlinkedClientRandom) entry.clientRandom = unlinkedClientRandom;
        this._unlinkedClientRandom.delete(connPtr);
        return entry;
    }

    /**
     * resolveLinked for a client handshake start (TlsClientHandshaker::CryptoConnect):
     * it runs once per new connection and never on migration, so a pointer whose
     * generation already started a handshake or carried records is a reused one
     * even with the same peer and no client_random to compare.
     */
    resolveNewHandshake(connPtr: string, self: QuicSocketAddress | null, peer: QuicSocketAddress | null): LinkedQuicConnection {
        const prev = this._linked.get(connPtr);
        if (prev && peer && (prev.carriedTraffic || prev.handshakeStarted) && infoHasEndpoint(prev.info, "peer", peer)) {
            this.startGeneration(connPtr, prev, usableSelf(self, peer), peer);
        }
        const linked = this.resolveLinked(connPtr, self, peer);
        const entry = this._linked.get(connPtr);
        if (entry && entry.connKey === linked.connKey) entry.handshakeStarted = true;
        return linked;
    }

    /** Note that a record was built for a connection resolveLinked just returned. */
    noteLinkedTraffic(linked: LinkedQuicConnection): void {
        const entry = linked as Partial<LinkedEntry>;
        // An unlinked identity has no generation and is never tracked.
        if (entry.carriedTraffic || entry.generation === undefined) return;
        entry.carriedTraffic = true;
    }

    /** A new connection behind `connPtr`: next generation, own key and 4-tuple. */
    private startGeneration(connPtr: string, prev: LinkedEntry | undefined,
                            self: QuicSocketAddress | null, peer: QuicSocketAddress): LinkedEntry {
        const generation = prev ? prev.generation + 1 : 0;
        const connKey = generation === 0 ? connPtr : connPtr + "#" + generation;
        const local = self ? localOf(self) : syntheticLocal(hashPtr(connKey), peer.family);
        const entry: LinkedEntry = {
            connKey, generation, provisionalLocal: !self,
            info: {
                serverName: "", scid: "", dcid: "", ssFamily: peer.family,
                peerAddr: peer.addr, peerPort: peer.port, ...local,
                // A guessed local makes the tuple provisional for the host.
                synthetic: !self,
            },
        };
        this._linked.set(connPtr, entry);
        return entry;
    }

    /** Self of a linked entry: after a self change, the migrated address its info carries. */
    private static selfOf(entry: LinkedEntry): QuicSocketAddress {
        return { family: entry.info.ssFamily, addr: entry.info.localAddr, port: entry.info.localPort } as QuicSocketAddress;
    }

    /** Peer of a linked entry, as the endpoint resolveLinked compares against. */
    private static peerOf(entry: LinkedEntry): QuicSocketAddress {
        return { family: entry.info.ssFamily, addr: entry.info.peerAddr, port: entry.info.peerPort } as QuicSocketAddress;
    }

    /** Identity of a connection without readable addresses: the pointer key and a synthetic tuple. */
    private unlinkedConnection(connPtr: string): LinkedQuicConnection {
        const unlinked: LinkedQuicConnection = {
            connKey: connPtr, info: this.synthesizeInfo(connPtr), reuseUndetectable: true,
        };
        const clientRandom = this._unlinkedClientRandom.get(connPtr);
        if (clientRandom) unlinked.clientRandom = clientRandom;
        return unlinked;
    }

    /**
     * Attach `clientRandom` to the connection behind `connPtr` only while it is
     * still generation `connKey`, so a reused pointer never inherits it. A
     * different client_random after a self change starts the next generation.
     * Without the CryptoConnect hook (resolveNewHandshake) a reused pointer to
     * the same peer whose old generation never got a client_random cannot be
     * told from migration and keeps the old key.
     */
    bindClientRandom(connPtr: string, connKey: string, clientRandom: string): boolean {
        if (!clientRandom) return false;
        const entry = this._linked.get(connPtr);
        if (entry) {
            if (entry.connKey !== connKey) return false;
            if (entry.selfChanged && entry.clientRandom && entry.clientRandom !== clientRandom) {
                // A second handshake after the self change: a new connection reusing the pointer.
                const next = this.startGeneration(connPtr, entry, QuicConnectionTracker.selfOf(entry),
                                                  QuicConnectionTracker.peerOf(entry));
                next.clientRandom = clientRandom;
                return true;
            }
            entry.clientRandom = clientRandom;
            return true;
        }
        if (connKey !== connPtr) return false;  // a generation whose entry is gone (evicted)
        this._unlinkedClientRandom.set(connPtr, clientRandom);
        return true;
    }

    /**
     * Number of tracked connections.
     */
    get size(): number {
        return this._connections.size;
    }
}

/**
 * Singleton connection tracker shared across all QUIC hooks.
 */
export const quicConnectionTracker = new QuicConnectionTracker();
