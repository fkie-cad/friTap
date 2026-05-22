// agent/quic/shared/quic_connection_tracker.ts
//
// Tracks QUIC connection metadata (addresses, connection IDs)
// keyed by the native connection pointer. Shared across all QUIC
// library definitions (Cloudflare quiche, Google QUICHE, msquic).

import { devlog } from "../../util/log.js";

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
}

/**
 * Build a datalog-compatible message object from connection info.
 * Returns the address fields needed by sendQuicDatalog/sendDatalog.
 */
export function buildQuicMessage(
    info: QuicConnectionInfo,
    connKey: string,
    functionLabel: string,
): { [key: string]: any } {
    return {
        src_addr: info.peerAddr,
        src_port: info.peerPort,
        dst_addr: info.localAddr,
        dst_port: info.localPort,
        ss_family: info.ssFamily,
        ssl_session_id: connKey,
        function: functionLabel,
    };
}

/** A real UDP peer 4-tuple observed at the socket layer (best-effort). */
export interface ObservedPeer {
    addr: string | number;
    port: number;
    family: string;
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

class QuicConnectionTracker {
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
        if (NON_QUIC_UDP_PORTS.has(peer.port)) {
            devlog("[QUIC tracker] ignoring non-QUIC observed peer " +
                   formatAddr(peer.addr, peer.family) + ":" + peer.port);
            return;
        }
        this._observedPeer = peer;
        devlog("[QUIC tracker] observed real UDP peer " +
               formatAddr(peer.addr, peer.family) + ":" + peer.port);
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
        const localPort = 49152 + (h % 16384);
        const peer = this._observedPeer;

        if (peer && peer.family === "AF_INET6") {
            // v6 observed peer: synthesize a matching-family unique-local client
            // (fd00::/8) so families don't mismatch within one flow.
            const localV6 = "FD" + "00".repeat(11) +
                ("00000000" + h.toString(16).toUpperCase()).slice(-8);
            return {
                serverName: "", scid: "", dcid: "",
                ssFamily: "AF_INET6",
                peerAddr: peer.addr, peerPort: peer.port,
                localAddr: localV6, localPort,
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
            localAddr: 0x0A000001, // 10.0.0.1
            localPort,
        };
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
