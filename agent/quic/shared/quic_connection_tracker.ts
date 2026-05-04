// agent/quic/shared/quic_connection_tracker.ts
//
// Tracks QUIC connection metadata (addresses, connection IDs)
// keyed by the native connection pointer. Shared across all QUIC
// library definitions (Cloudflare quiche, Google QUICHE, msquic).

import { devlog } from "../../util/log.js";

export interface QuicConnectionInfo {
    serverName: string;
    localAddr: string;
    localPort: number;
    peerAddr: string;
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

class QuicConnectionTracker {
    private _connections: Map<string, QuicConnectionInfo> = new Map();

    /**
     * Register a new QUIC connection.
     * @param connPtr  Native pointer to the connection object (as hex string key)
     * @param info     Connection metadata
     */
    register(connPtr: string, info: QuicConnectionInfo): void {
        this._connections.set(connPtr, info);
        devlog("[QUIC tracker] registered connection " + connPtr +
               " -> " + info.peerAddr + ":" + info.peerPort);
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
