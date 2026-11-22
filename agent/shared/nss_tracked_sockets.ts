// agent/shared/nss_tracked_sockets.ts
//
// The sslSockets (from SSL_ImportFD) that tier 2's read-only PK11_GenerateRandom observer
// attributes 32-byte generations to, shared by its two consumers: the client_random
// learner (nss_client_random_learner.ts) and the ECH random recorder
// (nss_ech_random_recorder.ts). One store, one attribution per RNG call.
//
// Attribution rule: while the client_random offset is unknown, a generation into `data`
// goes to the NEAREST tracked socket at or below it within ATTRIBUTION_WINDOW (a linear
// scan); once the offset `off` is known it goes to the socket at data-off (client_random)
// or data-off-32 (ECH client_inner_random), two O(1) lookups. Either way the offset must
// be 4-aligned. Pure: works on bigint addresses.

import { LruMap } from "./lru.js";

export const CLIENT_RANDOM_LENGTH = 32;
/** sslSocket allocations are 0x2000 apart on Fenix: the window alone cannot pick the socket. */
export const ATTRIBUTION_WINDOW = 0x4000;
/** Bound on tracked sockets (the oldest is dropped). */
export const MAX_TRACKED_SOCKETS = 4096;
/** A 32-byte random as lower-case hex. */
export const HEX_RANDOM_RE = /^[0-9a-f]{64}$/;
export const ALL_ZERO_RE = /^0+$/;

const ATTRIBUTION_WINDOW_BIG = BigInt(ATTRIBUTION_WINDOW);
const CLIENT_RANDOM_LENGTH_BIG = BigInt(CLIENT_RANDOM_LENGTH);

/** Per-socket state of both consumers. */
export interface TrackedSocket {
    /** learner: offset from the sslSocket -> randoms generated there (bounded) */
    learnerRandoms: Map<number, string[]>;
    /** learner: validated offset, "invalid" after a mismatch, undefined while undecided */
    verdict?: number | "invalid";
    /** ECH recorder: offset -> FIRST random generated there */
    echRandoms: Map<number, string>;
}

/** Socket and offset a generation was attributed to. */
export interface Attribution {
    ss: bigint;
    offset: number;
}

export class NssTrackedSockets {
    // Insertion order is eviction order: reads use peek()/has(), which never promote.
    private readonly records: LruMap<bigint, TrackedSocket>;

    constructor(maxSockets: number = MAX_TRACKED_SOCKETS) {
        this.records = new LruMap(maxSockets);
    }

    get size(): number { return this.records.size; }

    /** A new sslSocket from SSL_ImportFD; a record left at a reused address is reset. */
    track(ss: bigint): void {
        this.records.set(ss, { learnerRandoms: new Map(), echRandoms: new Map() });
    }

    forget(ss: bigint): void {
        this.records.delete(ss);
    }

    clear(): void {
        this.records.clear();
    }

    record(ss: bigint): TrackedSocket | undefined {
        return this.records.peek(ss);
    }

    /** Every record, oldest first. */
    allRecords(): TrackedSocket[] {
        return this.records.entries().map(([, record]) => record);
    }

    /**
     * Attribute a generation into `data`: O(1) when the client_random offset is known,
     * else the nearest-socket scan. Null when no socket is in reach or it is misaligned.
     */
    locate(data: bigint, knownOffset: number | null = null): Attribution | null {
        const ss = knownOffset === null ? this.nearest(data) : this.atKnownOffset(data, knownOffset);
        if (ss === null) return null;
        const offset = Number(data - ss);
        return offset % 4 === 0 ? { ss, offset } : null;
    }

    /** The nearest tracked sslSocket at or below `data` within the window, or null. */
    nearest(data: bigint): bigint | null {
        let best: bigint | null = null;
        for (const [ss] of this.records.entries()) {
            if (ss <= data && (best === null || ss > best)) best = ss;
        }
        if (best === null || data - best >= ATTRIBUTION_WINDOW_BIG) return null;
        return best;
    }

    /** The tracked socket `data` is the client_random (data-off) or inner random (data-off-32) of. */
    private atKnownOffset(data: bigint, offset: number): bigint | null {
        const clientRandomOwner = data - BigInt(offset);
        if (this.records.has(clientRandomOwner)) return clientRandomOwner;
        const innerRandomOwner = clientRandomOwner - CLIENT_RANDOM_LENGTH_BIG;
        return this.records.has(innerRandomOwner) ? innerRandomOwner : null;
    }
}
