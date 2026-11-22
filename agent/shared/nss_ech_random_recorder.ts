// agent/shared/nss_ech_random_recorder.ts
//
// Tier-2 ECH support for NSS. NSS generates ss->ssl3.hs.client_random (the OUTER random)
// and, with ECH, ss->ssl3.hs.client_inner_random right after it (+32), each with one
// PK11_GenerateRandom(field, 32) call into the sslSocket. When the server accepts ECH,
// NSS copies the inner random over client_random, so the SSL_SecretCallback tier reads
// the INNER random at ss+off. NSS's own keylog then also writes ECH_SECRET so Wireshark
// can map inner -> outer; tier 2 has no ECH_SECRET, so Wireshark (which only sees the
// outer random on the wire) cannot match those lines.
//
// The recorder keeps, per tracked sslSocket, the FIRST random generated at each offset
// (attribution by the store shared with the client_random learner, nss_tracked_sockets.ts).
// At a secret callback with a known client_random offset `off`: if the live bytes at
// ss+off equal the random recorded at off+32 (inner) and a different random was recorded
// at off (outer), ECH was accepted and the line is emitted for both randoms. Otherwise
// only the live random is used. Pure: works on bigint addresses.

import {
    ALL_ZERO_RE, CLIENT_RANDOM_LENGTH, HEX_RANDOM_RE, NssTrackedSockets, type Attribution,
} from "./nss_tracked_sockets.js";

/** Bound on distinct offsets recorded per socket (client_random, inner random, fake session id, ...). */
export const MAX_ECH_OFFSETS_PER_SOCKET = 8;

export class NssEchRandomRecorder {
    constructor(private readonly sockets: NssTrackedSockets = new NssTrackedSockets()) {}

    get trackedSockets(): number { return this.sockets.size; }

    /** A new sslSocket from SSL_ImportFD; a record left at a reused address is reset. */
    trackSocket(ss: bigint): void {
        this.sockets.track(ss);
    }

    forgetSocket(ss: bigint): void {
        this.sockets.forget(ss);
    }

    /** Drop every recorded random (the tracked sockets stay: the learner may still need them). */
    clear(): void {
        for (const record of this.sockets.allRecords()) record.echRandoms.clear();
    }

    /**
     * Record a 32-byte generation into `data` (first random per offset wins, so a
     * HelloRetryRequest or a later RNG call at the same field changes nothing).
     * Returns the socket and offset it was attributed to, or null.
     */
    record(data: bigint, generatedHex: string): Attribution | null {
        const hit = this.sockets.locate(data);
        return hit === null ? null : this.recordAt(hit, generatedHex);
    }

    /** As record(), for a generation the shared store already attributed. All-zero bytes are not a random. */
    recordAt(hit: Attribution, generatedHex: string): Attribution | null {
        if (!HEX_RANDOM_RE.test(generatedHex) || ALL_ZERO_RE.test(generatedHex)) return null;
        const randoms = this.sockets.record(hit.ss)?.echRandoms;
        if (randoms === undefined) return null;
        const attribution = { ss: hit.ss, offset: hit.offset };
        if (randoms.has(hit.offset)) return attribution;
        if (randoms.size >= MAX_ECH_OFFSETS_PER_SOCKET) return null;
        randoms.set(hit.offset, generatedHex);
        return attribution;
    }

    /**
     * The client_randoms to key one secret line of `ss` with, given the client_random
     * offset and the live bytes read there: [inner, outer] when ECH was accepted (live
     * equals the inner random recorded at offset+32, and a different outer random was
     * recorded at offset), else [live]. Never contains duplicates.
     */
    keylogRandoms(ss: bigint, offset: number, liveHex: string): string[] {
        const live = liveHex.toLowerCase();
        const randoms = this.sockets.record(ss)?.echRandoms;
        if (randoms === undefined) return [live];
        const outer = randoms.get(offset);
        const inner = randoms.get(offset + CLIENT_RANDOM_LENGTH);
        if (outer === undefined || inner === undefined || live !== inner || outer === inner) return [live];
        return [inner, outer];
    }
}
