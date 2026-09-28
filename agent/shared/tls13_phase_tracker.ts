// TLS 1.3 handshake- vs application-phase tracking for ncrypt.dll's
// SslExpandTrafficKeys (Windows SSPI / LSASS keylog hooks).
//
// ncrypt calls SslExpandTrafficKeys twice per TLS 1.3 handshake: first for the
// handshake traffic secrets, then for the application traffic secrets. Nothing
// in the call itself distinguishes them, so the phase is inferred from call
// order -- and that order must be counted per HANDSHAKE, not per thread. lsass
// is system-wide and its worker threads are pooled across concurrent (and
// foreign) handshakes, so a thread-keyed "seen" flag left over from another
// handshake flips the two labels (HANDSHAKE_TRAFFIC_SECRET vs
// TRAFFIC_SECRET_0), which prevents Wireshark from decrypting. Keying on
// (thread, client_random) scopes the flag to one handshake. When client_random
// is unknown ("???") the label may still swap; the offline `--repair-keylog`
// pass relabels by trial decryption regardless.
//
// The tracker is bounded: an entry is removed when its handshake reaches the
// application phase, and handshakes that abort after the first expansion (and
// so never get a second call) are evicted oldest-first once `maxTracked` is
// exceeded, keeping memory flat over long-lived LSASS agent sessions.
//
// Pure logic (no Frida APIs) so it is unit-testable under node.

export type Tls13TrafficSecretPhase = "HANDSHAKE_TRAFFIC_SECRET" | "TRAFFIC_SECRET_0";

export const DEFAULT_MAX_TRACKED_HANDSHAKES = 1024;

export class Tls13PhaseTracker {
    // Set iteration order is insertion order, so the first element is the oldest.
    private readonly awaitingAppPhase = new Set<string>();

    constructor(private readonly maxTracked: number = DEFAULT_MAX_TRACKED_HANDSHAKES) {
        if (!(maxTracked >= 1)) {
            throw new RangeError(`maxTracked must be >= 1, got ${maxTracked}`);
        }
    }

    /**
     * Return the phase label for the SslExpandTrafficKeys call happening now for
     * `handshakeKey` (`${threadId}:${clientRandom}`). The first call of a
     * handshake is the handshake phase; the second is the application phase and
     * clears the entry.
     */
    nextPhase(handshakeKey: string): Tls13TrafficSecretPhase {
        if (this.awaitingAppPhase.has(handshakeKey)) {
            this.awaitingAppPhase.delete(handshakeKey);
            return "TRAFFIC_SECRET_0";
        }
        this.awaitingAppPhase.add(handshakeKey);
        this.evictIfNeeded();
        return "HANDSHAKE_TRAFFIC_SECRET";
    }

    /** Number of handshakes currently awaiting their application phase. */
    get size(): number {
        return this.awaitingAppPhase.size;
    }

    private evictIfNeeded(): void {
        while (this.awaitingAppPhase.size > this.maxTracked) {
            const oldest = this.awaitingAppPhase.values().next().value as string | undefined;
            if (oldest === undefined) return;
            this.awaitingAppPhase.delete(oldest);
        }
    }
}

/**
 * Build the per-handshake key used by {@link Tls13PhaseTracker}. Combining the
 * thread id with the client random scopes the phase flag to a single handshake
 * even though ncrypt's worker threads are pooled across concurrent handshakes.
 */
export function makeHandshakeKey(threadId: number, clientRandom: string): string {
    return threadId + ":" + clientRandom;
}
