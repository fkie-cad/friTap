// agent/shared/nss_client_random_learner.ts
//
// Tier-2 client_random source for NSS builds where the keylog writer was not located
// (tier 1) and the version table is unverified (tier 3, NSS >= 3.115).
//
// NSS fills ss->ssl3.hs.client_random (and, with ECH, client_inner_random right after
// it) with ONE PK11_GenerateRandom(field, 32) call written straight into the sslSocket.
// A read-only hook on that export sees the destination address; the offset from the
// sslSocket returned by SSL_ImportFD is the client_random offset. Acceptance rule
// (R2, replayed over two real Fenix runs, 315/315 keylog lines):
//   * a 32-byte SECSuccess generation is attributed to the NEAREST tracked sslSocket at
//     or below the destination, offset < 0x4000 and 4-aligned, and only if the 32 bytes
//     after it are still all zero (a server_random next to a client_random is not);
//   * per socket, at its first secret callback: candidate = smallest attributed offset;
//     valid iff the live bytes at ss+candidate equal a random recorded at candidate or
//     candidate+32 (ECH: the inner random is copied over client_random);
//   * the offset is accepted globally once >= 3 valid sockets at distinct addresses
//     agree and none disagree; a disagreement means it is never accepted (fail closed).
// The tracked sockets and the attribution live in nss_tracked_sockets.ts (shared with the
// ECH recorder). The pure core works on bigint addresses; the Frida glue at the bottom only reads.

import { copyPointer, isReadable, untag } from "../util/safe_memory.js";
import { toHexString } from "../util/hex.js";
import {
    ALL_ZERO_RE, ATTRIBUTION_WINDOW, CLIENT_RANDOM_LENGTH, HEX_RANDOM_RE, NssTrackedSockets, type Attribution,
} from "./nss_tracked_sockets.js";

export { ATTRIBUTION_WINDOW, CLIENT_RANDOM_LENGTH };

/** Learned-cache layout item holding the accepted offset (keyed per module build like every item). */
export const LEARNED_NSS_CLIENT_RANDOM_OFF = "nss.client_random_off";
export const ACCEPTANCE_QUORUM = 3;
/** Bound on randoms kept per offset of one socket. */
const MAX_RANDOMS_PER_OFFSET = 4;

/** 32 bytes at ss+offset as lower-case hex, or null when unreadable. */
export type ClientRandomReader = (offset: number) => string | null;

export interface LearnerEvents {
    onAccepted?: (offset: number, sockets: number) => void;
    onDisagreement?: (offsets: number[]) => void;
}

/** True for an offset a learned or cached entry may carry: inside the window and 4-aligned. */
export function isPlausibleClientRandomOffset(offset: unknown): offset is number {
    return typeof offset === "number" && Number.isInteger(offset)
        && offset > 0 && offset < ATTRIBUTION_WINDOW && offset % 4 === 0;
}

export class NssClientRandomLearner {
    /** sslSocket address -> offset it validated at (distinct addresses vote once). */
    private readonly votes = new Map<bigint, number>();
    private readonly votedOffsets = new Set<number>();
    private accepted: number | null = null;
    private disagreement = false;
    mismatches = 0;

    constructor(private readonly events: LearnerEvents = {},
                private readonly quorum: number = ACCEPTANCE_QUORUM,
                private readonly sockets: NssTrackedSockets = new NssTrackedSockets()) {}

    get acceptedOffset(): number | null { return this.accepted; }
    get disagreed(): boolean { return this.disagreement; }
    /** True once the learner has nothing left to learn (accepted, or failed closed). */
    get settled(): boolean { return this.accepted !== null || this.disagreement; }
    get trackedSockets(): number { return this.sockets.size; }

    /** A new sslSocket from SSL_ImportFD; a record left at a reused address is reset. */
    trackSocket(ss: bigint): void {
        this.sockets.track(ss);
    }

    forgetSocket(ss: bigint): void {
        this.sockets.forget(ss);
    }

    /**
     * Record a 32-byte generation into `data`. Returns the socket and offset it was
     * attributed to, or null (no socket in reach, misaligned, or bytes follow it).
     */
    attribute(data: bigint, generatedHex: string, followingZero: boolean): Attribution | null {
        if (this.settled) return null;
        const hit = this.sockets.locate(data);
        return hit === null ? null : this.attributeAt(hit, generatedHex, followingZero);
    }

    /** As attribute(), for a generation the shared store already attributed. */
    attributeAt(hit: Attribution, generatedHex: string, followingZero: boolean): Attribution | null {
        if (this.settled || !followingZero || !HEX_RANDOM_RE.test(generatedHex)) return null;
        const randoms = this.sockets.record(hit.ss)?.learnerRandoms;
        if (randoms === undefined) return null;
        const atOffset = randoms.get(hit.offset) ?? [];
        if (atOffset.length < MAX_RANDOMS_PER_OFFSET) atOffset.push(generatedHex);
        randoms.set(hit.offset, atOffset);
        return { ss: hit.ss, offset: hit.offset };
    }

    /** Offset this socket already validated at, or null (undecided, invalid, or failed closed). */
    validatedOffset(ss: bigint): number | null {
        if (this.disagreement) return null;
        const verdict = this.sockets.record(ss)?.verdict;
        return typeof verdict === "number" ? verdict : null;
    }

    /**
     * Validate a socket at its secret callback (sticky once decided). Returns the offset
     * to read its client_random at, or null: untracked, nothing attributed, not yet
     * written, mismatch, or the learner failed closed.
     */
    validateSocket(ss: bigint, read: ClientRandomReader): number | null {
        if (this.disagreement) return null;
        const record = this.sockets.record(ss);
        if (record === undefined) return null;
        if (record.verdict !== undefined) return record.verdict === "invalid" ? null : record.verdict;
        const randoms = record.learnerRandoms;
        if (randoms.size === 0) return null;
        const candidate = Math.min(...randoms.keys());
        const live = read(candidate);
        if (live === null || ALL_ZERO_RE.test(live)) return null;
        const recorded = [...(randoms.get(candidate) ?? []), ...(randoms.get(candidate + CLIENT_RANDOM_LENGTH) ?? [])];
        if (!recorded.includes(live.toLowerCase())) {
            record.verdict = "invalid";
            this.mismatches++;
            return null;
        }
        record.verdict = candidate;
        this.vote(ss, candidate);
        return this.disagreement ? null : candidate;
    }

    private vote(ss: bigint, offset: number): void {
        if (this.settled) return;
        this.votes.set(ss, offset);
        this.votedOffsets.add(offset);
        if (this.votedOffsets.size > 1) {
            this.disagreement = true;
            this.events.onDisagreement?.([...this.votedOffsets].sort((a, b) => a - b));
            return;
        }
        if (this.votes.size >= this.quorum) {
            this.accepted = offset;
            this.events.onAccepted?.(offset, this.votes.size);
        }
    }
}

// ---- Frida glue (read-only) ---------------------------------------------------

/** Untagged address of a pointer as bigint (Android heap pointers carry a top-byte tag). */
export function addressOf(p: NativePointer): bigint {
    return BigInt(untag(p).toString());
}

/** 32 bytes at `at` as lower-case hex, or null when unreadable. Never throws. */
export function readClientRandomHex(at: NativePointer): string | null {
    try {
        if (!isReadable(at, CLIENT_RANDOM_LENGTH)) return null;
        const bytes = at.readByteArray(CLIENT_RANDOM_LENGTH);
        return bytes === null ? null : toHexString(bytes);
    } catch (_e) {
        return null;
    }
}

/**
 * Read-only hook on PK11_GenerateRandom(unsigned char *data, int len): every 32-byte call
 * that returns SECSuccess (0) hands its destination to `onGenerated` (a copied pointer).
 * `onGenerated` must not throw into NSS; failures are swallowed here as a last line.
 */
export function attachGeneratedRandomObserver(generateRandom: NativePointer,
                                              onGenerated: (data: NativePointer) => void): InvocationListener {
    return Interceptor.attach(generateRandom, {
        onEnter(args: InvocationArguments) {
            this.data = args[1].toInt32() === CLIENT_RANDOM_LENGTH ? copyPointer(args[0]) : null;
        },
        onLeave(retval: InvocationReturnValue) {
            if (!this.data || retval.toInt32() !== 0) return;
            try {
                onGenerated(this.data);
            } catch (_e) { /* an observer failure must never reach NSS */ }
        },
    });
}
