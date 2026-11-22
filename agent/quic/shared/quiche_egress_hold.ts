// agent/quic/shared/quiche_egress_hold.ts
//
// Egress STREAM chunks held per session while its connection cannot be
// resolved yet. Held chunks must never vanish: a connection that never
// resolves would otherwise lose every request header silently. They are
// released (in order) on resolution, past the per-session or total budget, on
// LRU eviction, after a bounded time, and before shutdown.

import { LruMap } from "../../shared/lru.js";
import { HoldClock, HoldTimer, holdClock } from "./hold_timer.js";

/** Egress chunks held per session before they go out unresolved. */
export const MAX_EGRESS_HELD_CHUNKS = 256;
/** Sessions with held chunks (LRU). */
export const MAX_EGRESS_HELD_SESSIONS = 32;
/** Chunk bytes held over all sessions; past it the oldest session goes out unresolved. */
export const MAX_EGRESS_HELD_BYTES = 1 << 20;
/** Longest a session's first chunk is held before its chunks go out unresolved. */
export const EGRESS_HOLD_TIMEOUT_MS = 3000;
/** Longest a session's first chunk is held while `holdWhile` asks for more time. */
export const MAX_EGRESS_HOLD_MS = 15_000;

/** Why held chunks are released without their connection having resolved. */
export type EgressReleaseReason = "budget" | "evicted" | "timeout" | "shutdown";

/** A released chunk and the ms it was held (the host back-dates it by that). */
export interface HeldChunk<V> { readonly chunk: V; readonly heldMs: number; }

/** Release a session's held chunks, oldest first. */
export type ReleaseEgress<V> = (key: string, held: HeldChunk<V>[], reason: EgressReleaseReason) => void;

export interface EgressHoldOptions<V> {
    maxSessions?: number;
    maxChunks?: number;
    maxBytes?: number;
    /** Bytes a chunk counts against `maxBytes`. */
    sizeOf?: (chunk: V) => number;
    /**
     * True while the session of `chunk` (its first held one) may still resolve: a
     * timeout then keeps holding, up to MAX_EGRESS_HOLD_MS. Released unresolved,
     * its chunks would go out under another key than the session's later ones.
     */
    holdWhile?: (chunk: V) => boolean;
    clock?: HoldClock;
}

interface HeldSession<V> {
    readonly chunks: { chunk: V; heldAt: number }[];
    bytes: number;
    /** When the timeout releases the session (unless `holdWhile` extends it). */
    dueAt: number;
}

export class QuicheEgressHold<V> {
    private readonly sessions: LruMap<string, HeldSession<V>>;
    private readonly timer: HoldTimer;
    private readonly clock: HoldClock;
    private readonly maxChunks: number;
    private readonly maxBytes: number;
    private readonly sizeOf: (chunk: V) => number;
    private readonly holdWhile: (chunk: V) => boolean;
    private bytes = 0;

    constructor(private readonly release: ReleaseEgress<V>, options: EgressHoldOptions<V> = {}) {
        this.clock = options.clock ?? holdClock(EGRESS_HOLD_TIMEOUT_MS);
        this.maxChunks = options.maxChunks ?? MAX_EGRESS_HELD_CHUNKS;
        this.maxBytes = options.maxBytes ?? MAX_EGRESS_HELD_BYTES;
        this.sizeOf = options.sizeOf ?? (() => 0);
        this.holdWhile = options.holdWhile ?? (() => false);
        this.sessions = new LruMap(options.maxSessions ?? MAX_EGRESS_HELD_SESSIONS,
                                   (key, held) => this.releaseSession(key, held, "evicted"));
        this.timer = new HoldTimer(this.clock, () => this.onTimeout(), () => this.releaseAll("shutdown"));
    }

    has(key: string): boolean {
        return this.sessions.has(key);
    }

    get size(): number {
        return this.sessions.size;
    }

    get heldBytes(): number {
        return this.bytes;
    }

    get timerArmed(): boolean {
        return this.timer.armed;
    }

    /** Hold `chunk` for `key`; past a budget chunks go out at once. */
    hold(key: string, chunk: V): void {
        // Peek, and re-insert only new sessions: LRU order must stay oldest-held, not most-written.
        const existing = this.sessions.peek(key);
        const held = existing ?? { chunks: [], bytes: 0, dueAt: this.clock.now() + this.clock.timeoutMs };
        const size = this.sizeOf(chunk);
        held.chunks.push({ chunk, heldAt: this.clock.now() });
        held.bytes += size;
        this.bytes += size;
        if (held.chunks.length > this.maxChunks) {
            this.sessions.delete(key);
            this.releaseSession(key, held, "budget");
        } else {
            if (existing === undefined) this.sessions.set(key, held);
            this.enforceByteBudget();
        }
        this.syncTimer();
    }

    /** Remove and return the session's held chunks (its connection resolved). */
    take(key: string): HeldChunk<V>[] {
        const held = this.sessions.peek(key);
        if (held === undefined) return [];
        this.sessions.delete(key);
        this.bytes -= held.bytes;
        this.syncTimer();
        return this.withHeldMs(held);
    }

    /** Release every held session. */
    releaseAll(reason: EgressReleaseReason): void {
        while (this.releaseOldest(reason)) { /* next */ }
        this.syncTimer();
    }

    /** Oldest sessions first (the LRU order) until the held bytes fit. */
    private enforceByteBudget(): void {
        while (this.bytes > this.maxBytes && this.releaseOldest("budget")) { /* next */ }
    }

    /** Release the oldest-held session (the LRU order: hold() never promotes); false when none is held. */
    private releaseOldest(reason: EgressReleaseReason): boolean {
        const oldest = this.sessions.oldest();
        if (oldest === undefined) return false;
        const [key, held] = oldest;
        this.sessions.delete(key);
        this.releaseSession(key, held, reason);
        return true;
    }

    /** Release a session already removed from `sessions`; one failure must not keep the others held. */
    private releaseSession(key: string, held: HeldSession<V>, reason: EgressReleaseReason): void {
        this.bytes -= held.bytes;
        try {
            this.release(key, this.withHeldMs(held), reason);
        } catch (_e) {
            /* the chunks are gone either way */
        }
    }

    private withHeldMs(held: HeldSession<V>): HeldChunk<V>[] {
        const now = this.clock.now();
        return held.chunks.map(({ chunk, heldAt }) => ({ chunk, heldMs: Math.max(0, now - heldAt) }));
    }

    /** Earliest due time of a held session, or null when nothing is held. */
    private nextDueAt(): number | null {
        let next: number | null = null;
        for (const [, held] of this.sessions.entries()) {
            if (next === null || held.dueAt < next) next = held.dueAt;
        }
        return next;
    }

    /** The timer is due when the first held session is (a new session is never due before an armed timer). */
    private syncTimer(): void {
        const next = this.timer.armed ? null : this.nextDueAt();
        if (this.sessions.size === 0) this.timer.cancel();
        else if (next !== null) this.timer.sync(true, Math.max(0, next - this.clock.now()));
    }

    private onTimeout(): void {
        const now = this.clock.now();
        for (const [key, held] of this.sessions.entries()) {
            if (held.dueAt > now) continue;
            const extendUntil = held.chunks[0].heldAt + MAX_EGRESS_HOLD_MS;
            if (now < extendUntil && this.mayResolve(held)) {
                held.dueAt = Math.min(now + this.clock.timeoutMs, extendUntil);
                continue;
            }
            this.sessions.delete(key);
            this.releaseSession(key, held, "timeout");
        }
        this.syncTimer();
    }

    private mayResolve(held: HeldSession<V>): boolean {
        try {
            return this.holdWhile(held.chunks[0].chunk);
        } catch (_e) {
            return false;
        }
    }
}
