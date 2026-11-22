// agent/quic/shared/quiche_body_queue.ts
//
// De-framed body records held while QuicStream::id_ is still being learned.
// Sent with stream id -1 they could not be matched against the STREAM-frame
// path's per-stream ownership, and the host could only guess their stream.
// Each entry keeps a copy of the stream's id_ candidate window, so once the
// offset is known every held record gets its own real id, in arrival order.

import { HoldClock, HoldTimer, holdClock } from "./hold_timer.js";
import { StreamIdWindow } from "./quiche_stream_id.js";

/** Records held at most (oldest released first, with an unknown stream id). */
export const MAX_PENDING_BODIES = 256;
/** Payload + window bytes held at most. */
export const MAX_PENDING_BODY_BYTES = 1 << 20;
/**
 * Longest a record is held: then everything goes out with an unknown id (the host keeps it apart).
 * Short on purpose: the host stamps a record's time on receipt (corrected by `held_ms`).
 */
export const PENDING_BODY_TIMEOUT_MS = 1500;
/** Longest a record is held while `holdWhile` asks for more time (frame hooks pending or id_ still being learned). */
export const MAX_PENDING_BODY_HOLD_MS = 15_000;

export interface PendingBody<R> {
    readonly record: R;
    readonly data: ArrayBuffer;
    readonly window: StreamIdWindow | null;
    /** False: captured before the STREAM-frame hooks were live (no ownership check at release). */
    readonly frameHooksLive?: boolean;
}

/** Release one held record with its stream id (null: still unknown) and the ms it was held. */
export type ReleaseBody<R> = (entry: PendingBody<R>, streamId: number | null, heldMs: number) => void;

interface HeldBody<R> {
    readonly entry: PendingBody<R>;
    readonly heldAt: number;
}

function sizeOf<R>(entry: PendingBody<R>): number {
    return entry.data.byteLength + (entry.window?.bytes.length ?? 0);
}

export class QuicheBodyQueue<R> {
    private entries: HeldBody<R>[] = [];
    private bytes = 0;
    private readonly timer: HoldTimer;
    /** While true, a timeout keeps holding (up to MAX_PENDING_BODY_HOLD_MS from the oldest record). */
    holdWhile: () => boolean = () => false;

    constructor(private readonly release: ReleaseBody<R>,
                private readonly maxRecords: number = MAX_PENDING_BODIES,
                private readonly maxBytes: number = MAX_PENDING_BODY_BYTES,
                private readonly clock: HoldClock = holdClock(PENDING_BODY_TIMEOUT_MS)) {
        this.timer = new HoldTimer(clock, () => this.onTimeout(), () => this.flushUnattributed());
    }

    get size(): number {
        return this.entries.length;
    }

    get heldBytes(): number {
        return this.bytes;
    }

    get timerArmed(): boolean {
        return this.timer.armed;
    }

    /** Hold `entry`; past the bound the oldest records go out with an unknown id. */
    push(entry: PendingBody<R>): void {
        this.entries.push({ entry, heldAt: this.clock.now() });
        this.bytes += sizeOf(entry);
        while (this.entries.length > 0 && (this.entries.length > this.maxRecords || this.bytes > this.maxBytes)) {
            const oldest = this.entries.shift()!;
            this.bytes -= sizeOf(oldest.entry);
            this.releaseHeld(oldest, null);
        }
        this.timer.sync(this.entries.length > 0);
    }

    /** Release every held record in arrival order, each with the id `idOf` reads from its own window. */
    flush(idOf: (window: StreamIdWindow | null) => number | null): void {
        const held = this.entries;
        this.entries = [];
        this.bytes = 0;
        this.timer.cancel();
        for (const body of held) this.releaseHeld(body, idOf(body.entry.window));
    }

    /** Release every held record with an unknown stream id. */
    flushUnattributed(): void {
        this.flush(() => null);
    }

    /** Give the held records a fresh timeout (the id source just changed, e.g. the frame hooks went live). */
    restartTimer(): void {
        this.timer.restart(this.entries.length > 0);
    }

    private releaseHeld(body: HeldBody<R>, streamId: number | null): void {
        this.release(body.entry, streamId, Math.max(0, this.clock.now() - body.heldAt));
    }

    /** Ms the oldest record may still be held on request of `holdWhile` (0: release now). */
    private extendedHoldMs(): number {
        if (this.entries.length === 0 || !this.holdWhile()) return 0;
        return MAX_PENDING_BODY_HOLD_MS - (this.clock.now() - this.entries[0].heldAt);
    }

    private onTimeout(): void {
        const extra = this.extendedHoldMs();
        if (extra > 0) this.timer.sync(true, Math.min(this.clock.timeoutMs, extra));
        else this.flushUnattributed();
    }
}
