// agent/quic/shared/hold_timer.ts
//
// Timer of a QUIC holding queue (held bodies, held egress chunks): one timer
// per holding period, not per held item; a timeout that never throws into the
// target and releases nothing once shutdown started; and a pre-shutdown flush,
// so held data still goes out on detach while sends work.

import { _isShuttingDownNow } from "../../util/log.js";
import { registerPreShutdownFlush } from "../../shared/pre_shutdown.js";

/** Timeout, clock and shutdown hooks (injectable for tests). */
export interface HoldClock {
    timeoutMs: number;
    now: () => number;
    schedule: (fn: () => void, ms: number) => unknown;
    cancel: (handle: unknown) => void;
    isShuttingDown: () => boolean;
}

/** The real clock with a hold timeout of `timeoutMs`. */
export function holdClock(timeoutMs: number): HoldClock {
    return {
        timeoutMs,
        now: () => Date.now(),
        schedule: (fn, ms) => {
            const handle: any = setTimeout(fn, ms);
            handle?.unref?.();      // Node test runs only; Frida returns a plain id
            return handle;
        },
        cancel: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>),
        isShuttingDown: _isShuttingDownNow,
    };
}

export class HoldTimer {
    private handle: unknown = null;

    /**
     * `onDue` runs when the timer fires (not during shutdown); `onPreShutdown`
     * must release everything held and be a no-op when nothing is.
     */
    constructor(private readonly clock: HoldClock,
                private readonly onDue: () => void,
                onPreShutdown: () => void) {
        registerPreShutdownFlush(onPreShutdown);
    }

    get armed(): boolean {
        return this.handle !== null;
    }

    /** While `holding`, arm (after `delayMs`) unless armed; once nothing is held, cancel. */
    sync(holding: boolean, delayMs: number = this.clock.timeoutMs): void {
        if (!holding) {
            this.cancel();
            return;
        }
        if (this.handle === null) this.handle = this.clock.schedule(() => this.fire(), delayMs);
    }

    /** Re-arm from now (e.g. the held items' release condition just changed). */
    restart(holding: boolean, delayMs?: number): void {
        this.cancel();
        this.sync(holding, delayMs);
    }

    /** Disarm: nothing is held any more. */
    cancel(): void {
        if (this.handle !== null) this.clock.cancel(this.handle);
        this.handle = null;
    }

    private fire(): void {
        this.handle = null;
        try {
            if (this.clock.isShuttingDown()) return;
            this.onDue();
        } catch (_e) {
            /* a timer callback must never throw into the target */
        }
    }
}
