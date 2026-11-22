// agent/quic/shared/quiche_frame_hook_gate.ts
//
// Outcome of the STREAM-frame hook install (installQuicheFrameHooks), readable
// before it settles. The body hooks attach as soon as the symbols resolve and
// read `hooked` per call; only the Readv decision waits for the final value.

export class FrameHookGate {
    private frameHooked = false;
    private readonly outcome: Promise<boolean>;

    constructor(install: Promise<boolean>) {
        this.outcome = install.then((hooked) => {
            this.frameHooked = hooked;
            return hooked;
        });
        // Rethrown by settled(); without this a rejection before that await would be unhandled.
        this.outcome.catch(() => undefined);
    }

    /** True once the frame hooks are live; false while pending, failed or rejected. */
    get hooked(): boolean {
        return this.frameHooked;
    }

    /** The final install outcome (rejects when the install rejected). */
    settled(): Promise<boolean> {
        return this.outcome;
    }
}
