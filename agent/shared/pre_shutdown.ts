/**
 * Pre-shutdown flush registry.
 *
 * `releaseAgentHooks()` sets the shutdown flag first, after which every send is
 * dropped. Data an agent module still holds (e.g. QUIC bodies waiting for their
 * stream id) must go out before that: `runPreShutdownFlushes()` runs first.
 */

import { makeHookRegistry } from "./hook_registry.js";

const flushes = makeHookRegistry({ reverse: false });

/** Register a flush to run on detach, before the shutdown flag is set. */
export function registerPreShutdownFlush(fn: () => void): void {
    flushes.register(fn);
}

/** Run every registered flush in registration order, isolating failures; idempotent; never throws. */
export function runPreShutdownFlushes(): void {
    flushes.run();
}
