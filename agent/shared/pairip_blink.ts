/**
 * --pairip-safe persistence ("blink"), folded into --pairip-safe (no CLI flag).
 *
 * PairIP runs a PERIODIC code-integrity check that SIGSEGVs the app when it finds
 * inline hooks in a protected lib's .text. The TLS keylog *callback* itself is a
 * heap data-field on the SSL_CTX (NOT a code patch), so it keeps firing even with
 * the inline SSL_new/SSL_CTX_new hooks removed. "Blink" exploits this:
 *   - WARMUP: stay BRIGHT (hooks attached) long enough to tag the app's initial
 *     SSL_CTX/SSL objects reliably (so capture matches keep-hooks at startup),
 *   - then toggle BRIGHT (~0.8s, re-tag any new contexts) / DARK (~12s + jitter,
 *     .text pristine) so a random PairIP scan almost always lands in a DARK window.
 *
 * CRITICAL: the keylog NativeCallback MUST be permanently rooted here, or Frida
 * may GC it after the inline hooks detach — every SSL_CTX still holding its
 * pointer would then call freed memory (a SIGSEGV indistinguishable from PairIP).
 */

import { devlog, log } from "../util/log.js";

/** Master switch (no CLI flag). Flip to false to A/B "keep-hooks" on device. */
export const PAIRIP_BLINK_ENABLED = true;

// Tunable on device (see plan verification step 5). Starting points:
const WARMUP_MS = 25000;   // stay BRIGHT initially to tag startup contexts
const BRIGHT_MS = 800;     // re-tag window
const DARK_MS = 12000;     // pristine window (base)
const JITTER_MS = 4000;    // ± so we can't phase-lock with PairIP's scan

interface BlinkTarget {
    module: string;
    /** (Re-)attach the inline SSL_new/SSL_CTX_new(+observer) hooks; returns the listeners. */
    attach: () => InvocationListener[];
    /** Currently-attached listeners ([] while DARK). */
    listeners: InvocationListener[];
}

// Never cleared — permanent GC roots.
const rootedCallbacks: NativeCallback<any, any>[] = [];
const targets: BlinkTarget[] = [];

let schedulerStarted = false;
let stopped = false;
let timer: any = null;

/**
 * Register a keylog hook set for blink management. Roots `keylogCb`, performs the
 * first BRIGHT attach immediately (so initial capture is unaffected), and starts
 * the global blink scheduler once. Call this ONLY when pairip_safe && blink.
 */
export function registerBlinkTarget(
    module: string,
    keylogCb: NativeCallback<any, any>,
    attach: () => InvocationListener[],
): void {
    rootedCallbacks.push(keylogCb); // <-- the load-bearing GC root
    const t: BlinkTarget = { module, attach, listeners: [] };
    try {
        t.listeners = attach();
    } catch (e) {
        devlog(`[pairip-blink] initial attach for ${module} failed: ${e}`);
    }
    targets.push(t);
    log(`[pairip-blink] armed for ${module} (warmup ${Math.round(WARMUP_MS / 1000)}s, then blink)`);
    ensureScheduler();
}

function brighten(): void {
    for (const t of targets) {
        if (t.listeners.length === 0) {
            try { t.listeners = t.attach(); } catch (e) { devlog(`[pairip-blink] re-attach ${t.module} failed: ${e}`); }
        }
    }
    devlog("[pairip-blink] BRIGHT (re-tagging contexts)");
}

function darken(): void {
    for (const t of targets) {
        for (const l of t.listeners) { try { l.detach(); } catch (e) { /* ignore */ } }
        t.listeners = [];
    }
    devlog("[pairip-blink] DARK (.text pristine)");
}

function nextDarkDelay(): number {
    // Math.random is available in the Frida (qjs) runtime.
    return DARK_MS + Math.floor(Math.random() * JITTER_MS);
}

function scheduleDarken(delay: number): void {
    if (stopped) return;
    timer = setTimeout(() => { darken(); scheduleBrighten(); }, delay);
}

function scheduleBrighten(): void {
    if (stopped) return;
    timer = setTimeout(() => { brighten(); scheduleDarken(BRIGHT_MS); }, nextDarkDelay());
}

function ensureScheduler(): void {
    if (schedulerStarted) return;
    schedulerStarted = true;
    // Warmup BRIGHT first (already attached in register), then begin blinking.
    scheduleDarken(WARMUP_MS);
}

/** Stop blinking (called from gracefulDetach before Interceptor.detachAll). */
export function stopBlink(): void {
    stopped = true;
    if (timer) { try { clearTimeout(timer); } catch (e) { /* ignore */ } timer = null; }
}
