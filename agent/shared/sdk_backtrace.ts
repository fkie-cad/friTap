// agent/shared/sdk_backtrace.ts
//
// SDK / caller attribution (Phase 3b; OPT-IN, OFF by default).
//
// When --attribute-sdk is set, capture the calling thread's backtrace ONCE per
// connection (per SSL object) at the first TLS plaintext hook and emit it as an
// additive `caller_stack` message, so the host can attribute decrypted traffic
// to the SDK / app code that produced it.
//
// The module is inert when the flag is off: maybeCaptureCallerStack() returns on
// its first line, and every TLS hook site additionally guards the call with
// `if (attribute_sdk)`, so when off the only runtime effect on the hot path is a
// single boolean read — no SSL state is touched, no backtrace is taken, no Java
// VM is entered and no message is sent. The join fields are supplied LAZILY (a
// provider invoked only on the first capture of each connection), so even when
// on, nothing is recomputed for already-seen connections.

import { attribute_sdk } from "../fritap_agent.js";
import { Java } from "./javalib.js";
import { sendCallerStack, CallerStackJoin, CallerFrame } from "./shared_structures.js";

/** Cap per stack so a pathological frame count cannot bloat the message. */
const MAX_FRAMES = 32;

// One capture per SSL object. Keyed by the SSL pointer string so every record of
// a connection after the first is skipped. Evicted on SSL_free via forgetSsl()
// (called from the SSL_free scope hook in socket_fd_tracker.ts) so a reused
// pointer is attributed again. Stays empty while --attribute-sdk is off.
const seenSsl = new Set<string>();

/**
 * Symbolize native backtrace addresses into CallerFrame rows, capped to `max`.
 * Exported for unit testing; a failed symbolization still yields the raw address.
 */
export function symbolizeNativeFrames(addrs: NativePointer[], max: number = MAX_FRAMES): CallerFrame[] {
    const frames: CallerFrame[] = [];
    for (const addr of addrs.slice(0, max)) {
        try {
            const sym = DebugSymbol.fromAddress(addr);
            frames.push({
                module: sym.moduleName || "",
                symbol: sym.name || null,
                address: addr.toString(),
            });
        } catch (_e) {
            frames.push({ module: "", symbol: null, address: addr.toString() });
        }
    }
    return frames;
}

/** Native backtrace from `context` (ACCURATE, FUZZY on throw), symbolized. */
function captureNativeFrames(context: CpuContext): CallerFrame[] {
    let addrs: NativePointer[];
    try {
        addrs = Thread.backtrace(context, Backtracer.ACCURATE);
    } catch (_e) {
        try {
            addrs = Thread.backtrace(context, Backtracer.FUZZY);
        } catch (_e2) {
            return [];
        }
    }
    return symbolizeNativeFrames(addrs);
}

/** Top-down Java class-name stack, capped to MAX_FRAMES; empty when no Java VM.
 *  Every failure is swallowed so a Java problem never breaks native capture. */
function captureJavaFrames(): string[] {
    if (typeof Java === "undefined" || !Java.available) return [];
    const out: string[] = [];
    try {
        Java.perform(() => {
            try {
                const JavaThread = Java.use("java.lang.Thread");
                const elems = JavaThread.currentThread().getStackTrace();
                for (let i = 0; i < elems.length && out.length < MAX_FRAMES; i++) {
                    try { out.push(elems[i].getClassName()); } catch (_e) { /* skip one frame */ }
                }
            } catch (_e) { /* no usable Java stack */ }
        });
    } catch (_e) { /* Java.perform threw; never break capture */ }
    return out;
}

/**
 * Capture the caller stack for `ssl` once, behind the opt-in flag.
 *
 * Inert when --attribute-sdk is off (first-line return). On the first plaintext
 * record of each connection it emits ONE additive `caller_stack` message; later
 * records of the same SSL object are skipped (dedup by pointer).
 *
 * @param ssl      SSL object pointer (dedup key).
 * @param context  CpuContext of the hooked thread (the hook's onEnter context),
 *                 used as the backtrace origin.
 * @param join     Lazy provider of the connection-join fields. Invoked only on
 *                 the first capture of a connection, so no SSL state is read when
 *                 the flag is off or the connection was already seen.
 */
export function maybeCaptureCallerStack(
    ssl: NativePointer,
    context: CpuContext,
    join: () => CallerStackJoin,
): void {
    if (!attribute_sdk) return;
    const key = ssl.toString();
    if (seenSsl.has(key)) return;
    seenSsl.add(key);

    let joinFields: CallerStackJoin;
    try {
        joinFields = join();
    } catch (_e) {
        joinFields = {};
    }
    const nativeFrames = captureNativeFrames(context);
    const javaFrames = captureJavaFrames();
    sendCallerStack(joinFields, javaFrames, nativeFrames);
}

/** Forget an SSL object (SSL_free) so a reused pointer is attributed again. */
export function forgetSsl(key: string): void {
    seenSsl.delete(key);
}
