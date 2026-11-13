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
import { devlog } from "../util/log.js";
import { sendCallerStack, CallerStackJoin, CallerFrame } from "./shared_structures.js";
import {
    forgetSslIdentity, isLayoutLocatorSettled, isSslLayoutUsable, peekSslGeneration, readSslClientRandom, sslGeneration,
} from "./ssl_identity.js";
import {
    CallerStackCache, CallerStackCacheDeps, CapturedFrames, joinHasClientRandom, joinHasTuple, recordJoinFields, safeJoin,
} from "./caller_stack_cache.js";

export { CallerStackCache, recordJoinFields } from "./caller_stack_cache.js";

/** Cap per stack so a pathological frame count cannot bloat the message. */
const MAX_FRAMES = 32;

// Legacy per-SSL* dedup set, superseded by the (SSL*, generation) CallerStackCache
// below; kept declared (and still cleared by forgetSsl) for compatibility.
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

/**
 * True only when a Java VM exists AND the current thread is already attached to
 * it (`vm.tryGetEnv()` non-null). A BoringSSL hook often runs on a pure native
 * thread (Chromium's network thread): attaching it from inside the hook (what
 * Java.perform would do) is never allowed.
 */
export function currentThreadHasJavaEnv(bridge: any = Java): boolean {
    try {
        if (typeof bridge === "undefined" || !bridge || !bridge.available || !bridge.vm) return false;
        return bridge.vm.tryGetEnv() != null;
    } catch (_e) {
        return false;
    }
}

/** Top-down Java class-name stack, capped to MAX_FRAMES; empty when no Java VM or
 *  the current thread is not attached to it. Every failure is swallowed so a Java
 *  problem never breaks native capture. `bridge` is injectable for tests. */
export function captureJavaFrames(bridge: any = Java): string[] {
    if (!currentThreadHasJavaEnv(bridge)) return [];
    const out: string[] = [];
    try {
        bridge.perform(() => {
            try {
                const JavaThread = bridge.use("java.lang.Thread");
                const elems = JavaThread.currentThread().getStackTrace();
                for (let i = 0; i < elems.length && out.length < MAX_FRAMES; i++) {
                    try { out.push(elems[i].getClassName()); } catch (_e) { /* skip one frame */ }
                }
            } catch (_e) { /* no usable Java stack */ }
        });
    } catch (_e) { /* Java.perform threw; never break capture */ }
    return out;
}

/** Linux/Android thread name of `tid` from procfs ("" elsewhere or on error). */
export function readProcThreadName(tid: number): string {
    if (Process.platform !== "linux") return "";
    try {
        return File.readAllText(`/proc/self/task/${tid}/comm`).trim();
    } catch (_e) {
        return "";
    }
}

/**
 * A client_random can still arrive for `module` while its layout locator runs, or
 * once its layout is usable. A settled module with no layout, or with one that is
 * not usable (e.g. an unconfirmed stock guess on a one-connection app), cannot
 * produce one, so a held caller_stack falls back to its 5-tuple. A usable layout
 * that still yields nothing is covered by the cache's offer-count fallback.
 */
export function clientRandomMayArrive(module: string): boolean {
    if (!isLayoutLocatorSettled(module)) return true;
    return isSslLayoutUsable(module);
}

const fridaCallerStackDeps: CallerStackCacheDeps = {
    send: (join, javaFrames, nativeFrames, meta) => sendCallerStack(join, javaFrames, nativeFrames, meta),
    capture: (context): CapturedFrames => ({
        native: captureNativeFrames(context as CpuContext),
        java: captureJavaFrames(),
    }),
    now: () => Date.now(),
    currentThreadId: () => Process.getCurrentThreadId(),
    pid: () => Process.id,
    readThreadName: readProcThreadName,
    clientRandomMayArrive,
    onDroppedUnsent: (total, reason, ageMs) =>
        devlog(`[sdk-attribution] dropped an unsent caller_stack (${reason}, held ${ageMs} ms; ${total} total)`),
};

// One entry per (SSL*, generation); inert (empty) while --attribute-sdk is off.
const callerStacks = new CallerStackCache(fridaCallerStackDeps);

export interface CallerStackCaptureOptions {
    /** Module of the hooked TLS function, reported as transport_module and used for the send policy. */
    transportModule?: string;
}

/** The join provider's fields, plus the connection's client_random when it is cheaply known. */
function joinWithClientRandom(ssl: NativePointer, join: () => CallerStackJoin, module: string): CallerStackJoin {
    const fields = safeJoin(join);
    if (!joinHasClientRandom(fields)) {
        try {
            const cr = readSslClientRandom(ssl, module);
            if (cr) fields.client_random = cr;
        } catch (_e) { /* best-effort */ }
    }
    return fields;
}

/**
 * Capture the caller stack for `ssl` once per (SSL*, generation), behind the opt-in flag.
 *
 * Inert when --attribute-sdk is off (first-line return). Call it from the hook's
 * onEnter: the frames are unwound there, once. The `caller_stack` message is sent
 * immediately when the join has a client_random; otherwise it is held and sent by
 * offerCallerStackJoin() when a record of the connection carries one (or a 5-tuple,
 * once no client_random can arrive for the module). Sent at most once.
 *
 * @param ssl      SSL object pointer (dedup key, with its generation).
 * @param context  CpuContext of the hooked thread (the hook's onEnter context),
 *                 used as the backtrace origin.
 * @param join     Lazy provider of the connection-join fields. Invoked only on
 *                 the first capture of a connection, so no SSL state is read when
 *                 the flag is off or the connection was already seen.
 * @param opts     Optional transport module of the hooked function.
 */
export function maybeCaptureCallerStack(
    ssl: NativePointer,
    context: CpuContext,
    join: () => CallerStackJoin,
    opts?: CallerStackCaptureOptions,
): void {
    if (!attribute_sdk) return;
    const module = opts?.transportModule ?? "";
    callerStacks.capture({
        sslKey: ssl.toString(),
        generation: sslGeneration(ssl),
        module,
        context,
        join: () => joinWithClientRandom(ssl, join, module),
    });
}

/**
 * A plaintext record of `ssl` was built: if its connection's caller stack is still
 * held, send it once with the record's OWN client_random and 5-tuple (so the host
 * join keys are byte-identical to the flow's). Inert when --attribute-sdk is off.
 */
export function offerCallerStackJoin(ssl: NativePointer, recordMessage: { [key: string]: any }): void {
    if (!attribute_sdk || !ssl || !callerStacks.hasHeldEntries) return;
    try {
        const sslKey = ssl.toString();
        const generation = sslGeneration(ssl);
        if (!callerStacks.isHeld(sslKey, generation)) return;
        const join = recordJoinFields(recordMessage);
        if (!joinHasClientRandom(join) && !joinHasTuple(join)) return;
        callerStacks.offer(sslKey, generation, join);
    } catch (_e) {
        // best-effort: attribution never breaks a record
    }
}

/**
 * Forget an SSL object (SSL_free): send its held caller_stack if joinable (else
 * drop it) and start a new generation for the address. The generation is PEEKED,
 * never created: under --modern the lifecycle hook's forgetSslIdentity() runs
 * first, and a created generation would miss the freed connection's entry.
 */
export function forgetSsl(key: string): void {
    seenSsl.delete(key);
    try {
        const ssl = ptr(key);
        const generation = peekSslGeneration(ssl);
        if (generation !== null) callerStacks.forget(key, generation);
        forgetSslIdentity(ssl);
    } catch (_e) { /* best-effort */ }
}
