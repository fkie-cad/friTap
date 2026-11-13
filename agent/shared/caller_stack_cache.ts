// agent/shared/caller_stack_cache.ts
//
// Pure (Node-testable) core of the opt-in SDK/caller attribution (design P1 B5).
// Every Frida dependency (frame capture, send, clock, thread id/name, pid, the
// "can a client_random still arrive?" question) is injected, so this module has
// no Frida globals and no agent imports beyond the LRU helper.
//
// One entry per (SSL*, generation): the frames are unwound ONCE, at the first
// plaintext hook of the connection, and never again. Sending is decoupled from
// capturing: an entry whose join has no client_random is HELD until a record of
// the same connection offers a client_random (offer()), or -- with a 5-tuple
// known -- until no client_random can ever arrive for its module, or until
// TUPLE_FALLBACK_AFTER_OFFERS records offered no client_random, or until SSL_free
// (forget(): sent then if it has any usable join, dropped otherwise). Each entry is
// sent at most once (a client_random arriving later sends nothing more: the
// host joins by tuple then).

import { LruMap } from "./lru.js";
import type { CallerFrame, CallerStackJoin, CallerStackMeta } from "./shared_structures.js";

/** Max held/sent (SSL*, generation) entries. */
export const CALLER_STACK_CACHE_MAX = 1024;
/**
 * A held entry with a 5-tuple is sent tuple-only after this many records of its
 * connection offered no client_random (a layout that looked usable never yielded one).
 */
export const TUPLE_FALLBACK_AFTER_OFFERS = 8;
/** Max cached thread names (tid -> comm). */
export const THREAD_NAME_CACHE_MAX = 256;

/** The record/join fields copied from a record message into the caller_stack join. */
const RECORD_JOIN_FIELDS = ["ssl_session_id", "src_addr", "dst_addr", "src_port", "dst_port", "ss_family"] as const;

export interface CapturedFrames {
    native: CallerFrame[];
    java: string[];
}

export interface CallerStackCacheDeps {
    send(join: CallerStackJoin, javaFrames: string[], nativeFrames: CallerFrame[], meta: CallerStackMeta): void;
    /** Unwind the calling thread from the hook's (opaque) context. */
    capture(context: unknown): CapturedFrames;
    now(): number;
    currentThreadId(): number;
    pid(): number;
    /** Raw thread name of `tid` ("" when unknown); cached by the cache. */
    readThreadName(tid: number): string;
    /** False once no client_random can ever be learned for this module's SSL objects. */
    clientRandomMayArrive(module: string): boolean;
    /** Told about every held entry dropped without being sent (LRU eviction, or SSL_free with no usable join). */
    onDroppedUnsent?(droppedTotal: number, reason: string, ageMs: number): void;
}

export interface CallerStackCaptureRequest {
    sslKey: string;
    generation: number;
    /** The hooked transport module (e.g. "libwebviewchromium.so"), "" when unknown. */
    module: string;
    context: unknown;
    /** Lazy join fields: only invoked on the first capture of (sslKey, generation). */
    join: () => CallerStackJoin;
}

interface CallerStackEntry {
    module: string;
    join: CallerStackJoin;
    frames: CapturedFrames;
    meta: CallerStackMeta;
    capturedAtMs: number;
    sent: boolean;
    /** Records of this connection that offered a join without a client_random. */
    offersWithoutClientRandom: number;
}

export function callerStackKey(sslKey: string, generation: number): string {
    return `${sslKey}#${generation}`;
}

export function joinHasClientRandom(join: CallerStackJoin): boolean {
    return typeof join.client_random === "string" && join.client_random.length > 0;
}

export function joinHasTuple(join: CallerStackJoin): boolean {
    return typeof join.dst_port === "number" && join.dst_port > 0;
}

/** The join fields a record message carries (only those present; "" client_random skipped). */
export function recordJoinFields(record: { [key: string]: any }): CallerStackJoin {
    const join: { [key: string]: any } = {};
    for (const field of RECORD_JOIN_FIELDS) {
        if (record[field] !== undefined) join[field] = record[field];
    }
    if (record["client_random"]) join["client_random"] = record["client_random"];
    return join as CallerStackJoin;
}

export class CallerStackCache {
    private readonly entries: LruMap<string, CallerStackEntry>;
    private readonly threadNames = new LruMap<number, string>(THREAD_NAME_CACHE_MAX);
    private droppedUnsent = 0;
    /** Entries captured but not sent yet (lets callers skip per-record work when zero). */
    private heldCount = 0;

    constructor(private readonly deps: CallerStackCacheDeps, capacity: number = CALLER_STACK_CACHE_MAX) {
        this.entries = new LruMap(capacity, (_key, entry) => this.noteDropped(entry, "evicted"));
    }

    /** Capture (once per sslKey+generation) and send when the policy allows. True when newly captured. */
    capture(request: CallerStackCaptureRequest): boolean {
        const key = callerStackKey(request.sslKey, request.generation);
        if (this.entries.get(key) !== undefined) return false;
        const entry = this.newEntry(request);
        this.entries.set(key, entry);
        this.heldCount++;
        this.sendIfAllowed(entry, entry.join);
        return true;
    }

    /** A record of (sslKey, generation) carries join fields: send a held entry with them. True when sent. */
    offer(sslKey: string, generation: number, recordJoin: CallerStackJoin): boolean {
        const entry = this.entries.get(callerStackKey(sslKey, generation));
        if (entry === undefined || entry.sent) return false;
        const join = { ...entry.join, ...recordJoin };
        if (!joinHasClientRandom(join)) entry.offersWithoutClientRandom++;
        // Remember the richest join seen, so SSL_free can still send it (forget()).
        entry.join = join;
        return this.sendIfAllowed(entry, join);
    }

    /**
     * SSL_free: remove the entry of (sslKey, generation). A held entry whose join
     * is usable (client_random or 5-tuple) is sent first -- no later record can
     * improve it -- and only one with nothing joinable is counted as dropped.
     */
    forget(sslKey: string, generation: number): void {
        const key = callerStackKey(sslKey, generation);
        const entry = this.entries.get(key);
        if (entry === undefined) return;
        this.sendIfJoinable(entry);
        this.entries.delete(key);
        this.noteDropped(entry, "forgotten");
    }

    /** True when any captured entry is still waiting to be sent. */
    get hasHeldEntries(): boolean {
        return this.heldCount > 0;
    }

    /** True when (sslKey, generation) has a captured entry that was not sent yet. */
    isHeld(sslKey: string, generation: number): boolean {
        const entry = this.entries.get(callerStackKey(sslKey, generation));
        return entry !== undefined && !entry.sent;
    }

    get size(): number {
        return this.entries.size;
    }

    get droppedUnsentCount(): number {
        return this.droppedUnsent;
    }

    /**
     * Send policy: a client_random always; a 5-tuple once no client_random can
     * arrive, or after TUPLE_FALLBACK_AFTER_OFFERS cr-less offers.
     */
    shouldSend(join: CallerStackJoin, module: string, offersWithoutClientRandom: number = 0): boolean {
        if (joinHasClientRandom(join)) return true;
        if (!joinHasTuple(join)) return false;
        return offersWithoutClientRandom >= TUPLE_FALLBACK_AFTER_OFFERS || !this.deps.clientRandomMayArrive(module);
    }

    private newEntry(request: CallerStackCaptureRequest): CallerStackEntry {
        const tid = this.deps.currentThreadId();
        return {
            module: request.module,
            join: safeJoin(request.join),
            frames: this.deps.capture(request.context),
            meta: { tid, thread_name: this.threadName(tid), pid: this.deps.pid(), transport_module: request.module },
            capturedAtMs: this.deps.now(),
            sent: false,
            offersWithoutClientRandom: 0,
        };
    }

    private sendIfAllowed(entry: CallerStackEntry, join: CallerStackJoin): boolean {
        if (!this.shouldSend(join, entry.module, entry.offersWithoutClientRandom)) return false;
        this.send(entry, join);
        return true;
    }

    /** Send a held entry now if its join can be joined at all (forget-time: no policy wait). */
    private sendIfJoinable(entry: CallerStackEntry): void {
        if (entry.sent) return;
        if (!joinHasClientRandom(entry.join) && !joinHasTuple(entry.join)) return;
        this.send(entry, entry.join);
    }

    /** The one place an entry is sent: marks it sent (at most once) and releases its held slot. */
    private send(entry: CallerStackEntry, join: CallerStackJoin): void {
        entry.sent = true;
        this.heldCount--;
        this.deps.send(join, entry.frames.java, entry.frames.native, entry.meta);
    }

    private threadName(tid: number): string {
        const cached = this.threadNames.get(tid);
        if (cached !== undefined) return cached;
        let name = "";
        try { name = (this.deps.readThreadName(tid) || "").trim(); } catch (_e) { name = ""; }
        this.threadNames.set(tid, name);
        return name;
    }

    private noteDropped(entry: CallerStackEntry, reason: string): void {
        if (entry.sent) return;
        this.heldCount--;
        this.droppedUnsent++;
        this.deps.onDroppedUnsent?.(this.droppedUnsent, reason, this.deps.now() - entry.capturedAtMs);
    }
}

/** Invoke a join provider; a throwing or empty provider yields an empty join. */
export function safeJoin(join: () => CallerStackJoin): CallerStackJoin {
    try {
        return join() ?? {};
    } catch (_e) {
        return {};
    }
}
