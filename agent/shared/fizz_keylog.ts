// agent/shared/fizz_keylog.ts
//
// Read-only Fizz key extraction on top of fizz_locator.ts:
//
//   F2 (always, when located): hook KeyDerivationImpl::deriveSecret and
//      HandshakeContextImpl::appendToTranscript. appendToTranscript records each
//      handshake's messages per HandshakeContext; deriveSecret yields (label,
//      messageHash, secret). The client_random is bound EXACTLY: the messageHash
//      of every TLS 1.3 secret is Hash(transcript prefix), so the context whose
//      message-prefix hash (SHA-256 or SHA-384 by hash length) equals it owns the
//      secret, and its ClientHello random is the client_random. Covers TLS and
//      mvfst QUIC alike. Only when no prefix matches (transcript caps exceeded)
//      the binding of the same deriver+thread from an earlier exact match in the
//      same handshake is carried (the live-proven rule; reset at every
//      "c e traffic"/"c hs traffic"). Otherwise the secret stays pending (never
//      guessed) and is retried as more transcript arrives.
//   F1 (optional fast path): Meta's own keylog probe export
//      fizz_probe_secret_available(data, u8 size, label enum, client_random);
//      TCP only. Lines identical to F2's are deduplicated.
//
// FizzHandshakeBinder is the pure core (no Frida: hashing is injected), so the
// binding rules are unit-tested with synthetic TLS messages (fizz_keylog.test.ts).
// The hooks never write target memory.

import { log, devlog, devlog_debug } from "../util/log.js";
import { toHexString } from "../util/hex.js";
import { isReadable, resetReadableCache, safeReadPointer } from "../util/safe_memory.js";
import { sendKeylog } from "./shared_structures.js";
import { registerDetachTeardown } from "./detach_teardown.js";
import { rejectLearnedFunction } from "./learned_module_cache.js";
import { moduleOffsetLabel } from "./arm64_xref.js";
import { findModuleExport } from "./module_exports.js";
import { LabelSelfCheck } from "./keylog_guards.js";
import { FifoSet, LruMap } from "./lru.js";
import { MAX_SECRET_LEN } from "./call_abi.js";
import { LEARNED_FIZZ_DERIVE_SECRET, type FizzLocated } from "./fizz_locator.js";

// ---- labels ----------------------------------------------------------------------

/** deriveSecret labels that produce an NSS keylog line. */
export const FIZZ_NSS_LABELS: Readonly<Record<string, string>> = {
    "c e traffic": "CLIENT_EARLY_TRAFFIC_SECRET",
    "e exp master": "EARLY_EXPORTER_SECRET",
    "c hs traffic": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "s hs traffic": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "c ap traffic": "CLIENT_TRAFFIC_SECRET_0",
    "s ap traffic": "SERVER_TRAFFIC_SECRET_0",
    "exp master": "EXPORTER_SECRET",
};
/** Other TLS 1.3 labels deriveSecret legitimately sees: known (self-check), never logged. */
export const FIZZ_SKIPPED_LABELS: readonly string[] = [
    "derived", "ext binder", "res binder", "res master", "traffic upd",
];
/** Starts of a handshake phase: the carried binding is reset here (exact match or nothing). */
const PHASE_START_LABELS = new Set(["c e traffic", "c hs traffic"]);
/**
 * Secrets after which a handshake's transcript chunks are no longer needed: every
 * later logged secret hashes the same, already indexed, prefix.
 */
const FINAL_SECRET_NSS_LABELS = new Set(["SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"]);
/** fizz::KeyLogWriter::Label values passed to fizz_probe_secret_available. */
export const FIZZ_PROBE_LABELS: Readonly<Record<number, string>> = {
    2: "CLIENT_EARLY_TRAFFIC_SECRET", 3: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 4: "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    5: "CLIENT_TRAFFIC_SECRET_0", 6: "SERVER_TRAFFIC_SECRET_0", 7: "EARLY_EXPORTER_SECRET", 8: "EXPORTER_SECRET",
};
export const FIZZ_PROBE_EXPORT = "fizz_probe_secret_available";

export function isKnownFizzLabel(label: string | null): boolean {
    return label !== null && (label in FIZZ_NSS_LABELS || FIZZ_SKIPPED_LABELS.includes(label));
}

/**
 * Consecutive unknown labels before the deriveSecret hook is judged wrong and
 * removed. Higher than NSS's 4: an app's own exporter labels also reach deriveSecret.
 */
export const FIZZ_LABEL_MISMATCH_LIMIT = 8;

/** The deriveSecret hook's label self-check: known Fizz labels, FIZZ_LABEL_MISMATCH_LIMIT. */
export function newFizzLabelSelfCheck(): LabelSelfCheck {
    return new LabelSelfCheck(isKnownFizzLabel, FIZZ_LABEL_MISMATCH_LIMIT);
}

// ---- binder (pure) ---------------------------------------------------------------

export type FizzHashAlg = "sha256" | "sha384";
/** Lowercase hex digest of the concatenated chunks. */
export type FizzHasher = (alg: FizzHashAlg, chunks: Uint8Array[]) => string;

export const TLS_CLIENT_HELLO = 1;
/** RFC 8446 message_hash: the synthetic first message of the transcript after a HelloRetryRequest. */
export const TLS_MESSAGE_HASH = 254;
/** Bytes the binder needs of an append it will not store: type + declared length. */
export const HANDSHAKE_HEADER_LEN = 4;
const CLIENT_RANDOM_AT = HANDSHAKE_HEADER_LEN + 2;
const CLIENT_RANDOM_LEN = 32;

export const MAX_CONTEXTS = 64;
export const MAX_CHUNKS_PER_CONTEXT = 16;
export const MAX_CONTEXT_BYTES = 256 * 1024;
export const MAX_PENDING_SECRETS = 16;
export const MAX_DEDUPE_LINES = 4096;

interface TranscriptContext {
    clientRandom: string | null;
    hrr: boolean;
    chunks: Uint8Array[];
    bytes: number;
    /** Bytes still owed to the last handshake message (it was appended in parts, e.g. a PSK ClientHello). */
    owed: number;
    /** No further chunks are stored (caps exceeded, or released after the final secret). */
    full: boolean;
    /** Chunk counts at which a handshake message was complete: the only prefixes ever hashed. */
    boundaries: number[];
    /** Per algorithm: how many boundaries are already in the prefix-hash index. */
    hashed: Record<FizzHashAlg, number>;
    /** Index keys this context contributed (removed when it is evicted or replaced). */
    indexKeys: string[];
}

export interface FizzSecretEvent {
    /** Identity of the KeyDerivation object (`this`). */
    deriver: string;
    threadId: number;
    label: string;
    messageHash: Uint8Array | null;
    secret: Uint8Array;
}

interface PendingSecret { nss: string; hashHex: string; alg: FizzHashAlg; secretHex: string; }

export interface FizzBinderSummary {
    [key: string]: number;
    /** Transcript contexts started (one per ClientHello, or per HRR message_hash). */
    contexts: number;
    /** Distinct client randoms that got at least one keylog line. */
    handshakes: number;
    bound: number;
    unbound: number;
    lines: number;
    f1: number;
}

/** The client_random a transcript-prefix hash binds to, and every context holding that prefix. */
interface ExactBinding { clientRandom: string; owners: Set<TranscriptContext>; }

function hashAlgFor(length: number): FizzHashAlg | null {
    return length === 32 ? "sha256" : length === 48 ? "sha384" : null;
}

/** Declared size (header + body) of the handshake message starting `chunk`, or 0 when too short. */
function declaredMessageSize(chunk: Uint8Array): number {
    if (chunk.length < HANDSHAKE_HEADER_LEN) return 0;
    return HANDSHAKE_HEADER_LEN + ((chunk[1] << 16) | (chunk[2] << 8) | chunk[3]);
}

function clientRandomOf(clientHello: Uint8Array): string | null {
    if (clientHello.length < CLIENT_RANDOM_AT + CLIENT_RANDOM_LEN) return null;
    return toHexString(clientHello.subarray(CLIENT_RANDOM_AT, CLIENT_RANDOM_AT + CLIENT_RANDOM_LEN));
}

function prefixIndexKey(alg: FizzHashAlg, hashHex: string): string {
    return `${alg}|${hashHex}`;
}

/**
 * Binds Fizz secrets to their handshake's client_random and turns them into NSS
 * keylog lines. Pure: memory reads, hashing and emission are the caller's.
 */
export class FizzHandshakeBinder {
    private readonly contexts = new LruMap<string, TranscriptContext>(MAX_CONTEXTS, (_key, ctx) => this.unindex(ctx));
    /** alg|prefix hash -> contexts with that transcript prefix (filled lazily, per algorithm). */
    private readonly byPrefixHash = new Map<string, Set<TranscriptContext>>();
    private readonly carried = new Map<string, string>();
    private readonly pending: PendingSecret[] = [];
    private readonly lines = new FifoSet<string>(MAX_DEDUPE_LINES);
    private readonly boundRandoms = new FifoSet<string>(MAX_DEDUPE_LINES);
    private readonly probeSeen = new Set<string>();
    private readonly counts = { contexts: 0, handshakes: 0, bound: 0, carried: 0, droppedPending: 0, lines: 0, f1: 0 };
    /** Transcript state changed since the pending queue was last retried. */
    private transcriptChanged = false;

    constructor(private readonly hash: FizzHasher, private readonly emit: (line: string) => void) {}

    /**
     * Whether the next append of `contextKey` may be stored, so the caller should
     * read the whole message. false: HANDSHAKE_HEADER_LEN bytes plus the total length
     * suffice (the context is full and only tracks message bounds).
     */
    wantsBody(contextKey: string): boolean {
        const ctx = this.contexts.peek(contextKey);
        return ctx === undefined || !ctx.full;
    }

    /**
     * One appendToTranscript call of HandshakeContext `contextKey`: `bytes` are the
     * message's first bytes, `length` its total size. Returns false, changing
     * nothing, when `bytes` is only a prefix of a message that must be stored: the
     * caller then passes the whole message.
     */
    onTranscriptAppend(contextKey: string, bytes: Uint8Array, length: number = bytes.length): boolean {
        if (length === 0) return true;
        const existing = this.contexts.peek(contextKey);
        if (existing !== undefined && existing.owed > 0) return this.append(existing, bytes, length, true);
        const startsContext = bytes[0] === TLS_MESSAGE_HASH || bytes[0] === TLS_CLIENT_HELLO;
        if (startsContext && bytes.length < length) return false;
        if (bytes[0] === TLS_MESSAGE_HASH) {
            this.append(this.startContext(contextKey, null, true), bytes, length, false);
        } else if (bytes[0] === TLS_CLIENT_HELLO) {
            this.onClientHello(contextKey, existing, bytes);
        } else if (existing !== undefined) {
            return this.append(existing, bytes, length, false);
        }
        return true;
    }

    /** One successful deriveSecret; returns the lines emitted (incl. pending secrets bound by now). */
    onSecret(ev: FizzSecretEvent): string[] {
        const emitted = this.retryPending();
        const nss = FIZZ_NSS_LABELS[ev.label];
        const alg = ev.messageHash === null ? null : hashAlgFor(ev.messageHash.length);
        if (nss === undefined || ev.secret.length === 0) return emitted;
        const hashHex = ev.messageHash === null ? null : toHexString(ev.messageHash);
        const exact = alg === null || hashHex === null ? null : this.bindByHash(alg, hashHex);
        const key = `${ev.deriver}|${ev.threadId}`;
        if (PHASE_START_LABELS.has(ev.label) || exact !== null) {
            if (exact !== null) this.carried.set(key, exact.clientRandom); else this.carried.delete(key);
        }
        const clientRandom = exact?.clientRandom ?? this.carried.get(key) ?? null;
        if (clientRandom === null) {
            if (alg !== null && hashHex !== null) this.addPending({ nss, hashHex, alg, secretHex: toHexString(ev.secret) });
            return emitted;
        }
        if (exact === null) this.counts.carried++;
        else this.releaseAfterFinalSecret(nss, exact);
        this.counts.bound++;
        return [...emitted, ...this.emitLine(nss, clientRandom, toHexString(ev.secret))];
    }

    /** One fizz_probe_secret_available call; only the first line per (random, label) (KeyUpdate reuses labels). */
    onProbeSecret(labelEnum: number, clientRandom: Uint8Array, secret: Uint8Array): string[] {
        const nss = FIZZ_PROBE_LABELS[labelEnum];
        if (nss === undefined || clientRandom.length !== CLIENT_RANDOM_LEN || secret.length === 0) return [];
        const randomHex = toHexString(clientRandom);
        const key = `${randomHex}|${labelEnum}`;
        if (this.probeSeen.has(key)) return [];
        this.probeSeen.add(key);
        this.counts.f1++;
        return this.emitLine(nss, randomHex, toHexString(secret));
    }

    get pendingCount(): number {
        return this.pending.length;
    }

    summary(): FizzBinderSummary {
        return {
            contexts: this.counts.contexts, handshakes: this.counts.handshakes, bound: this.counts.bound,
            carried: this.counts.carried, unbound: this.pending.length + this.counts.droppedPending,
            lines: this.counts.lines, f1: this.counts.f1,
        };
    }

    // ---- transcript bookkeeping ----

    private onClientHello(contextKey: string, existing: TranscriptContext | undefined, bytes: Uint8Array): void {
        if (existing !== undefined && existing.hrr && existing.clientRandom === null) {
            existing.clientRandom = clientRandomOf(bytes);
            this.append(existing, bytes, bytes.length, false);
            return;
        }
        const random = clientRandomOf(bytes);
        if (random === null) return;
        this.counts.contexts++;
        this.append(this.startContext(contextKey, random, false), bytes, bytes.length, false);
    }

    private startContext(contextKey: string, clientRandom: string | null, hrr: boolean): TranscriptContext {
        const ctx: TranscriptContext = {
            clientRandom, hrr, chunks: [], bytes: 0, owed: 0, full: false, boundaries: [],
            hashed: { sha256: 0, sha384: 0 }, indexKeys: [],
        };
        const replaced = this.contexts.peek(contextKey);
        if (replaced !== undefined) {
            this.contexts.delete(contextKey);
            this.unindex(replaced);
        }
        this.contexts.set(contextKey, ctx); // evicts (and unindexes) the oldest beyond MAX_CONTEXTS
        return ctx;
    }

    /** See onTranscriptAppend: false only for a prefix of a message that must be stored. */
    private append(ctx: TranscriptContext, bytes: Uint8Array, length: number, continuation: boolean): boolean {
        // A message over MAX_APPEND_BYTES (e.g. a huge Certificate) is never read whole, so it
        // cannot be stored: the context goes header-only rather than skipping it (a skipped
        // message would make every later prefix hash a wrong transcript).
        const stores = !ctx.full && ctx.chunks.length < MAX_CHUNKS_PER_CONTEXT && length <= MAX_APPEND_BYTES
            && ctx.bytes + length <= MAX_CONTEXT_BYTES;
        if (stores && bytes.length < length) return false;
        ctx.owed = continuation ? Math.max(0, ctx.owed - length) : Math.max(0, declaredMessageSize(bytes) - length);
        if (!stores) {
            ctx.full = true; // prefixes recorded so far stay valid; later ones are simply not matchable
            return true;
        }
        ctx.chunks.push(bytes);
        ctx.bytes += length;
        if (ctx.owed === 0) ctx.boundaries.push(ctx.chunks.length);
        this.transcriptChanged = true;
        return true;
    }

    // ---- binding ----

    /** Add the message-boundary prefixes of `ctx` not yet hashed with `alg` to the index. */
    private indexPrefixes(ctx: TranscriptContext, alg: FizzHashAlg): void {
        for (let i = ctx.hashed[alg]; i < ctx.boundaries.length; i++) {
            const key = prefixIndexKey(alg, this.hash(alg, ctx.chunks.slice(0, ctx.boundaries[i])));
            let owners = this.byPrefixHash.get(key);
            if (owners === undefined) this.byPrefixHash.set(key, owners = new Set());
            owners.add(ctx);
            ctx.indexKeys.push(key);
        }
        ctx.hashed[alg] = ctx.boundaries.length;
    }

    private unindex(ctx: TranscriptContext): void {
        for (const key of ctx.indexKeys) {
            const owners = this.byPrefixHash.get(key);
            if (owners === undefined) continue;
            owners.delete(ctx);
            if (owners.size === 0) this.byPrefixHash.delete(key);
        }
        ctx.indexKeys = [];
        this.transcriptChanged = true; // dropping a context can resolve an ambiguity
    }

    /** The only client_random whose handshake has a transcript prefix hashing to `hashHex`, else null. */
    private bindByHash(alg: FizzHashAlg, hashHex: string): ExactBinding | null {
        for (const [, ctx] of this.contexts.entries()) this.indexPrefixes(ctx, alg);
        const owners = this.byPrefixHash.get(prefixIndexKey(alg, hashHex));
        if (owners === undefined) return null;
        const randoms = new Set<string>();
        for (const ctx of owners) if (ctx.clientRandom !== null) randoms.add(ctx.clientRandom);
        return randoms.size === 1 ? { clientRandom: [...randoms][0], owners } : null;
    }

    /** After a handshake's final secret: drop its chunks; its indexed prefix hashes and random stay. */
    private releaseAfterFinalSecret(nss: string, exact: ExactBinding): void {
        if (!FINAL_SECRET_NSS_LABELS.has(nss)) return;
        for (const ctx of exact.owners) {
            ctx.chunks = [];
            ctx.boundaries = [];
            ctx.hashed = { sha256: 0, sha384: 0 };
            ctx.full = true;
        }
    }

    private addPending(p: PendingSecret): void {
        this.pending.push(p);
        if (this.pending.length > MAX_PENDING_SECRETS) {
            this.pending.shift();
            this.counts.droppedPending++;
        }
    }

    /** Re-bind queued secrets, only when the transcripts changed since the last try. */
    private retryPending(): string[] {
        const changed = this.transcriptChanged;
        this.transcriptChanged = false;
        if (!changed) return [];
        const emitted: string[] = [];
        for (let i = this.pending.length - 1; i >= 0; i--) {
            const p = this.pending[i];
            const exact = this.bindByHash(p.alg, p.hashHex);
            if (exact === null) continue;
            this.pending.splice(i, 1);
            this.counts.bound++;
            this.releaseAfterFinalSecret(p.nss, exact);
            emitted.push(...this.emitLine(p.nss, exact.clientRandom, p.secretHex));
        }
        return emitted;
    }

    private emitLine(nss: string, clientRandom: string, secretHex: string): string[] {
        const line = `${nss} ${clientRandom} ${secretHex}`;
        if (this.lines.has(line)) return [];
        this.lines.add(line);
        if (!this.boundRandoms.has(clientRandom)) {
            this.boundRandoms.add(clientRandom);
            this.counts.handshakes++;
        }
        this.counts.lines++;
        this.emit(line);
        return [line];
    }
}

// ---- Frida glue ----------------------------------------------------------------------

/** folly::IOBuf: length_ @0 (u64), data_ @8, next_ @0x20; the chain is circular. */
const IOBUF_LENGTH_AT = 0x0, IOBUF_DATA_AT = 0x8, IOBUF_NEXT_AT = 0x20;
export const MAX_IOBUF_SEGMENTS = 64;
export const MAX_APPEND_BYTES = 64 * 1024;
const MAX_LABEL_LEN = 32;
const MAX_HASH_LEN = 64;
/** fizz::Status::Success; the call sites test `w0 & 0xff`. */
const STATUS_SUCCESS = 1;

export interface IOBufRead {
    /** The chain's first min(total, maxBytes) bytes. */
    bytes: Uint8Array;
    /** Bytes in the whole chain. */
    total: number;
}

function concatParts(parts: Uint8Array[], length: number): Uint8Array {
    if (parts.length === 1) return parts[0]; // one segment: no second copy
    const out = new Uint8Array(length);
    let at = 0;
    for (const part of parts) { out.set(part, at); at += part.length; }
    return out;
}

/**
 * The IOBuf chain at `head`: its total length and its first `maxBytes` bytes
 * (concatenated across segments, never more than MAX_APPEND_BYTES); null when
 * unreadable. The cap applies to the bytes kept only: an oversized chain still
 * reports its total, so the binder can track the message bound.
 */
export function readIOBufChain(head: NativePointer, maxBytes: number = MAX_APPEND_BYTES): IOBufRead | null {
    maxBytes = Math.min(maxBytes, MAX_APPEND_BYTES);
    const parts: Uint8Array[] = [];
    let total = 0;
    let kept = 0;
    let p = head;
    for (let n = 0; n < MAX_IOBUF_SEGMENTS; n++) {
        if (!isReadable(p, IOBUF_NEXT_AT + 8)) return null;
        const length = p.add(IOBUF_LENGTH_AT).readU64().toNumber();
        if (length > 0) {
            const take = Math.min(length, maxBytes - kept);
            if (take > 0) {
                const data = p.add(IOBUF_DATA_AT).readPointer();
                if (!isReadable(data, take)) return null;
                parts.push(new Uint8Array(data.readByteArray(take)!));
                kept += take;
            }
            total += length;
        }
        p = p.add(IOBUF_NEXT_AT).readPointer();
        if (p.equals(head)) break;
    }
    return { bytes: concatParts(parts, kept), total };
}

/** Bytes of [begin, end) when 1..max long and readable, else null. */
function readRange(begin: NativePointer | null, end: NativePointer | null, max: number): Uint8Array | null {
    if (begin === null || end === null) return null;
    const length = Number(end.sub(begin).toString());
    if (!(length >= 1 && length <= max) || !isReadable(begin, length)) return null;
    try { return new Uint8Array(begin.readByteArray(length)!); } catch (_e) { return null; }
}

/** The label [begin, end) decoded from one read (Latin-1, one char per byte). */
function readLabel(begin: NativePointer, end: NativePointer): string | null {
    const bytes = readRange(begin, end, MAX_LABEL_LEN);
    return bytes === null ? null : String.fromCharCode(...bytes);
}

/** Frida's Checksum over the chunks (a chunk viewing its whole buffer is passed without a copy). */
export function fridaFizzHasher(alg: FizzHashAlg, chunks: Uint8Array[]): string {
    const checksum = new Checksum(alg);
    for (const c of chunks) {
        const whole = c.byteOffset === 0 && c.byteLength === c.buffer.byteLength;
        checksum.update((whole ? c.buffer : c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength)) as ArrayBuffer);
    }
    return checksum.getString();
}

let processBinder: FizzHandshakeBinder | null = null;

/**
 * ONE binder per process. Fizz is split across libraries (Instagram: core
 * KeyScheduler in libstartup.so, the F1 probe in libscrollmerged.so), so F1 and F2
 * lines of the same secret must dedupe against each other across modules.
 */
function fizzBinder(): FizzHandshakeBinder {
    if (processBinder === null) processBinder = new FizzHandshakeBinder(fridaFizzHasher, (line) => sendKeylog(line, null));
    return processBinder;
}

/** F2 entry points already hooked (deriveSecret / appendToTranscript address -> module that hooked it). */
const hookedF2Addresses = new Map<string, string>();
/** F1 probe addresses already hooked (each probe once per process). */
const hookedProbeAddresses = new Set<string>();

/**
 * Feed one appendToTranscript call to the binder: the whole message only when the
 * context may store it, otherwise its header (re-read in full only if the binder
 * then asks for it, i.e. a new ClientHello on a full context).
 */
function recordTranscriptAppend(binder: FizzHandshakeBinder, contextKey: string, head: NativePointer): void {
    const read = readIOBufChain(head, binder.wantsBody(contextKey) ? MAX_APPEND_BYTES : HANDSHAKE_HEADER_LEN);
    if (read === null || binder.onTranscriptAppend(contextKey, read.bytes, read.total)) return;
    const whole = readIOBufChain(head);
    if (whole !== null) binder.onTranscriptAppend(contextKey, whole.bytes, whole.total);
}

class FizzHookSet {
    readonly labelCheck = newFizzLabelSelfCheck();
    readonly listeners: InvocationListener[] = [];
    private derive: InvocationListener | null = null;
    private deriveAt: NativePointer | null = null;
    private lastPendingLogged = 0;

    constructor(readonly mod: Module, readonly binder: FizzHandshakeBinder) {}

    attachTranscript(at: NativePointer): void {
        const binder = this.binder;
        this.listeners.push(Interceptor.attach(at, {
            onEnter(args) {
                try {
                    resetReadableCache();
                    const head = safeReadPointer(args[2]);
                    if (head !== null && !head.isNull()) recordTranscriptAppend(binder, args[0].toString(), head);
                } catch (e) {
                    devlog(`[fizz] appendToTranscript hook error: ${e}`);
                }
            },
        }));
    }

    attachDeriveSecret(at: NativePointer): void {
        const self = this;
        this.deriveAt = at;
        this.derive = Interceptor.attach(at, {
            onEnter(args) {
                this.fizzLabel = null;
                try {
                    resetReadableCache();
                    const label = readLabel(args[5], args[6]);
                    const verdict = self.labelCheck.observe(label);
                    if (verdict === "detach") { self.dropDeriveSecretHook(); return; }
                    if (verdict !== "emit" || !(label! in FIZZ_NSS_LABELS)) return;
                    const sp = this.context.sp;
                    this.fizzLabel = label;
                    this.fizzRet = args[1];
                    this.fizzDeriver = args[0].toString();
                    this.fizzHash = readRange(safeReadPointer(sp), safeReadPointer(sp.add(8)), MAX_HASH_LEN);
                } catch (e) {
                    devlog(`[fizz] deriveSecret onEnter error: ${e}`);
                }
            },
            onLeave(retval) {
                if (this.fizzLabel === null || this.fizzLabel === undefined) return;
                try {
                    if ((retval.toUInt32() & 0xff) !== STATUS_SUCCESS) return;
                    const ret: NativePointer = this.fizzRet;
                    const secret = readRange(safeReadPointer(ret), safeReadPointer(ret.add(8)), MAX_SECRET_LEN);
                    if (secret === null) return;
                    self.binder.onSecret({
                        deriver: this.fizzDeriver, threadId: this.threadId, label: this.fizzLabel,
                        messageHash: this.fizzHash, secret,
                    });
                    self.logPendingGrowth();
                } catch (e) {
                    devlog(`[fizz] deriveSecret onLeave error: ${e}`);
                }
            },
        });
        this.listeners.push(this.derive);
    }

    attachProbe(at: NativePointer): void {
        const binder = this.binder;
        this.listeners.push(Interceptor.attach(at, {
            onEnter(args) {
                try {
                    resetReadableCache();
                    const size = args[1].toUInt32() & 0xff;
                    const secret = readRange(args[0], args[0].add(size), MAX_SECRET_LEN);
                    const random = readRange(args[3], args[3].add(CLIENT_RANDOM_LEN), CLIENT_RANDOM_LEN);
                    if (secret !== null && random !== null) binder.onProbeSecret(args[2].toUInt32(), random, secret);
                } catch (e) {
                    devlog(`[fizz] probe hook error: ${e}`);
                }
            },
        }));
    }

    /** Detach this module's listeners (the shared binder and its counts stay). */
    detachListeners(): void {
        for (const l of this.listeners) { try { l.detach(); } catch (_e) { /* already gone */ } }
        this.listeners.length = 0;
    }

    private dropDeriveSecretHook(): void {
        if (this.derive === null) return;
        try { this.derive.detach(); } catch (_e) { /* already gone */ }
        this.derive = null;
        if (this.deriveAt !== null) hookedF2Addresses.delete(this.deriveAt.toString());
        rejectLearnedFunction(this.mod, LEARNED_FIZZ_DERIVE_SECRET);
        log(`[-] ${this.mod.name}: Fizz deriveSecret hook saw ${FIZZ_LABEL_MISMATCH_LIMIT} unknown labels in a row; removed`);
    }

    private logPendingGrowth(): void {
        const pending = this.binder.pendingCount;
        if (pending > this.lastPendingLogged) devlog_debug(`[fizz] ${this.mod.name}: ${pending} unbound secret(s) pending`);
        this.lastPendingLogged = pending;
    }
}

/**
 * Meta's keylog probe as exported by `mod` ITSELF: dlsym on the module handle also
 * searches its DT_NEEDED dependencies, and on Facebook every small lib-compressed
 * library linking libcoldstart.so "exports" fizz_probe_secret_available.
 */
export function findProbeExport(mod: Module): NativePointer | null {
    return findModuleExport(mod.name, FIZZ_PROBE_EXPORT, { ownModuleOnly: true });
}

function tryAttach(mod: Module, what: string, attach: () => void): boolean {
    try {
        attach();
        return true;
    } catch (e) {
        log(`[-] ${mod.name}: could not hook Fizz ${what}: ${e}`);
        return false;
    }
}

const installedHookSets: FizzHookSet[] = [];
let teardownRegistered = false;

/**
 * Hook deriveSecret + appendToTranscript once per ADDRESS; true iff this call hooked
 * them. A module whose located entry points are already hooked (through another
 * module name/mapping of the same code) adds nothing, so no secret is ever reported
 * twice by two hooks.
 */
function installF2(mod: Module, hooks: FizzHookSet, located: FizzLocated | null): boolean {
    if (located === null) return false;
    const key = located.deriveSecret.toString();
    const owner = hookedF2Addresses.get(key);
    if (owner !== undefined) {
        log(`[*] ${mod.name}: Fizz deriveSecret ${moduleOffsetLabel(mod, located.deriveSecret)} already hooked via ${owner}`);
        return false;
    }
    const ok = tryAttach(mod, "appendToTranscript", () => hooks.attachTranscript(located.appendToTranscript))
        && tryAttach(mod, "deriveSecret", () => hooks.attachDeriveSecret(located.deriveSecret));
    if (!ok) {
        hooks.detachListeners();
        return false;
    }
    hookedF2Addresses.set(key, mod.name);
    return true;
}

/** One teardown for every Fizz module: detach all listeners, report the shared binder's counts once. */
function registerFizzTeardown(): void {
    if (teardownRegistered) return;
    teardownRegistered = true;
    registerDetachTeardown("fizz-keylog", () => {
        const modules = installedHookSets.length;
        const deriveSecretHooks = hookedF2Addresses.size;
        for (const hooks of installedHookSets) hooks.detachListeners();
        installedHookSets.length = 0;
        hookedF2Addresses.clear();
        hookedProbeAddresses.clear();
        return { ...fizzBinder().summary(), modules, deriveSecretHooks };
    });
}

function install(mod: Module, located: FizzLocated | null): boolean {
    const hooks = new FizzHookSet(mod, fizzBinder());
    const f2 = installF2(mod, hooks, located);
    const probe = findProbeExport(mod);
    const probeFresh = probe !== null && !hookedProbeAddresses.has(probe.toString());
    const f1 = probeFresh && tryAttach(mod, FIZZ_PROBE_EXPORT, () => hooks.attachProbe(probe!));
    if (f1) hookedProbeAddresses.add(probe!.toString());
    if (!f1 && !f2) return false;
    installedHookSets.push(hooks);
    registerFizzTeardown();
    log(`[*] ${mod.name}: Fizz key hooks installed (deriveSecret+transcript: ${f2 ? "yes" : "no"}, ` +
        `probe export: ${f1 ? moduleOffsetLabel(mod, probe) : "no"})`);
    return true;
}

/** Test seam: forget every install (address dedupe, binder, teardown flag). */
export function resetFizzKeylogStateForTests(): void {
    installedHookSets.length = 0;
    hookedF2Addresses.clear();
    hookedProbeAddresses.clear();
    processBinder = null;
    teardownRegistered = false;
}

/**
 * Hook Fizz key derivation in `mod` (read-only): F2 when `located` is given, plus
 * the F1 probe export when the module has it. True iff this call installed at least
 * one hook. Every entry point is hooked once per address across modules (the
 * per-mapping memo is installFizzKeylog's). One detach teardown ("fizz-keylog")
 * removes every module's listeners and reports {contexts, handshakes, bound,
 * carried, unbound, lines, f1, modules, deriveSecretHooks}.
 */
export function installFizzKeyHooks(mod: Module, located: FizzLocated | null): boolean {
    return install(mod, located);
}
