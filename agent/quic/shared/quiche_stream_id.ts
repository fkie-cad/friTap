// agent/quic/shared/quiche_stream_id.ts
//
// Where QuicStream::id_ lives inside a stream object, for the stream-level
// (de-framed body) hooks whose only handle on the stream is `this`.
//
// The layout discovery (quiche_layout.ts) assumes id_ sits one pointer before
// session_. Current QUICHE moved it: sequencer_, session_, stream_delegate_,
// priority_, priority_source_, stream_bytes_read_, stream_error_, id_. On such
// a build the legacy slot holds the tail of the sequencer (small counters), so
// body records carried a wrong stream id and the per-stream ownership check
// against the STREAM-frame path never matched: both paths reported the bytes.
//
// With the STREAM-frame hooks live the real ids are known (they come straight
// from the QuicStreamFrame / WriteStreamData arguments). The learner scores
// candidate slots around session_ against the ids the frame path saw on the
// same connection, and adopts the slot that keeps matching distinct real ids.
// Without the frame hooks there is no oracle: a seeded offset (cross-run cache)
// is used unchecked until they are live. The legacy slot is read only once the
// frame hooks will never come; while they are still being located ids stay
// unknown (the legacy slot is wrong on current QUICHE and the ids are persisted).

import { LruMap } from "../../shared/lru.js";
import { Address, QuicheMemory } from "./quiche_layout.js";

/** Distinct real stream ids a slot must match before it is adopted. */
export const MIN_DISTINCT_MATCHES = 4;
/** Mismatches a slot may have and still be adopted (an id the oracle already dropped). */
export const MAX_MISSES = 1;
/** Body records spent on learning before giving up (stream ids then stay unknown). */
export const MAX_LEARNING_OBSERVATIONS = 512;
/** Last bytes past session_ that may hold id_ (current QUICHE: session_ + 0x50). */
export const ID_SCAN_AFTER_SESSION = 0xc0;
/** Connections whose frame-path stream ids are remembered (LRU). */
const MAX_ORACLE_CONNECTIONS = 64;
/** Stream ids remembered per connection (oldest dropped first). */
const MAX_ORACLE_IDS = 256;

/** "awaiting": the frame hooks are still being located (no oracle yet, legacy slot not trusted). */
export type StreamIdLearning = "legacy" | "awaiting" | "learning" | "learned" | "failed";

/** States in which an unknown id may still become known: body records are held, not sent. */
export function isStreamIdPending(learning: StreamIdLearning): boolean {
    return learning === "learning" || learning === "awaiting";
}

/** Copy of the stream bytes the learner scores: `bytes[0]` is at session_ + `base`. */
export interface StreamIdWindow { readonly base: number; readonly bytes: Uint8Array; }

/** The candidate-slot window of `stream` (session_ - pointer .. session_ + ID_SCAN_AFTER_SESSION + 4). */
export function readStreamIdWindow(mem: QuicheMemory, stream: Address, streamSession: number): StreamIdWindow | null {
    const base = -mem.pointerSize;
    const bytes = mem.readBytes(stream + BigInt(streamSession + base), mem.pointerSize + ID_SCAN_AFTER_SESSION + 4);
    return bytes ? { base, bytes } : null;
}

/** The window of one stream, read on first call only (the learner and the body queue share one read). */
export type StreamIdWindowSource = () => StreamIdWindow | null;

export function lazyStreamIdWindow(mem: QuicheMemory, stream: Address, streamSession: number): StreamIdWindowSource {
    let read = false;
    let window: StreamIdWindow | null = null;
    return () => {
        if (!read) {
            window = readStreamIdWindow(mem, stream, streamSession);
            read = true;
        }
        return window;
    };
}

interface Candidate { offset: number; matched: Set<number>; misses: number; }

function newCandidate(offset: number): Candidate {
    return { offset, matched: new Set(), misses: 0 };
}

/** Score `value` read at the candidate's slot against the frame-path ids of its connection. */
function score(candidate: Candidate, value: number, known: Set<number>): void {
    if (known.has(value)) candidate.matched.add(value);
    else candidate.misses++;
}

function isRuledOut(candidate: Candidate): boolean {
    return candidate.misses > MAX_MISSES;
}

function isDecided(candidate: Candidate): boolean {
    return candidate.matched.size >= MIN_DISTINCT_MATCHES;
}

function u32le(bytes: Uint8Array, offset: number): number {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) |
            (bytes[offset + 3] << 24)) >>> 0;
}

/** u32 at `offset` (relative to session_) inside `window`; null outside it. */
function readWindowU32(window: StreamIdWindow, offset: number): number | null {
    const at = offset - window.base;
    return at >= 0 && at + 4 <= window.bytes.length ? u32le(window.bytes, at) : null;
}

/** The legacy slot (session_ - pointer, the window's first u32) of a window copy. */
export function legacyStreamIdFromWindow(window: StreamIdWindow | null): number | null {
    return window === null ? null : readWindowU32(window, window.base);
}

/** Candidate id_ offsets relative to session_: the legacy slot, then every u32 after stream_delegate_. */
function candidateOffsets(pointerSize: number): number[] {
    const offsets = [-pointerSize];
    for (let o = 2 * pointerSize; o <= ID_SCAN_AFTER_SESSION; o += 4) offsets.push(o);
    return offsets;
}

export class QuicheStreamIdLearner {
    /** The STREAM-frame hooks: not expected, being located, or live (their ids are the oracle). */
    private oracle: "none" | "awaiting" | "live" = "none";
    private learnedOffset: number | null = null;
    private failed = false;
    private observations = 0;
    private candidates: Candidate[] | null = null;
    private seeded = false;
    /** The seeded offset's score while it is still unconfirmed. */
    private seedCheck: Candidate | null = null;
    private readonly seen = new LruMap<string, Set<number>>(MAX_ORACLE_CONNECTIONS);

    /** Called once when a seeded offset is confirmed (true) or contradicted and dropped (false). */
    onSeedSettled?: (holds: boolean) => void;

    /** Called once when learning ends: an offset was adopted ("learned") or the budget ran out ("failed"). */
    onLearningSettled?: (learning: "learned" | "failed") => void;

    /** The STREAM-frame hooks are live: from now on ids are learned against them. */
    enableOracle(): void {
        this.oracle = "live";
    }

    /** The frame hooks are being located: until they settle, ids without a seed stay unknown. */
    awaitOracle(): void {
        if (this.oracle !== "live") this.oracle = "awaiting";
    }

    /** The frame hooks will never be live: fall back to the legacy slot. */
    oracleUnavailable(): void {
        if (this.oracle === "awaiting") this.oracle = "none";
    }

    get learning(): StreamIdLearning {
        if (this.oracle === "none") return "legacy";
        if (this.oracle === "awaiting") return "awaiting";
        if (this.learnedOffset !== null) return "learned";
        return this.failed ? "failed" : "learning";
    }

    /** id_ offset relative to session_, once learned (or seeded). */
    get offset(): number | null {
        return this.learnedOffset;
    }

    /** id_ offset once learned or a seed confirmed; null while a seed is unconfirmed. */
    get validatedOffset(): number | null {
        return this.seedCheck === null ? this.learnedOffset : null;
    }

    /**
     * Use `offset` (relative to session_, e.g. from an earlier run) right away.
     * It is still checked against the frame-path ids with the learning miss rule
     * and dropped, back to learning, once they contradict it. Ignored after
     * learning has started deciding, or for an offset outside the scan window.
     */
    seedOffset(offset: number): boolean {
        if (this.learnedOffset !== null || this.failed || this.candidates !== null || this.seeded) return false;
        if (!Number.isInteger(offset) || offset < -8 || offset > ID_SCAN_AFTER_SESSION) return false;
        this.learnedOffset = offset;
        this.seeded = true;
        this.seedCheck = newCandidate(offset);
        return true;
    }

    /** A real stream id the frame path saw on `connection` (the capture connection key). */
    noteStream(connection: string, streamId: number): void {
        let ids = this.seen.get(connection);
        if (ids === undefined) {
            ids = new Set();
            this.seen.set(connection, ids);
        }
        if (ids.has(streamId)) return;
        if (ids.size >= MAX_ORACLE_IDS) ids.delete(ids.values().next().value as number);
        ids.add(streamId);
    }

    /**
     * Stream id of `stream` (whose session_ is at `streamSession`) on `connection`,
     * or null while it cannot be trusted (frame hooks pending, still learning, or learning failed).
     * Only `canTeach` records (ingress bodies, decoded after their STREAM frame
     * reached the frame hooks) are compared; an egress body may precede its frame.
     * `window`, when given, is the stream's shared window source (read at most once).
     */
    streamId(mem: QuicheMemory, stream: Address, streamSession: number, connection: string,
             canTeach: boolean, window?: StreamIdWindowSource): number | null {
        const ps = mem.pointerSize;
        if (this.learnedOffset !== null) {
            const id = this.readAt(mem, stream, streamSession + this.learnedOffset);
            // Before the frame hooks are live a seed cannot be checked, but it beats
            // the legacy slot, which current QUICHE fills with the sequencer tail.
            if (this.seedCheck === null || !canTeach || this.oracle !== "live") return id;
            this.checkSeed(id, connection);
            if (this.learnedOffset !== null) return id;
        }
        if (this.oracle === "none") return this.readAt(mem, stream, streamSession - ps);
        if (this.oracle === "awaiting") return null;
        if (this.failed || !canTeach) return null;
        this.observe(mem, stream, streamSession, connection, window);
        return this.learnedOffset === null ? null : this.readAt(mem, stream, streamSession + this.learnedOffset);
    }

    /** id_ read from a window copied while learning, through the now known offset; null while unknown. */
    streamIdFromWindow(window: StreamIdWindow | null): number | null {
        if (this.learnedOffset === null || window === null) return null;
        return readWindowU32(window, this.learnedOffset);
    }

    private checkSeed(id: number | null, connection: string): void {
        const known = this.seen.get(connection);
        const check = this.seedCheck!;
        if (id === null || known === undefined || known.size === 0) return;
        score(check, id, known);
        const holds = !isRuledOut(check);
        if (holds && !isDecided(check)) return;
        this.seedCheck = null;
        if (!holds) this.learnedOffset = null;
        this.onSeedSettled?.(holds);
    }

    private readAt(mem: QuicheMemory, stream: Address, offset: number): number | null {
        const bytes = mem.readBytes(stream + BigInt(offset), 4);
        return bytes && bytes.length >= 4 ? u32le(bytes, 0) : null;
    }

    private observe(mem: QuicheMemory, stream: Address, streamSession: number, connection: string,
                    windowOf?: StreamIdWindowSource): void {
        const known = this.seen.get(connection);
        if (known === undefined || known.size === 0) return;    // nothing to compare with yet
        const window = windowOf ? windowOf() : readStreamIdWindow(mem, stream, streamSession);
        if (!window) return;
        this.candidates ??= candidateOffsets(mem.pointerSize).map(newCandidate);
        for (const c of this.candidates) {
            const value = readWindowU32(window, c.offset);
            if (value !== null) score(c, value, known);
        }
        this.candidates = this.candidates.filter((c) => !isRuledOut(c));
        this.adoptIfDecided();
        if (this.learnedOffset !== null) {
            this.onLearningSettled?.("learned");
        } else if (++this.observations >= MAX_LEARNING_OBSERVATIONS) {
            this.failed = true;
            this.candidates = null;
            this.onLearningSettled?.("failed");
        }
    }

    private adoptIfDecided(): void {
        // Several qualifying slots (e.g. a copy of the id in flow_controller_) agree on
        // every stream: the one with most distinct matches, then the lowest offset, wins.
        let best: Candidate | null = null;
        for (const c of this.candidates!) {
            if (!isDecided(c)) continue;
            if (best === null || c.matched.size > best.matched.size) best = c;
        }
        if (best === null) return;
        this.learnedOffset = best.offset;
        this.candidates = null;
    }
}
