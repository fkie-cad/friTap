// agent/tls/shared/boringssl_plaintext_locator.ts
//
// Locate BoringSSL's SSL_read / SSL_write in a STRIPPED, statically linked
// arm64 monolith (Chrome's libmonochrome_64.so / libchrome.so, WebView's
// libwebviewchromium.so) without symbols or per-version byte patterns.
//
// Keys for these builds already come from the ssl_log_secret pattern/anchor
// tiers; plaintext did not, because nothing located the record-layer API.
//
// ANCHOR: every OPENSSL_PUT_ERROR(SSL, reason) in ssl_lib.cc compiles to
//     adrp/adr x3, "<...>/ssl/ssl_lib.cc"     ; __FILE__
//     mov  w0, #0x10                           ; ERR_LIB_SSL
//     mov  w2, #<reason>                       ; SSL_R_* / ERR_R_*
//     mov  w4, #<line>                         ; __LINE__ (version specific, unused)
//     bl   ERR_put_error
// The REASON codes are part of BoringSSL's stable error ABI, so the set of
// reasons a function raises identifies it across versions:
//   SSL_write      : ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED (quic_method), SSL_R_UNINITIALIZED,
//                    SSL_R_BAD_LENGTH (num < 0) [+ SSL_R_SSL_HANDSHAKE_FAILURE]  — unique;
//   ssl_read_impl  : SSL_R_UNINITIALIZED + SSL_R_SSL_HANDSHAKE_FAILURE, nothing else;
//   SSL_peek       : only ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED, and calls ssl_read_impl;
//   SSL_read       : SSL_peek + consume. SSL_peek returns right after copying the record
//                    out; SSL_read stores (consumes it) first. Either it calls SSL_peek first
//                    (Chrome 133 libmonochrome) or SSL_peek / ssl_read_impl are inlined into
//                    it (see resolveSslRead, pickConsumingReader).
//
// Flutter's libflutter.so passes __FILE__ in x2 to a 4-argument ERR_put_error
// copy (reason w1, line w3), usually via a shared OUTLINED stub
//     adrp x2, ssl_lib.cc ; add x2, x2, #.. ; mov w0, #0x10 ; ret
// called as `bl stub ; mov w1, #reason ; mov w3, #line ; bl ERR_put_error`.
// So the reason is read relative to the file register F (reason w(F-1), line
// w(F+1)), and a stub's sites are its BL callers. There SSL_peek and
// ssl_read_impl are inlined into SSL_read, which is then picked by its reasons.
//
// Function boundaries come from the module's .eh_frame_hdr search table, so a
// hook is only ever placed on a real function entry; sites no FDE covers use
// landing-pad bounds (eh_frame.ts functionBoundsFor).
//
// Verified on Chrome 133.0.6943.137 libmonochrome_64.so (SSL_read +0x515113c,
// SSL_write +0x5151490) and on mainline Cronet's stable_cronet_libssl.so (the
// inlined-peek shape; checked against its exported SSL_read/SSL_write).

import { devlog } from "../../util/log.js";
import {
    AnchorSite, FunctionBoundsSource, LOAD_SITE_WINDOW, ScanRange, anchorSiteFunctions, moduleOffsetLabel, scanRangesChunked,
} from "../../shared/arm64_xref.js";
import {
    blTargetOffset, isADDimm64, isADR, isADRP, isBL, isBLR, isLDRimmU64, isNonStackStore, isRET, isUnconditionalB,
    maskedWordScanPattern, movzW, regRd, regRn,
} from "../../shared/arm64.js";
import { functionBoundsFor } from "../../shared/eh_frame.js";

// ---------------------------------------------------------------------------
// Pure logic (unit-tested under Node)
// ---------------------------------------------------------------------------

export const ERR_LIB_SSL = 0x10;
export const SSL_REASON = {
    SHOULD_NOT_HAVE_BEEN_CALLED: 0x42,   // ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED
    BAD_LENGTH: 0x6f,                    // SSL_R_BAD_LENGTH
    SSL_HANDSHAKE_FAILURE: 0xd7,         // SSL_R_SSL_HANDSHAKE_FAILURE
    UNINITIALIZED: 0xe2,                 // SSL_R_UNINITIALIZED
} as const;

/** Instructions searched after (and before) an error site's __FILE__ load. */
const REASON_WINDOW_AFTER = 10;
export const REASON_WINDOW_BEFORE = 6;

/**
 * The SSL reason code of the OPENSSL_PUT_ERROR site whose __FILE__ load is
 * `words[at]`: the nearest `mov w2, #imm` (forward first), accepted only when
 * a `mov w0, #ERR_LIB_SSL` is in the same window.
 */
export function decodeErrorReason(words: ArrayLike<number>, at: number): number | null {
    const lo = Math.max(0, at - REASON_WINDOW_BEFORE);
    const hi = Math.min(words.length, at + REASON_WINDOW_AFTER + 1);
    let isSslLib = false;
    for (let i = lo; i < hi; i++) if (movzW(words[i], 0) === ERR_LIB_SSL) isSslLib = true;
    if (!isSslLib) return null;
    for (let i = at + 1; i < hi; i++) {
        const reason = movzW(words[i], 2);
        if (reason !== null) return reason;
    }
    for (let i = at - 1; i >= lo; i--) {
        const reason = movzW(words[i], 2);
        if (reason !== null) return reason;
    }
    return null;
}

/** Instructions after the __FILE__ load (or the stub call) holding the reason/line movs. */
export const ARGS_WINDOW = 10;

/** The register a site's __FILE__ load leaves the literal in, and the index of its last word. */
export interface FileLoad { reg: number; end: number; }

/** `words[at]` is the ADRP/ADR of a __FILE__ load: where it completes, or null. */
export function fileLoadAt(words: ArrayLike<number>, at: number): FileLoad | null {
    const first = words[at];
    if (first === undefined) return null;
    if (isADR(first)) return { reg: regRd(first), end: at };
    if (!isADRP(first)) return null;
    const page = regRd(first);
    const hi = Math.min(words.length, at + 1 + LOAD_SITE_WINDOW);
    for (let i = at + 1; i < hi; i++) {
        const w = words[i];
        if ((isADDimm64(w) || isLDRimmU64(w)) && regRn(w) === page) return { reg: regRd(w), end: i };
    }
    return null;
}

/** The load is the body of an outlined `file = ssl_lib.cc; lib = SSL; return` stub. */
// Assumes the ADRP is the stub's first word (entry = load site); otherwise no caller matches (fails safe).
export function isOutlinedErrorStub(words: ArrayLike<number>, load: FileLoad): boolean {
    const end = load.end;
    return end + 2 < words.length && movzW(words[end + 1], 0) === ERR_LIB_SSL && isRET(words[end + 2]);
}

export interface ErrorArgs { reason: number; line: number | null; }

/**
 * Reason (`mov w(F-1)`) and line (`mov w(F+1)`) of the error call that follows
 * `words[start]`, F being the __FILE__ register. Stops after the first call,
 * branch or return; null unless `mov w0, #ERR_LIB_SSL` was seen (or `libSeen`).
 */
export function decodeArgsAfter(words: ArrayLike<number>, start: number, fileReg: number,
                                libSeen: boolean): ErrorArgs | null {
    // F-1 must not alias w0 (the library code).
    if (fileReg < 2 || fileReg > 29) return null;
    let reason: number | null = null, line: number | null = null, lib = libSeen;
    const hi = Math.min(words.length, start + ARGS_WINDOW);
    for (let i = start; i < hi; i++) {
        const w = words[i];
        if (movzW(w, 0) === ERR_LIB_SSL) lib = true;
        if (reason === null) reason = movzW(w, fileReg - 1);
        if (line === null) line = movzW(w, fileReg + 1);
        if (isBL(w) || isUnconditionalB(w) || isRET(w)) break;
    }
    return lib && reason !== null ? { reason, line } : null;
}

/** An ssl_lib.cc load site, classified. */
export type DecodedLoad =
    | { kind: "site"; reason: number }
    | { kind: "stub"; fileReg: number }
    | null;

/** `mov w0, #ERR_LIB_SSL` in the lookback before `words[at]`, not past a call, branch or return. */
export function libLoadedBefore(words: ArrayLike<number>, at: number): boolean {
    // Stop at control flow like decodeArgsAfter: a w0 set before it belongs to another call.
    for (let i = at - 1; i >= Math.max(0, at - REASON_WINDOW_BEFORE); i--) {
        const w = words[i];
        if (isBL(w) || isUnconditionalB(w) || isBLR(w) || isRET(w)) return false;
        if (movzW(w, 0) === ERR_LIB_SSL) return true;
    }
    return false;
}

/**
 * Classify the __FILE__ load at `words[at]`: an inline error site with its
 * reason, an outlined stub (its sites are its callers), or nothing. x3 sites
 * keep the original 5-argument decoder unchanged.
 */
export function decodeFileLoad(words: ArrayLike<number>, at: number): DecodedLoad {
    const load = fileLoadAt(words, at);
    if (load !== null && isOutlinedErrorStub(words, load)) return { kind: "stub", fileReg: load.reg };
    if (load !== null && load.reg !== 3) {
        const lib = libLoadedBefore(words, at);
        const args = decodeArgsAfter(words, load.end + 1, load.reg, lib);
        if (args !== null) return { kind: "site", reason: args.reason };
    }
    const reason = decodeErrorReason(words, at);
    return reason === null ? null : { kind: "site", reason };
}

/**
 * `words[0]` at module offset `pc` calls one of `stubs` (entry offset -> file
 * register): the error args after the call, else null.
 */
export function decodeStubCall(pc: number, words: ArrayLike<number>, stubs: Map<number, number>): ErrorArgs | null {
    const target = words.length > 0 ? blTargetOffset(pc, words[0]) : null;
    const fileReg = target === null ? undefined : stubs.get(target);
    return fileReg === undefined ? null : decodeArgsAfter(words, 1, fileReg, true);
}

export interface ErrorSite { func: number; reason: number; }

export function reasonsByFunction(sites: ErrorSite[]): Map<number, Set<number>> {
    const groups = new Map<number, Set<number>>();
    for (const { func, reason } of sites) {
        if (!groups.has(func)) groups.set(func, new Set());
        groups.get(func)!.add(reason);
    }
    return groups;
}

function only<T>(items: T[]): T | null {
    return items.length === 1 ? items[0] : null;
}

function funcsWhere(groups: Map<number, Set<number>>, pred: (r: Set<number>) => boolean): number[] {
    return [...groups.entries()].filter(([, reasons]) => pred(reasons)).map(([func]) => func);
}

/** The unique function raising SHOULD_NOT_HAVE_BEEN_CALLED + UNINITIALIZED + BAD_LENGTH. */
export function pickSslWrite(groups: Map<number, Set<number>>): number | null {
    const R = SSL_REASON;
    return only(funcsWhere(groups, (r) =>
        r.has(R.SHOULD_NOT_HAVE_BEEN_CALLED) && r.has(R.UNINITIALIZED) && r.has(R.BAD_LENGTH)));
}

/** ssl_read_impl's reasons (UNINITIALIZED + SSL_HANDSHAKE_FAILURE), here or inlined; never SSL_write's BAD_LENGTH. */
function isReadImplShaped(r: Set<number>): boolean {
    const R = SSL_REASON;
    return r.has(R.UNINITIALIZED) && r.has(R.SSL_HANDSHAKE_FAILURE) && !r.has(R.BAD_LENGTH);
}

/** The unique function raising exactly UNINITIALIZED + SSL_HANDSHAKE_FAILURE (ssl_read_impl). */
export function pickSslReadImpl(groups: Map<number, Set<number>>): number | null {
    return only(funcsWhere(groups, (r) => r.size === 2 && isReadImplShaped(r)));
}

/** Functions whose only ssl_lib.cc error is SHOULD_NOT_HAVE_BEEN_CALLED (SSL_peek-shaped). */
export function peekShapedFunctions(groups: Map<number, Set<number>>): number[] {
    return funcsWhere(groups, (r) => r.size === 1 && r.has(SSL_REASON.SHOULD_NOT_HAVE_BEEN_CALLED));
}

/**
 * SSL_read when SSL_peek and ssl_read_impl are both inlined into it (Flutter):
 * the unique function raising SHOULD_NOT_HAVE_BEEN_CALLED + UNINITIALIZED +
 * SSL_HANDSHAKE_FAILURE but not BAD_LENGTH (which marks SSL_write).
 */
export function pickInlinedSslRead(groups: Map<number, Set<number>>): number | null {
    return only(inlinedReadShapedFunctions(groups));
}

/** Functions with ssl_read_impl inlined: SHOULD_NOT_HAVE_BEEN_CALLED + UNINITIALIZED + SSL_HANDSHAKE_FAILURE, no BAD_LENGTH. */
export function inlinedReadShapedFunctions(groups: Map<number, Set<number>>): number[] {
    return funcsWhere(groups, (r) => isReadImplShaped(r) && r.has(SSL_REASON.SHOULD_NOT_HAVE_BEEN_CALLED));
}

/**
 * SSL_read when no ssl_read_impl was found: the inlined-read shape, trusted only
 * when outlined stubs were found (the Flutter layout); otherwise no read hook
 * rather than risk hooking SSL_write as SSL_read.
 */
export function pickSslReadWithoutImpl(groups: Map<number, Set<number>>, stubCount: number): number | null {
    return stubCount > 0 ? pickInlinedSslRead(groups) : null;
}

/**
 * The BL-caller scan of outlined stubs is a whole-module fallback: only when the
 * inline sites did not already yield SSL_write and a read candidate.
 */
export function needsStubCallerScan(groups: Map<number, Set<number>>, stubCount: number): boolean {
    if (stubCount === 0) return false;
    const hasRead = pickSslReadImpl(groups) !== null || pickInlinedSslRead(groups) !== null;
    return pickSslWrite(groups) === null || !hasRead;
}

/** `callees` in address order (directCallees inserts them as it walks the body). */
export interface FunctionCalls { func: number; callees: Set<number>; }

/**
 * ssl_read_impl with more inlined into it (LTO, e.g. libsignal_jni: post-handshake
 * reasons too). Raises UNINITIALIZED + SSL_HANDSHAKE_FAILURE, not BAD_LENGTH, and is
 * called by a peek-shaped function, which keeps an inlined SSL_read or SSL_shutdown out.
 */
export function pickCalledSslReadImpl(groups: Map<number, Set<number>>, peekShaped: FunctionCalls[]): number | null {
    const called = new Set(peekShaped.flatMap((f) => [...f.callees]));
    return only(funcsWhere(groups, isReadImplShaped).filter((func) => called.has(func)));
}

/** The exact-set ssl_read_impl first, else the called superset one. */
export function chooseSslReadImpl(groups: Map<number, Set<number>>, peekShaped: FunctionCalls[]): number | null {
    return pickSslReadImpl(groups) ?? pickCalledSslReadImpl(groups, peekShaped);
}

/**
 * What the code after the producer call `words[at]` reaches first: a non-sp store (the
 * consume), a return, or nothing. With `stopAtCalls` a call or branch also ends the walk.
 */
function effectAfterCall(words: ArrayLike<number>, base: number, at: number,
                         stopAtCalls: boolean): "consumes" | "returns" | null {
    for (let j = at + 1; j < words.length; j++) {
        const w = words[j];
        if (isNonStackStore(w)) return "consumes";
        if (isRET(w)) return "returns";
        if (stopAtCalls && (blTargetOffset(base + j * 4, w) !== null || isBLR(w) || isUnconditionalB(w))) return null;
    }
    return null;
}

/** Index of the first BL in `words[from..]` (at module offset `base`) whose target satisfies `pred`, or -1. */
function firstCallWhere(words: ArrayLike<number>, base: number, from: number,
                        pred: (target: number) => boolean): number {
    for (let i = from; i < words.length; i++) {
        const t = blTargetOffset(base + i * 4, words[i]);
        if (t !== null && pred(t)) return i;
    }
    return -1;
}

/**
 * The body `words` (at module offset `base`) calls `readImpl`, then a copy (the
 * next other BL), then stores to memory before a return: SSL_read consuming the
 * record it copied out (true). Bare SSL_peek returns after the copy (false).
 * null when the body is unreadable or shows neither.
 */
export function copyVerdict(words: ArrayLike<number>, base: number, readImpl: number): boolean | null {
    const impl = firstCallWhere(words, base, 0, (t) => t === readImpl);
    const copy = impl < 0 ? -1 : firstCallWhere(words, base, impl + 1, (t) => t !== readImpl);
    const effect = copy < 0 ? null : effectAfterCall(words, base, copy, false);
    return effect === null ? null : effect === "consumes";
}

/** What follows the calls to `target` in `words` (at module offset `base`), up to the next call or return. */
export function afterCallsTo(words: ArrayLike<number>, base: number, target: number): { consumes: boolean; returns: boolean } {
    let consumes = false, returns = false;
    for (let i = firstCallWhere(words, base, 0, (t) => t === target); i >= 0;
         i = firstCallWhere(words, base, i + 1, (t) => t === target)) {
        const effect = effectAfterCall(words, base, i, true);
        consumes ||= effect === "consumes";
        returns ||= effect === "returns";
    }
    return { consumes, returns };
}

export interface FunctionBody { func: number; words: ArrayLike<number>; }

/** Direct call targets (module offsets) of a body, in address order. */
function directCallees({ func, words }: FunctionBody): Set<number> {
    const out = new Set<number>();
    for (let i = 0; i < words.length; i++) {
        const t = blTargetOffset(func + i * 4, words[i]);
        if (t !== null) out.add(t);
    }
    return out;
}

/**
 * ssl_read_impl inlined into both SSL_read and SSL_peek: the copy is a callee all bodies
 * share. SSL_read is the one body that stores after it while every other body returns.
 */
export function pickConsumingReader(bodies: FunctionBody[]): number | null {
    if (bodies.length < 2) return null;
    const [first, ...rest] = bodies.map(directCallees);
    const shared = [...first].filter((t) => rest.every((callees) => callees.has(t)));
    const picks = new Set<number>();
    for (const target of shared) {
        const after = bodies.map((b) => afterCallsTo(b.words, b.func, target));
        const consumers = bodies.filter((_, i) => after[i].consumes && !after[i].returns);
        const othersReturn = after.every((a, i) => bodies[i] === consumers[0] || (a.returns && !a.consumes));
        if (consumers.length === 1 && othersReturn) picks.add(consumers[0].func);
    }
    return only([...picks]);
}

/** `a` when its callee set strictly contains `b`'s (the extra callee is the consume helper). */
function calleeSuperset(a: FunctionCalls, b: FunctionCalls): FunctionCalls | null {
    const contains = (x: Set<number>, y: Set<number>) => x.size > y.size && [...y].every((c) => x.has(c));
    return contains(a.callees, b.callees) ? a : contains(b.callees, a.callees) ? b : null;
}

/**
 * SSL_read (= SSL_peek + consume) from the peek-shaped functions that call ssl_read_impl.
 * Two readers where one's callee set strictly contains the other's: the superset is
 * SSL_read with SSL_peek inlined. Otherwise the candidate is the lone reader, or the one
 * whose first call is ssl_read_impl (SSL_peek can also be inlined into callers that call
 * other helpers first). A unique wrapper calling it first makes it SSL_peek and the wrapper
 * SSL_read; without one it is accepted only if it consumes. Several candidates: the unique
 * consuming one. `consumes` is tri-state (see copyVerdict).
 */
export function resolveSslRead(
    peekShaped: FunctionCalls[], readImpl: number, wrappersOf: (peek: number) => number[],
    consumes: (func: number) => boolean | null = () => null,
): number | null {
    const readers = peekShaped.filter((f) => f.callees.has(readImpl));
    const superset = readers.length === 2 ? calleeSuperset(readers[0], readers[1]) : null;
    if (superset !== null) return superset.func;
    const leading = readers.length > 1
        ? readers.filter((f) => f.callees.values().next().value === readImpl)
        : readers;
    if (leading.length !== 1) return only(leading.filter((f) => consumes(f.func) === true))?.func ?? null;
    const [candidate] = leading;
    const wrappers = wrappersOf(candidate.func);
    const wrapper = only(wrappers);
    if (wrapper !== null) return wrapper;
    // A bare SSL_peek also calls ssl_read_impl first; hooking it as SSL_read duplicates peeked records.
    if (readers.length > 1) return consumes(candidate.func) === true ? candidate.func : null;
    // A lone reader with ambiguous wrappers stays unresolved rather than guessed.
    return wrappers.length === 0 && consumes(candidate.func) === true ? candidate.func : null;
}

// ---------------------------------------------------------------------------
// Frida side
// ---------------------------------------------------------------------------

/** Upper bound on a function body walked for its calls. */
const MAX_BODY_BYTES = 0x1000;
/** Around the ssl_lib.cc functions, how far to look for SSL_read's call to SSL_peek. */
const WRAPPER_SEARCH_MARGIN = 0x10000;

function readWords(at: NativePointer, count: number): Uint32Array | null {
    try {
        const buf = at.readByteArray(count * 4);
        return buf ? new Uint32Array(buf) : null;
    } catch (_e) {
        return null;
    }
}

function offsetOf(mod: Module, p: NativePointer): number {
    return p.sub(mod.base).toInt32();
}

/** Functions near `around` whose FIRST call is a BL to `peek` (SSL_read wrapping SSL_peek). */
function wrappersOf(mod: Module, table: FunctionBoundsSource, peek: number, lo: number, hi: number): number[] {
    // Also bounded around `peek`: ssl_lib.cc functions can span ~123 MB (macOS Chrome).
    const start = Math.max(0, lo - WRAPPER_SEARCH_MARGIN, peek - WRAPPER_SEARCH_MARGIN);
    const end = Math.min(hi + WRAPPER_SEARCH_MARGIN, peek + WRAPPER_SEARCH_MARGIN, mod.size);
    const words = readWords(mod.base.add(start), (end - start) >> 2) ?? new Uint32Array(0);
    const found = new Set<number>();
    words.forEach((w, i) => {
        const pc = start + i * 4;
        if (blTargetOffset(pc, w) !== peek) return;
        const fn = table.bounds(mod.base.add(pc));
        if (!fn) return;
        const fnOff = offsetOf(mod, fn.start);
        // The call must be the function's first: no other BL between entry and it.
        const prefix = readWords(fn.start, (pc - fnOff) >> 2) ?? new Uint32Array(0);
        if (prefix.length <= 16 && prefix.every((x, k) => blTargetOffset(fnOff + k * 4, x) === null)) found.add(fnOff);
    });
    return [...found];
}

export interface LocatedPlaintextApi {
    sslRead: NativePointer | null;
    sslWrite: NativePointer | null;
}

/** ssl_lib.cc's __FILE__ literal: every OPENSSL_PUT_ERROR site in the file loads it. */
const SSL_LIB_ANCHOR = { text: "/ssl/ssl_lib.cc", literalSuffix: true, maxSites: 512 };

/** Words read around a load site: lookback, the load itself, its ADD/LDR, the args or stub tail. */
const LOAD_WINDOW_WORDS = REASON_WINDOW_BEFORE + 1 + Math.max(REASON_WINDOW_AFTER, LOAD_SITE_WINDOW + ARGS_WINDOW);

/**
 * `bl <any>` followed by `movz w<reasonReg>, #imm`: an outlined-stub call site
 * (Flutter: `bl stub; mov w1, #reason`). Pinning the register keeps the hit count down.
 */
export function blThenMovzPattern(reasonReg: number): string {
    const [bl, blMask] = maskedWordScanPattern(0x94000000, 0xfc000000).split(" : ");
    const [mov, movMask] = maskedWordScanPattern((0x52800000 | reasonReg) >>> 0, 0xffe0001f).split(" : ");
    return `${bl} ${mov} : ${blMask} ${movMask}`;
}

interface SiteCollector {
    sites: ErrorSite[];
    bodies: Map<number, NativePointer | null>;
}

function addSite(mod: Module, out: SiteCollector, fn: AnchorSite["fn"], reason: number): void {
    if (!fn) return;
    const func = offsetOf(mod, fn.start);
    out.bodies.set(func, fn.end);
    out.sites.push({ func, reason });
}

/**
 * Error sites raised through outlined stubs: every `bl stub` in the module's
 * code, found with one native masked scan (only run when a stub exists).
 */
async function addStubCallerSites(mod: Module, table: FunctionBoundsSource, stubs: Map<number, number>,
                                  out: SiteCollector): Promise<void> {
    let hits = 0;
    const onMatch = (hit: NativePointer) => {
        hits++;
        if (hit.and(ptr(3)).toInt32() !== 0) return;
        const pc = offsetOf(mod, hit);
        const args = decodeStubCall(pc, readWords(hit, 1 + ARGS_WINDOW) ?? [], stubs);
        if (args !== null) addSite(mod, out, table.bounds(hit), args.reason);
    };
    const code = mod.enumerateRanges("r-x") as ScanRange[];
    const reasonRegs = new Set([...stubs.values()].map((fileReg) => fileReg - 1).filter((r) => r > 0));
    const started = Date.now();
    await scanRangesChunked(code, [...reasonRegs].map((r) => ({ pattern: blThenMovzPattern(r), onMatch })));
    devlog(`[BoringSSL plaintext] ${mod.name}: stub-caller scan ${hits} hits in ${Date.now() - started} ms`);
}

/** Error sites (function + reason) of the ssl_lib.cc anchor's load sites, plus each function's end. */
async function sslLibErrorSites(mod: Module, table: FunctionBoundsSource):
        Promise<{ sites: ErrorSite[]; bodies: Map<number, NativePointer | null>; stubs: number } | null> {
    const [loads] = await anchorSiteFunctions(mod, table, [SSL_LIB_ANCHOR]);
    if (loads.length === 0) return null;
    const out: SiteCollector = { sites: [], bodies: new Map() };
    const stubs = new Map<number, number>();
    for (const { at, fn } of loads) {
        const from = at.sub(REASON_WINDOW_BEFORE * 4);
        // The shorter read is the original window, kept for sites at the very end of a mapping.
        const words = readWords(from, LOAD_WINDOW_WORDS) ??
                      readWords(from, REASON_WINDOW_BEFORE + REASON_WINDOW_AFTER + 1);
        const decoded = words ? decodeFileLoad(words, REASON_WINDOW_BEFORE) : null;
        if (decoded?.kind === "stub") stubs.set(offsetOf(mod, at), decoded.fileReg);
        else if (decoded?.kind === "site") addSite(mod, out, fn, decoded.reason);
    }
    if (needsStubCallerScan(reasonsByFunction(out.sites), stubs.size)) await addStubCallerSites(mod, table, stubs, out);
    return { ...out, stubs: stubs.size };
}

/** Function bodies (up to MAX_BODY_BYTES), each read once per locate call. */
type BodyReader = (func: number) => FunctionBody;

function bodyReader(mod: Module, ends: Map<number, NativePointer | null>): BodyReader {
    const cache = new Map<number, FunctionBody>();
    return (func) => {
        let body = cache.get(func);
        if (body === undefined) {
            const start = mod.base.add(func), end = ends.get(func) ?? null;
            const size = Math.min(end ? end.sub(start).toInt32() : MAX_BODY_BYTES, MAX_BODY_BYTES);
            body = { func, words: readWords(start, Math.max(0, size >> 2)) ?? [] };
            cache.set(func, body);
        }
        return body;
    };
}

/** The peek-shaped functions with their direct callees. */
function peekShapedCalls(groups: Map<number, Set<number>>, body: BodyReader): FunctionCalls[] {
    return peekShapedFunctions(groups).map((func) => ({ func, callees: directCallees(body(func)) }));
}

/** SSL_read from the error-site groups (see resolveSslRead), or null. */
function locateSslRead(mod: Module, table: FunctionBoundsSource, groups: Map<number, Set<number>>,
                       readImpl: number, body: BodyReader, peekShaped: FunctionCalls[]): number | null {
    const funcs = [...groups.keys()];
    const lo = Math.min(...funcs), hi = Math.max(...funcs);
    return resolveSslRead(peekShaped, readImpl, (peek) => wrappersOf(mod, table, peek, lo, hi),
                          (func) => copyVerdict(body(func).words, func, readImpl));
}

const offsetLabel = (off: number | null) => off === null ? "?" : "+0x" + off.toString(16);

/**
 * Locate SSL_read/SSL_write in `mod` (arm64 only). Never throws; returns null
 * when the anchor is missing.
 */
export async function locateBoringSslPlaintextApi(mod: Module): Promise<LocatedPlaintextApi | null> {
    if (Process.arch !== "arm64") return null;
    // FDE bounds where .eh_frame covers the site; landing-pad bounds elsewhere.
    const table = functionBoundsFor(mod);
    const found = await sslLibErrorSites(mod, table);
    if (!found) {
        devlog(`[BoringSSL plaintext] ${mod.name}: no BoringSSL ssl_lib.cc anchor string`);
        return null;
    }
    const groups = reasonsByFunction(found.sites);
    const sslWrite = pickSslWrite(groups);
    const body = bodyReader(mod, found.bodies);
    const peekShaped = peekShapedCalls(groups, body);
    const readImpl = chooseSslReadImpl(groups, peekShaped);
    const located = readImpl === null
        ? pickSslReadWithoutImpl(groups, found.stubs)
        : locateSslRead(mod, table, groups, readImpl, body, peekShaped);
    // ssl_read_impl inlined into SSL_read and SSL_peek alike: the shared-copy consumer.
    const picked = located ?? pickConsumingReader(inlinedReadShapedFunctions(groups).map(body));
    // Only a wrapper pick can land on SSL_write.
    const sslRead = picked === sslWrite ? null : picked;
    devlog(`[BoringSSL plaintext] ${mod.name}: ${found.sites.length} ssl_lib.cc error sites in ${groups.size} functions ` +
           `(${found.stubs} outlined stubs); ` +
           `SSL_write=${offsetLabel(sslWrite)} ssl_read_impl=${offsetLabel(readImpl)} SSL_read=${offsetLabel(sslRead)}`);
    return {
        sslRead: sslRead === null ? null : mod.base.add(sslRead),
        sslWrite: sslWrite === null ? null : mod.base.add(sslWrite),
    };
}

export function describeLocated(mod: Module, api: LocatedPlaintextApi): string {
    const at = (p: NativePointer | null) => moduleOffsetLabel(mod, p, "not found");
    return `SSL_read ${at(api.sslRead)}, SSL_write ${at(api.sslWrite)}`;
}
