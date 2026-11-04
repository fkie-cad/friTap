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
//   SSL_read       : SSL_peek + consume. Either it calls SSL_peek as its first call
//                    (Chrome 133 libmonochrome) or SSL_peek is inlined into it, in which
//                    case it is the peek-shaped function with the larger call set
//                    (it also calls the buffer-consume helper).
// Function boundaries come from the module's .eh_frame_hdr search table, so a
// hook is only ever placed on a real function entry.
//
// Verified on Chrome 133.0.6943.137 libmonochrome_64.so (SSL_read +0x515113c,
// SSL_write +0x5151490) and on mainline Cronet's stable_cronet_libssl.so (the
// inlined-peek shape; checked against its exported SSL_read/SSL_write).

import { devlog } from "../../util/log.js";
import { anchorSiteFunctions, moduleOffsetLabel } from "../../shared/arm64_xref.js";
import { blTargetOffset, movzW } from "../../shared/arm64.js";
import { EhFrameFunctionTable, ehFrameTableFor } from "../../shared/eh_frame.js";

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

/** The unique function raising exactly UNINITIALIZED + SSL_HANDSHAKE_FAILURE (ssl_read_impl). */
export function pickSslReadImpl(groups: Map<number, Set<number>>): number | null {
    const R = SSL_REASON;
    return only(funcsWhere(groups, (r) =>
        r.size === 2 && r.has(R.UNINITIALIZED) && r.has(R.SSL_HANDSHAKE_FAILURE)));
}

/** Functions whose only ssl_lib.cc error is SHOULD_NOT_HAVE_BEEN_CALLED (SSL_peek-shaped). */
export function peekShapedFunctions(groups: Map<number, Set<number>>): number[] {
    return funcsWhere(groups, (r) => r.size === 1 && r.has(SSL_REASON.SHOULD_NOT_HAVE_BEEN_CALLED));
}

export interface FunctionCalls { func: number; callees: Set<number>; }

/**
 * SSL_read from the peek-shaped functions that call ssl_read_impl.
 *   one such function  -> it is SSL_peek; SSL_read is the unique wrapper whose
 *                         first call is SSL_peek (`wrappersOf`);
 *   two such functions -> SSL_peek was inlined into SSL_read; SSL_read is the
 *                         one whose callee set strictly contains the other's.
 */
export function resolveSslRead(
    peekShaped: FunctionCalls[], readImpl: number, wrappersOf: (peek: number) => number[],
): number | null {
    const readers = peekShaped.filter((f) => f.callees.has(readImpl));
    if (readers.length === 1) return only(wrappersOf(readers[0].func));
    if (readers.length === 2) {
        const [a, b] = readers;
        const contains = (x: Set<number>, y: Set<number>) => x.size > y.size && [...y].every((c) => x.has(c));
        if (contains(a.callees, b.callees)) return a.func;
        if (contains(b.callees, a.callees)) return b.func;
    }
    return null;
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

/** Direct call targets (module offsets) in [start, end). */
function calleesOf(mod: Module, start: NativePointer, end: NativePointer | null): Set<number> {
    const size = Math.min(end ? end.sub(start).toInt32() : MAX_BODY_BYTES, MAX_BODY_BYTES);
    const words = readWords(start, Math.max(0, size >> 2)) ?? new Uint32Array(0);
    const base = offsetOf(mod, start);
    const callees = new Set<number>();
    words.forEach((w, i) => {
        const t = blTargetOffset(base + i * 4, w);
        if (t !== null) callees.add(t);
    });
    return callees;
}

/** Functions near `around` whose FIRST call is a BL to `peek` (SSL_read wrapping SSL_peek). */
function wrappersOf(mod: Module, table: EhFrameFunctionTable, peek: number, lo: number, hi: number): number[] {
    const start = Math.max(0, lo - WRAPPER_SEARCH_MARGIN);
    const end = Math.min(hi + WRAPPER_SEARCH_MARGIN, mod.size);
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

/** Error sites (function + reason) of the ssl_lib.cc anchor's load sites, plus each function's end. */
async function sslLibErrorSites(mod: Module, table: EhFrameFunctionTable):
        Promise<{ sites: ErrorSite[]; bodies: Map<number, NativePointer | null> } | null> {
    const [loads] = await anchorSiteFunctions(mod, table, [SSL_LIB_ANCHOR]);
    if (loads.length === 0) return null;
    const sites: ErrorSite[] = [];
    const bodies = new Map<number, NativePointer | null>();
    for (const { at, fn } of loads) {
        const words = readWords(at.sub(REASON_WINDOW_BEFORE * 4), REASON_WINDOW_BEFORE + REASON_WINDOW_AFTER + 1);
        const reason = words ? decodeErrorReason(words, REASON_WINDOW_BEFORE) : null;
        if (reason === null || !fn) continue;
        const func = offsetOf(mod, fn.start);
        bodies.set(func, fn.end);
        sites.push({ func, reason });
    }
    return { sites, bodies };
}

/** SSL_read from the error-site groups (see resolveSslRead), or null. */
function locateSslRead(mod: Module, table: EhFrameFunctionTable, groups: Map<number, Set<number>>,
                       readImpl: number, bodies: Map<number, NativePointer | null>): number | null {
    const peekShaped = peekShapedFunctions(groups).map((func) => ({
        func, callees: calleesOf(mod, mod.base.add(func), bodies.get(func) ?? null),
    }));
    const funcs = [...groups.keys()];
    const lo = Math.min(...funcs), hi = Math.max(...funcs);
    return resolveSslRead(peekShaped, readImpl, (peek) => wrappersOf(mod, table, peek, lo, hi));
}

const offsetLabel = (off: number | null) => off === null ? "?" : "+0x" + off.toString(16);

/**
 * Locate SSL_read/SSL_write in `mod` (arm64 only). Never throws; returns null
 * when the anchor or the function table is missing.
 */
export async function locateBoringSslPlaintextApi(mod: Module): Promise<LocatedPlaintextApi | null> {
    if (Process.arch !== "arm64") return null;
    const table = ehFrameTableFor(mod);
    if (!table) {
        devlog(`[BoringSSL plaintext] ${mod.name}: no usable .eh_frame_hdr; cannot bound functions`);
        return null;
    }
    const found = await sslLibErrorSites(mod, table);
    if (!found) {
        devlog(`[BoringSSL plaintext] ${mod.name}: no BoringSSL ssl_lib.cc anchor string`);
        return null;
    }
    const groups = reasonsByFunction(found.sites);
    const sslWrite = pickSslWrite(groups);
    const readImpl = pickSslReadImpl(groups);
    const sslRead = readImpl === null ? null : locateSslRead(mod, table, groups, readImpl, found.bodies);
    devlog(`[BoringSSL plaintext] ${mod.name}: ${found.sites.length} ssl_lib.cc error sites in ${groups.size} functions; ` +
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
