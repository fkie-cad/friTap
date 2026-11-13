import { toHexString } from "../util/hex.js";
import { devlog_debug } from "../util/log.js";
import { LruMap } from "./lru.js";
import { setKeylogSslObserver } from "./keylog_ssl_observer.js";
import { MIN_VALID_S3_PTR, S3_CANDIDATE_OFFSETS, SSL3_RANDOM_SIZE, isMostlyZero } from "./ssl_struct_walk.js";

/*
 * Per-SSL* identity: client_random as the join key (P1, design B1).
 *
 * One cache, shared by every BoringSSL-family hook, that answers "which TLS
 * connection is this SSL*?" with the connection's client_random plus a
 * generation number that changes whenever the SSL* address is reused for a
 * different connection.
 *
 * Sources, most authoritative first:
 *   1. noteSslClientRandom() -- a keylog line carried this cr for this SSL*.
 *      Validates (or refutes) the module's layout, and learns one by overlap.
 *   2. readSslClientRandom() -- the hot path: cache hit check, then a read
 *      through the module's layout ({s3Off, crOff}), then an optional
 *      SSL_get_client_random-style export.
 *
 * Rules:
 *   - Layouts are PER MODULE. A BoringSSL layout must never be applied to an
 *     OpenSSL (or any other) module whose ssl_st differs.
 *   - Never negative-cache. "" and mostly-zero 32 bytes (the SSL* before its
 *     ClientHello) mean "unknown", and the next call reads again.
 *   - Trust: "learned" layouts are validated by construction; a "decoded"
 *     layout (from the target's own ssl_log_secret, >=2 agreeing labels) is
 *     usable at once; a "stock" guess only after 3 distinct plausible SSL*.
 *     Every layout read still passes the plausibility guard (s3 readable, not
 *     mostly zero, enough distinct byte values), and a keylog mismatch drops it.
 *   - Every native read can fault; the memory reader turns a fault into null.
 *   - Frida memory access is injectable (setSslMemoryReader) so this module is
 *     testable under Node with fake memory.
 */

export interface SslLayout {
    s3Off: number;
    crOff: number;
    source: "decoded" | "learned" | "stock";
    validated: boolean;
}

export interface SslIdentity {
    cr: string;
    generation: number;
}

/** Native memory access used by this module. Every method returns null on a fault. */
export interface SslMemoryReader {
    /** The pointer stored at base+offset, or null (fault, NULL, implausibly low). */
    readPointer(base: NativePointer, offset: number): NativePointer | null;
    /** `length` bytes at base+offset, or null on a fault. */
    readBytes(base: NativePointer, offset: number, length: number): Uint8Array | null;
    /** The u64 at base+offset (the cache-hit anchor check: no buffer, no string), or null on a fault. */
    readU64(base: NativePointer, offset: number): UInt64 | null;
}

export const SSL_IDENTITY_MAX = 4096;
/** Retired (freed) generations remembered for peekSslGeneration(); only the SSL_free window needs them. */
export const RETIRED_GENERATION_MAX = 256;
/**
 * A STOCK layout becomes usable after this many distinct plausible SSL*. A
 * decoded layout is usable at once (see isSslLayoutUsable).
 */
export const LAYOUT_USABLE_AFTER_DISTINCT_SSL = 3;
/** ssl->s3 slots probed by overlap learning (ssl_struct_walk's probe set). */
export const OVERLAP_S3_OFFSETS: readonly number[] = S3_CANDIDATE_OFFSETS;
export const OVERLAP_CR_OFFSET_MIN = 0x10;
export const OVERLAP_CR_OFFSET_MAX = 0x100;
export const OVERLAP_CR_OFFSET_STEP = 8;
/** Overlap learning is ~125 reads; stop retrying a module that never matches (e.g. OpenSSL). */
export const MAX_FAILED_OVERLAP_ATTEMPTS_PER_MODULE = 16;
/**
 * Low-entropy reject for every layout read: a real client_random is 32 random
 * bytes, so it shows at least this many distinct byte values.
 *
 * Why 16: for 32 uniform bytes over 256 values the expected distinct count is
 * 256 * (1 - (255/256)^32) ~= 30.2. P(distinct < 16) ~= 3.2e-17 (exact
 * Stirling-number sum), and even if 4 bytes were a gmt_unix_time prefix, 28
 * random bytes give P(< 16) ~= 1.2e-12 -- a false reject is negligible. What it
 * does reject when a layout points at the wrong field: repeated patterns,
 * small-int / flag structs, ASCII text and 0xff/0x00 fills (mostly-zero is
 * already rejected separately).
 */
export const MIN_DISTINCT_CR_BYTE_VALUES = 16;
const CLIENT_RANDOM_HEX_RE = /^[0-9a-f]{64}$/;

// ---------------------------------------------------------------------------
// Memory reader (injectable)
// ---------------------------------------------------------------------------

/** Default reader over Frida NativePointer methods (not the removed Memory.read* helpers). */
export const fridaSslMemoryReader: SslMemoryReader = {
    readPointer(base: NativePointer, offset: number): NativePointer | null {
        try {
            const value = base.add(offset).readPointer();
            if (value.isNull() || value.compare(MIN_VALID_S3_PTR) < 0) return null;
            return value;
        } catch (_) {
            return null;
        }
    },
    readBytes(base: NativePointer, offset: number, length: number): Uint8Array | null {
        try {
            const buf = base.add(offset).readByteArray(length);
            return buf ? new Uint8Array(buf as ArrayBuffer) : null;
        } catch (_) {
            return null;
        }
    },
    readU64(base: NativePointer, offset: number): UInt64 | null {
        try {
            return base.add(offset).readU64();
        } catch (_) {
            return null;
        }
    },
};

let memoryReader: SslMemoryReader = fridaSslMemoryReader;

/** Swap the memory reader (tests inject fake memory). Pass null to restore Frida's. */
export function setSslMemoryReader(reader: SslMemoryReader | null): void {
    memoryReader = reader ?? fridaSslMemoryReader;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/** Where a cached cr was read from, so a later call can cheaply re-check it. */
interface IdentityAnchor {
    s3Off: number;
    crOff: number;
    s3: NativePointer;
    /** First 8 bytes of the cr: the hit check is one readU64 + equals, never a buffer or string. */
    head: UInt64;
}

/**
 * Where a cached cr came from. Decides whether an ANCHORLESS cr may be served:
 * a "note" (keylog / probe) is replaced by the next handshake's note on the same
 * SSL*, an "export" result has nothing that would ever replace it, so it is
 * never served from the cache (see cachedCr).
 */
type IdentitySource = "layout" | "note" | "export";

/**
 * Everything known about one SSL* address. `generation` exists before the cr is
 * known; `cr` is "" while unknown (then `anchor` is null).
 */
interface SslEntry {
    generation: number;
    cr: string;
    anchor: IdentityAnchor | null;
    source?: IdentitySource;
}

/** A layout locator was started for the module ("pending") and possibly finished ("settled"). */
type LayoutLocatorState = "pending" | "settled";

interface ModuleLayoutState {
    layout: SslLayout;
    plausibleSsl: Set<string>;
}

let entryBySsl = new LruMap<string, SslEntry>(SSL_IDENTITY_MAX);
/**
 * Generation an SSL* had when forgetSslIdentity() dropped it: the SSL_free hooks
 * run in attach order, so a later SSL_free consumer (sdk_backtrace's forgetSsl)
 * can still name the freed connection through peekSslGeneration().
 */
let retiredGenerationBySsl = new LruMap<string, number>(RETIRED_GENERATION_MAX);
const layoutByModule = new Map<string, ModuleLayoutState>();
const failedOverlapAttempts = new Map<string, number>();
/** Modules a layout locator was ever started for, and whether it has settled. */
const layoutLocatorByModule = new Map<string, LayoutLocatorState>();
/** Modules whose client_random miss was already reported (the observer decides once per module). */
const missReportedModules = new Set<string>();
/** Told (once per module, see notifyClientRandomMiss) that a lookup returned no client_random. */
let clientRandomMissObserver: ((module: string) => void) | null = null;
let generationCounter = 0;

/** Test hook: forget every identity, generation, layout and counter. */
export function resetSslIdentityState(): void {
    entryBySsl = new LruMap<string, SslEntry>(SSL_IDENTITY_MAX);
    retiredGenerationBySsl = new LruMap<string, number>(RETIRED_GENERATION_MAX);
    layoutByModule.clear();
    failedOverlapAttempts.clear();
    layoutLocatorByModule.clear();
    missReportedModules.clear();
    generationCounter = 0;
}

/** Number of cached SSL* entries (identities and generation-only; bounded by SSL_IDENTITY_MAX). */
export function sslIdentityCacheSize(): number {
    return entryBySsl.size;
}

// ---------------------------------------------------------------------------
// Small pure helpers
// ---------------------------------------------------------------------------

function sslKey(ssl: NativePointer): string {
    return ssl.toString();
}

/** Lower-cased cr when it is a usable 32-byte client_random, else "". */
export function normalizeClientRandom(crHex: string | null | undefined): string {
    if (!crHex) return "";
    const cr = crHex.trim().toLowerCase();
    if (!CLIENT_RANDOM_HEX_RE.test(cr)) return "";
    return rejectMostlyZeroClientRandom(cr);
}

/** `cr` (already lower-case 64-hex) unless it is mostly zero (the SSL* before its ClientHello), else "". */
function rejectMostlyZeroClientRandom(cr: string): string {
    return isMostlyZero(hexToBytes(cr)) ? "" : cr;
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
}

/** Number of distinct byte values in `bytes`. */
export function distinctByteValues(bytes: Uint8Array): number {
    const seen = new Set<number>();
    for (let i = 0; i < bytes.length; i++) seen.add(bytes[i]);
    return seen.size;
}

/** True when `bytes` has the spread of a random value (MIN_DISTINCT_CR_BYTE_VALUES). */
export function looksLikeRandomBytes(bytes: Uint8Array): boolean {
    return distinctByteValues(bytes) >= MIN_DISTINCT_CR_BYTE_VALUES;
}

/** True when `bytes` can be a client_random: 32 bytes, not mostly zero, random-looking. */
function isPlausibleCrBytes(bytes: Uint8Array | null): bytes is Uint8Array {
    return bytes !== null && bytes.length === SSL3_RANDOM_SIZE && !isMostlyZero(bytes) && looksLikeRandomBytes(bytes);
}

function sameOffsets(a: SslLayout, b: SslLayout): boolean {
    return a.s3Off === b.s3Off && a.crOff === b.crOff;
}

// ---------------------------------------------------------------------------
// Layouts (per module) and their validation state (design B2)
// ---------------------------------------------------------------------------

/**
 * Install `layout` for `module`. A validated layout is never replaced by an
 * unvalidated one with different offsets (a late decoder result must not
 * override a layout a keylog already confirmed). Returns true when installed.
 */
export function setSslLayout(module: string, layout: SslLayout): boolean {
    const current = layoutByModule.get(module);
    if (current && current.layout.validated && !layout.validated && !sameOffsets(current.layout, layout)) {
        devlog_debug(`[ssl-identity] kept validated layout for ${module}; ignored ${layout.source}`);
        return false;
    }
    // Same offsets as an already-validated layout (e.g. a decoded layout arriving
    // after a keylog confirmed the stock guess): keep the validation.
    const keepsValidation = current !== undefined && current.layout.validated && sameOffsets(current.layout, layout);
    layoutByModule.set(module, { layout: { ...layout, validated: layout.validated || keepsValidation }, plausibleSsl: new Set() });
    devlog_debug(
        `[ssl-identity] layout ${module}: s3=0x${layout.s3Off.toString(16)} cr=0x${layout.crOff.toString(16)} ` +
        `(${layout.source}${layout.validated ? ", validated" : ""})`
    );
    return true;
}

export function sslLayoutFor(module: string): SslLayout | null {
    return layoutByModule.get(module)?.layout ?? null;
}

/** Drop the module's layout (used on a keylog mismatch). */
export function clearSslLayout(module: string): void {
    layoutByModule.delete(module);
}

/** A layout locator for `module` was started; its layout may still arrive. */
export function markLayoutLocatorStarted(module: string): void {
    layoutLocatorByModule.set(module, "pending");
}

/** True once any layout locator was started for `module` (settled or not). */
export function hasLayoutLocatorStarted(module: string): boolean {
    return layoutLocatorByModule.has(module);
}

/** The module's layout locator finished (success or failure): no layout will arrive from it. */
export function markLayoutLocatorSettled(module: string): void {
    if (layoutLocatorByModule.has(module)) layoutLocatorByModule.set(module, "settled");
}

/**
 * True unless a layout locator for `module` is still running. A module whose
 * locator was never started is settled: nothing will ever install a layout for it.
 */
export function isLayoutLocatorSettled(module: string): boolean {
    return layoutLocatorByModule.get(module) !== "pending";
}

/**
 * True once a layout may be used to answer reads: validated, decoded from the
 * target's own code, or (a stock guess) seen plausible on enough distinct SSL*.
 * Reads through a usable-but-unvalidated layout still pass the per-read guard.
 */
export function isSslLayoutUsable(module: string): boolean {
    const state = layoutByModule.get(module);
    if (!state) return false;
    if (state.layout.validated || isTrustedWithoutConfirmation(state.layout)) return true;
    return state.plausibleSsl.size >= LAYOUT_USABLE_AFTER_DISTINCT_SSL;
}

/**
 * A decoded layout comes from the module's own ssl_log_secret instructions, and
 * the locator only accepts a candidate >=2 keylog labels agree on: it needs no
 * distinct-SSL* warm-up (a one-connection app would otherwise never use it).
 */
function isTrustedWithoutConfirmation(layout: SslLayout): boolean {
    return layout.source === "decoded";
}

function countPlausibleRead(state: ModuleLayoutState, ssl: NativePointer): void {
    if (state.plausibleSsl.size < LAYOUT_USABLE_AFTER_DISTINCT_SSL) state.plausibleSsl.add(sslKey(ssl));
}

function markLayoutValidated(module: string): void {
    const state = layoutByModule.get(module);
    if (state && !state.layout.validated) {
        state.layout.validated = true;
        devlog_debug(`[ssl-identity] layout ${module} validated by keylog`);
    }
}

// ---------------------------------------------------------------------------
// Reading through a layout
// ---------------------------------------------------------------------------

/** Plausible client_random bytes behind {s3Off, crOff}, with the s3 they were read from. */
interface PlausibleLayoutRead {
    s3Off: number;
    crOff: number;
    s3: NativePointer;
    bytes: Uint8Array;
}

/** Read the raw client_random bytes via {s3Off, crOff}; null unless plausible. Encodes nothing. */
function readPlausibleCrBytes(ssl: NativePointer, s3Off: number, crOff: number): PlausibleLayoutRead | null {
    const s3 = memoryReader.readPointer(ssl, s3Off);
    if (!s3) return null;
    const bytes = memoryReader.readBytes(s3, crOff, SSL3_RANDOM_SIZE);
    return isPlausibleCrBytes(bytes) ? { s3Off, crOff, s3, bytes } : null;
}

/** Hex-encode a plausible read and anchor it (s3 + the cr's first u64); null on a fault. */
function identityFromRead(read: PlausibleLayoutRead): { cr: string; anchor: IdentityAnchor } | null {
    const head = memoryReader.readU64(read.s3, read.crOff);
    if (head === null) return null;
    return { cr: toHexString(read.bytes), anchor: { s3Off: read.s3Off, crOff: read.crOff, s3: read.s3, head } };
}

/** Read client_random via {s3Off, crOff}. Returns the cr and its anchor, or null. */
function readThroughLayout(
    ssl: NativePointer,
    s3Off: number,
    crOff: number,
): { cr: string; anchor: IdentityAnchor } | null {
    const read = readPlausibleCrBytes(ssl, s3Off, crOff);
    return read ? identityFromRead(read) : null;
}

/** Cheap re-check (2 reads, no allocation): same s3 pointer and same first 8 bytes of cr. */
function anchorStillHolds(ssl: NativePointer, anchor: IdentityAnchor): boolean {
    const s3 = memoryReader.readPointer(ssl, anchor.s3Off);
    if (!s3 || !s3.equals(anchor.s3)) return false;
    const head = memoryReader.readU64(s3, anchor.crOff);
    return head !== null && head.equals(anchor.head);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Identity cache + generations
// ---------------------------------------------------------------------------

function nextGeneration(): number {
    generationCounter += 1;
    return generationCounter;
}

/** Store cr for ssl; a cr different from the last one seen on this SSL* starts a new generation. */
function recordIdentity(ssl: NativePointer, cr: string, anchor: IdentityAnchor | null, source: IdentitySource): void {
    const key = sslKey(ssl);
    const entry = entryBySsl.get(key);
    if (!entry) {
        entryBySsl.set(key, { generation: nextGeneration(), cr, anchor, source });
    } else if (entry.cr !== "" && entry.cr !== cr) {
        entryBySsl.set(key, { generation: nextGeneration(), cr, anchor, source });
        devlog_debug(`[ssl-identity] ${key} reused for a new connection (generation ${generationCounter})`);
    } else {
        entry.cr = cr;
        entry.anchor = anchor;
        entry.source = source;
    }
}

/** The cached cr if its anchor still holds; a stale cr is dropped. Anchorless: see cachedCr. */
function verifiedCachedCr(ssl: NativePointer): string {
    return cachedCr(ssl, true);
}

/**
 * The cached cr of `ssl`, or "". An anchored cr is re-checked (a stale one starts
 * a new generation). An ANCHORLESS cr cannot be re-checked, so a reused SSL*
 * address would keep it: an export-derived one is never served (the export is
 * asked again per record), a noted one only when `allowAnchorlessNote` (the
 * next handshake's note on the same SSL* replaces it).
 */
function cachedCr(ssl: NativePointer, allowAnchorlessNote: boolean): string {
    const key = sslKey(ssl);
    const entry = entryBySsl.get(key);
    if (!entry || entry.cr === "") return "";
    if (entry.anchor === null) return allowAnchorlessNote && entry.source === "note" ? entry.cr : "";
    if (anchorStillHolds(ssl, entry.anchor)) return entry.cr;
    startNewGeneration(key);
    return "";
}

/** The SSL* address now holds a different connection whose cr is not known yet. */
function startNewGeneration(key: string): void {
    entryBySsl.set(key, { generation: nextGeneration(), cr: "", anchor: null });
    devlog_debug(`[ssl-identity] ${key} anchor changed (generation ${generationCounter})`);
}

/** Cached identity of an SSL*, re-checked against its anchor; null when unknown. */
export function sslIdentity(ssl: NativePointer): SslIdentity | null {
    if (!ssl || ssl.isNull()) return null;
    const cr = verifiedCachedCr(ssl);
    if (!cr) return null;
    return { cr, generation: sslGeneration(ssl) };
}

/**
 * Generation of an SSL*. Exists before the cr is known (a caller stack captured
 * before the ClientHello keeps its generation once the cr arrives); changes on
 * forgetSslIdentity() and when a different cr is seen on the same address.
 */
export function sslGeneration(ssl: NativePointer): number {
    const key = sslKey(ssl);
    const entry = entryBySsl.get(key);
    if (entry) return entry.generation;
    const generation = nextGeneration();
    entryBySsl.set(key, { generation, cr: "", anchor: null });
    return generation;
}

/**
 * Generation of an SSL* WITHOUT creating one: the live entry's, else the one
 * forgetSslIdentity() just retired (so every SSL_free consumer names the freed
 * connection whatever the hook order), else null.
 */
export function peekSslGeneration(ssl: NativePointer): number | null {
    const key = sslKey(ssl);
    return entryBySsl.get(key)?.generation ?? retiredGenerationBySsl.get(key) ?? null;
}

/** SSL_free: forget the identity; the next sight of this address gets a new generation. */
export function forgetSslIdentity(ssl: NativePointer): void {
    const key = sslKey(ssl);
    const entry = entryBySsl.get(key);
    if (entry) retiredGenerationBySsl.set(key, entry.generation);
    entryBySsl.delete(key);
}

// ---------------------------------------------------------------------------
// Hot path
// ---------------------------------------------------------------------------

/** Read through the module's layout; plausibility and usability are checked before any hex encode. */
function readViaModuleLayout(ssl: NativePointer, module: string): string {
    const state = layoutByModule.get(module);
    if (!state) return "";
    const read = readPlausibleCrBytes(ssl, state.layout.s3Off, state.layout.crOff);
    if (!read) return "";
    countPlausibleRead(state, ssl);
    if (!isSslLayoutUsable(module)) return "";
    const identity = identityFromRead(read);
    if (!identity) return "";
    recordIdentity(ssl, identity.cr, identity.anchor, "layout");
    return identity.cr;
}

function readViaExport(ssl: NativePointer, exportFn?: (ssl: NativePointer) => string): string {
    if (!exportFn) return "";
    let cr = "";
    try {
        cr = normalizeClientRandom(exportFn(ssl));
    } catch (_) {
        return "";
    }
    // The export may itself have noted this cr (with a layout anchor); keep that anchor.
    // Recorded for the generation only: an anchorless export cr is never served from
    // the cache (cachedCr), so a reused SSL* address re-reads its new cr here.
    if (cr && entryBySsl.get(sslKey(ssl))?.cr !== cr) recordIdentity(ssl, cr, null, "export");
    return cr;
}

/**
 * client_random of `ssl` (lower-case hex), or "" when unknown. Order: verified
 * cache -> the module's layout -> `exportFn` (e.g. SSL_get_client_random).
 * With an export, an anchorless noted cr is only the last resort: the export is
 * asked first, as it reflects a reused SSL* address and the note may not.
 * A miss on a module no layout locator was started for is reported to the
 * miss observer (ssl_layout_autolocate.ts may then start one).
 */
export function readSslClientRandom(
    ssl: NativePointer,
    module: string,
    exportFn?: (ssl: NativePointer) => string,
): string {
    if (!ssl || ssl.isNull()) return "";
    const hasExport = exportFn !== undefined;
    const cr = cachedCr(ssl, !hasExport) || readViaModuleLayout(ssl, module) || readViaExport(ssl, exportFn)
        || (hasExport ? cachedCr(ssl, true) : "");
    if (!cr) notifyClientRandomMiss(module);
    return cr;
}

/** Register (or with null, clear) the observer told about client_random misses. */
export function setClientRandomMissObserver(observer: ((module: string) => void) | null): void {
    clientRandomMissObserver = observer;
}

/**
 * Reports a module's first miss only: the observer decides once per module, so
 * every later miss (gate-rejected, or a locator already started) costs one Set
 * lookup and no call. Never throws.
 */
function notifyClientRandomMiss(module: string): void {
    if (!clientRandomMissObserver || !module || missReportedModules.has(module)) return;
    missReportedModules.add(module);
    if (layoutLocatorByModule.has(module)) return;
    try {
        clientRandomMissObserver(module);
    } catch (e) {
        devlog_debug(`[ssl-identity] client_random miss observer failed: ${e}`);
    }
}

// ---------------------------------------------------------------------------
// Authoritative notes (keylog) + overlap learning
// ---------------------------------------------------------------------------

/**
 * Find the unique {s3Off, crOff} at which `crHex` sits behind `ssl`:
 * s3Off in OVERLAP_S3_OFFSETS x crOff in [0x10, 0x100] step 8, exact 32-byte
 * match. Returns null when nothing or more than one pair matches.
 */
export function learnLayoutByOverlap(
    ssl: NativePointer,
    crHex: string,
    probe: SslMemoryReader = memoryReader,
): SslLayout | null {
    const cr = normalizeClientRandom(crHex);
    if (!cr || !ssl || ssl.isNull()) return null;
    const matches = findOverlapMatches(ssl, cr, probe);
    if (matches.length !== 1) return null;
    return { ...matches[0], source: "learned", validated: true };
}

function findOverlapMatches(ssl: NativePointer, cr: string, probe: SslMemoryReader): { s3Off: number; crOff: number }[] {
    const crBytes = hexToBytes(cr);
    const matches: { s3Off: number; crOff: number }[] = [];
    for (const s3Off of OVERLAP_S3_OFFSETS) {
        const s3 = probe.readPointer(ssl, s3Off);
        if (!s3) continue;
        for (let crOff = OVERLAP_CR_OFFSET_MIN; crOff <= OVERLAP_CR_OFFSET_MAX; crOff += OVERLAP_CR_OFFSET_STEP) {
            const bytes = probe.readBytes(s3, crOff, SSL3_RANDOM_SIZE);
            if (bytes && sameBytes(bytes, crBytes)) matches.push({ s3Off, crOff });
        }
    }
    return matches;
}

function tryLearnLayout(ssl: NativePointer, cr: string, module: string): void {
    const failures = failedOverlapAttempts.get(module) ?? 0;
    if (failures >= MAX_FAILED_OVERLAP_ATTEMPTS_PER_MODULE) return;
    const learned = learnLayoutByOverlap(ssl, cr);
    if (learned) {
        failedOverlapAttempts.delete(module);
        setSslLayout(module, learned);
    } else {
        failedOverlapAttempts.set(module, failures + 1);
    }
}

/**
 * Check the module's layout against an authoritative cr. Returns the anchor
 * when the layout agrees, null otherwise (after dropping a refuted layout and
 * attempting overlap learning).
 */
function reconcileLayoutWithNote(ssl: NativePointer, cr: string, module: string): IdentityAnchor | null {
    const layout = sslLayoutFor(module);
    if (layout) {
        const read = readThroughLayout(ssl, layout.s3Off, layout.crOff);
        if (read && read.cr === cr) {
            markLayoutValidated(module);
            return read.anchor;
        }
        devlog_debug(`[ssl-identity] keylog refuted ${layout.source} layout for ${module}; re-learning`);
        clearSslLayout(module);
    }
    tryLearnLayout(ssl, cr, module);
    const learned = sslLayoutFor(module);
    return learned ? readThroughLayout(ssl, learned.s3Off, learned.crOff)?.anchor ?? null : null;
}

/**
 * Authoritative: a keylog line carried `crHex` for `ssl`. Validates, refutes or
 * learns the module's layout, then caches the identity (a changed cr on the
 * same SSL* starts a new generation). Never throws.
 */
export function noteSslClientRandom(ssl: NativePointer, crHex: string, module?: string): void {
    noteClientRandom(ssl, crHex, module, normalizeClientRandom);
}

/**
 * The keylog observer: keylog_ssl_observer.ts already hands over a lower-case
 * 64-hex cr, so only the mostly-zero check is left to do.
 */
function noteKeylogClientRandom(ssl: NativePointer, crHex: string, module?: string): void {
    noteClientRandom(ssl, crHex, module, rejectMostlyZeroClientRandom);
}

function noteClientRandom(
    ssl: NativePointer,
    crHex: string,
    module: string | undefined,
    normalize: (crHex: string) => string,
): void {
    try {
        if (!ssl || ssl.isNull() || isAlreadyNotedOnValidatedLayout(ssl, crHex, module)) return;
        const cr = normalize(crHex);
        if (!cr) return;
        const anchor = module ? reconcileLayoutWithNote(ssl, cr, module) : null;
        // Anchorless (no layout): served until the next handshake's note on this SSL*
        // replaces it (recordIdentity starts a new generation on a different cr).
        recordIdentity(ssl, cr, anchor, "note");
    } catch (e) {
        devlog_debug(`[ssl-identity] noteSslClientRandom failed: ${e}`);
    }
}

/**
 * True when `ssl` is already cached, anchored, with exactly this cr and the
 * module's layout is validated: the note would change nothing (TLS 1.3 emits up
 * to five lines per connection), so the regex and the layout reconcile are skipped.
 * The cached cr is normalized, so an exact match also proves `crHex` is valid.
 */
function isAlreadyNotedOnValidatedLayout(ssl: NativePointer, crHex: string, module: string | undefined): boolean {
    if (!module) return false;
    const entry = entryBySsl.get(sslKey(ssl));
    if (!entry || entry.anchor === null || entry.cr !== crHex) return false;
    return sslLayoutFor(module)?.validated === true;
}

// sendKeylog(line, ssl, module) feeds every BoringSSL-family keylog line here
// (before the keylog_enabled gate). Registered on import because
// shared_structures.ts cannot import this module without an import cycle.
setKeylogSslObserver(noteKeylogClientRandom);
