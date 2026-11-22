// agent/tls/shared/boringssl_plaintext_resolver.ts
//
// Resolve SSL_read/SSL_write of a statically linked BoringSSL, cheapest source
// first, each function on its own: the user's --offsets, the learned-offset
// cache, then the ssl_lib.cc error-site locator (boringssl_plaintext_locator.ts).
// Modules that export the API are the export-based hookers' job; callers filter
// them with exportsSslRecordApi.

import { log, devlog_debug } from "../../util/log.js";
import { offsets } from "../../shared/shared_structures.js";
import { locateBoringSslPlaintextApi, LocatedPlaintextApi } from "./boringssl_plaintext_locator.js";
import { matchesCronetHookerPlaintextRow, plaintextLocatorRunsOn } from "./chromium_plaintext_coverage.js";
import { isAndroid } from "../../util/process_infos.js";
import {
    type PrologueHasher, PROLOGUE_HASH_BYTES, isHookableAddress, moduleBasename, sha256Prologue, verifiedLearnedAddress,
} from "../../shared/learned_module_cache.js";

export { PROLOGUE_HASH_BYTES, isHookableAddress, moduleBasename, sha256Prologue };
export type { PrologueHasher };

export type PlaintextFunction = "SSL_read" | "SSL_write";
export type PlaintextFunctionSource = "offsets" | "learned" | "locator";
/** "mixed" when SSL_read and SSL_write came from different sources. */
export type PlaintextApiSource = PlaintextFunctionSource | "mixed";

export interface ResolvedPlaintextApi extends LocatedPlaintextApi {
    source: PlaintextApiSource;
    sources: Record<PlaintextFunction, PlaintextFunctionSource | null>;
}

export type PlaintextModule = Pick<Module, "name" | "base" | "size" | "findExportByName">;

/** Learned-cache entry: module-relative RVAs plus the SHA-256 (hex) of each function's first 32 bytes. */
export interface LearnedPlaintextEntry {
    rvas: { SSL_read: number; SSL_write: number };
    prologueSha256: { SSL_read: string; SSL_write: string };
}

/** Where learned entries come from; filled by the host-side learned-offset cache. */
export interface LearnedPlaintextSource {
    lookup(mod: PlaintextModule): LearnedPlaintextEntry | null;
    /** Called once the resolver accepted (prologue-verified) `entry` for `mod`. */
    onAccepted?(mod: PlaintextModule, entry: LearnedPlaintextEntry): void;
}

export type LocatorResolvedListener = (mod: PlaintextModule, api: LocatedPlaintextApi, elapsedMs: number) => void;

export interface PlaintextResolverDeps {
    readOffsets: () => unknown;
    learned: LearnedPlaintextSource;
    hashPrologue: PrologueHasher;
    locate: (mod: PlaintextModule) => Promise<LocatedPlaintextApi | null>;
    onLocatorResolved: LocatorResolvedListener;
    locatorRuns: () => boolean;
    warn: (message: string) => void;
    now: () => number;
    arch: () => string;
    isAndroid: () => boolean;
}

export const BORINGSECRETHUNTER_DOCS = "docs/libraries/boringssl.md#boringsecrethunter";

const PLAINTEXT_FUNCTIONS: PlaintextFunction[] = ["SSL_read", "SSL_write"];
const API_FIELD: Record<PlaintextFunction, keyof LocatedPlaintextApi> = { SSL_read: "sslRead", SSL_write: "sslWrite" };

const NO_LEARNED_ENTRIES: LearnedPlaintextSource = { lookup: () => null };
const IGNORE_LOCATOR_RESULT: LocatorResolvedListener = () => {};

let learnedSource: LearnedPlaintextSource = NO_LEARNED_ENTRIES;
let locatorResolvedListener: LocatorResolvedListener = IGNORE_LOCATOR_RESULT;
const missNoticeShown = new Set<string>();

/** Plug in the learned-offset cache (null restores the no-op source). */
export function setLearnedPlaintextSource(source: LearnedPlaintextSource | null): void {
    learnedSource = source ?? NO_LEARNED_ENTRIES;
}

/** Observe locator hits, e.g. to report them for the learned-offset cache (null restores the no-op). */
export function setLocatorResolvedListener(listener: LocatorResolvedListener | null): void {
    locatorResolvedListener = listener ?? IGNORE_LOCATOR_RESULT;
}

/**
 * True when `mod` exports SSL_read or SSL_write: some libcronet builds do, and
 * their primary row hooks those exports, so callers must not resolve them here.
 */
export function exportsSslRecordApi(mod: Pick<Module, "findExportByName">): boolean {
    return mod.findExportByName("SSL_read") !== null || mod.findExportByName("SSL_write") !== null;
}

function hasAnyFunction(api: LocatedPlaintextApi | null): api is LocatedPlaintextApi {
    return api !== null && (api.sslRead !== null || api.sslWrite !== null);
}

function offsetAddress(mod: PlaintextModule, entry: any): NativePointer | null {
    if (!entry || entry.address === undefined || entry.address === null) return null;
    const address = ptr(entry.address);
    return entry.absolute ? address : mod.base.add(address);
}

/**
 * The `{<module basename>: {SSL_read, SSL_write}}` entry of the user's --offsets.
 * Read alongside resolveOffsets' offsetKey entries, which keep their meaning.
 */
export function plaintextApiFromOffsets(allOffsets: unknown, mod: PlaintextModule): LocatedPlaintextApi | null {
    if (!allOffsets || typeof allOffsets !== "object") return null;
    const entry = (allOffsets as any)[moduleBasename(mod.name)];
    if (!entry || typeof entry !== "object") return null;
    const api = { sslRead: offsetAddress(mod, entry.SSL_read), sslWrite: offsetAddress(mod, entry.SSL_write) };
    return hasAnyFunction(api) ? api : null;
}

/** True when module.base+rva lies in `mod` and its prologue hashes to `expectedSha256` (case-insensitive hex). */
export function prologueMatches(mod: PlaintextModule, rva: number, expectedSha256: string,
                                hashPrologue: PrologueHasher = sha256Prologue): boolean {
    return verifiedLearnedAddress(mod, rva, expectedSha256, hashPrologue) !== null;
}

/** The learned entry's API when both RVAs still have their recorded prologues; null otherwise. */
export function plaintextApiFromLearned(entry: LearnedPlaintextEntry | null, mod: PlaintextModule,
                                        hashPrologue: PrologueHasher = sha256Prologue): LocatedPlaintextApi | null {
    if (!entry) return null;
    const sslRead = verifiedLearnedAddress(mod, entry.rvas.SSL_read, entry.prologueSha256.SSL_read, hashPrologue);
    const sslWrite = verifiedLearnedAddress(mod, entry.rvas.SSL_write, entry.prologueSha256.SSL_write, hashPrologue);
    // A stale entry (rebuilt library) must not place hooks on arbitrary code.
    return sslRead !== null && sslWrite !== null ? { sslRead, sslWrite } : null;
}

function defaultDeps(): PlaintextResolverDeps {
    return {
        readOffsets: () => offsets,
        learned: learnedSource,
        hashPrologue: sha256Prologue,
        locate: (mod) => locateBoringSslPlaintextApi(mod as Module),
        onLocatorResolved: locatorResolvedListener,
        locatorRuns: () => plaintextLocatorRunsOn(),
        warn: log,
        now: () => Date.now(),
        arch: () => Process.arch,
        isAndroid,
    };
}

function noticeMissOnce(moduleName: string, deps: PlaintextResolverDeps): void {
    if (missNoticeShown.has(moduleName)) return;
    missNoticeShown.add(moduleName);
    if (!deps.locatorRuns()) {
        // Not a find-failure: the locator is arm64-only, so every module would miss here.
        devlog_debug(`[BoringSSL plaintext] ${moduleName}: not resolved; locator unavailable on ${Process.arch}`);
        return;
    }
    deps.warn(`[!] ${moduleName}: BoringSSL SSL_read/SSL_write not located; TCP TLS plaintext unavailable (keys only). ` +
         `Supply them via --offsets; see ${BORINGSECRETHUNTER_DOCS}`);
}

/** Per-function merge of the sources; a function keeps the first source that had it. */
class PlaintextApiMerge {
    readonly api: LocatedPlaintextApi = { sslRead: null, sslWrite: null };
    readonly sources: Record<PlaintextFunction, PlaintextFunctionSource | null> = { SSL_read: null, SSL_write: null };

    constructor(private readonly mod: PlaintextModule, private readonly deps: PlaintextResolverDeps) {}

    missing(): boolean {
        return PLAINTEXT_FUNCTIONS.some((fn) => this.api[API_FIELD[fn]] === null);
    }

    take(candidate: LocatedPlaintextApi | null, source: PlaintextFunctionSource): void {
        if (candidate === null) return;
        for (const fn of PLAINTEXT_FUNCTIONS) {
            const address = candidate[API_FIELD[fn]];
            if (this.api[API_FIELD[fn]] !== null || address === null || !this.hookable(fn, address, source)) continue;
            this.api[API_FIELD[fn]] = address;
            this.sources[fn] = source;
        }
    }

    private hookable(fn: PlaintextFunction, address: NativePointer, source: PlaintextFunctionSource): boolean {
        if (isHookableAddress(address, this.deps.arch())) return true;
        const reason = `${fn} at ${address} is an even (ARM-mode) address on 32-bit ARM; not hooked`;
        if (source === "offsets") {
            this.deps.warn(`[!] ${this.mod.name}: --offsets ${reason}. Pass the Thumb address (address|1).`);
        } else {
            devlog_debug(`[BoringSSL plaintext] ${this.mod.name}: ${source} ${reason}`);
        }
        return false;
    }

    result(): ResolvedPlaintextApi | null {
        if (!hasAnyFunction(this.api)) return null;
        const used = [...new Set(PLAINTEXT_FUNCTIONS.map((fn) => this.sources[fn]).filter((s) => s !== null))];
        const source: PlaintextApiSource = used.length === 1 ? used[0]! : "mixed";
        devlog_debug(`[BoringSSL plaintext] ${this.mod.name}: SSL_read via ${this.sources.SSL_read ?? "none"}, ` +
                     `SSL_write via ${this.sources.SSL_write ?? "none"}`);
        return { ...this.api, source, sources: { ...this.sources } };
    }
}

// A failing cache-hit listener must not turn an accepted entry into a miss.
function notifyLearnedAccepted(mod: PlaintextModule, entry: LearnedPlaintextEntry, deps: PlaintextResolverDeps): void {
    try {
        deps.learned.onAccepted?.(mod, entry);
    } catch (e) {
        devlog_debug(`[BoringSSL plaintext] ${mod.name}: learned-entry listener failed: ${e}`);
    }
}

function learnedApi(mod: PlaintextModule, deps: PlaintextResolverDeps): LocatedPlaintextApi | null {
    const entry = deps.learned.lookup(mod);
    const api = plaintextApiFromLearned(entry, mod, deps.hashPrologue);
    if (api !== null && entry !== null) notifyLearnedAccepted(mod, entry, deps);
    return api;
}

// A failing listener must not turn a located API into a miss.
function notifyLocatorResolved(listener: LocatorResolvedListener, mod: PlaintextModule,
                               api: LocatedPlaintextApi, elapsedMs: number): void {
    try {
        listener(mod, api, elapsedMs);
    } catch (e) {
        devlog_debug(`[BoringSSL plaintext] ${mod.name}: locator listener failed: ${e}`);
    }
}

async function locatorApi(mod: PlaintextModule, deps: PlaintextResolverDeps): Promise<LocatedPlaintextApi | null> {
    const startedAt = deps.now();
    const located = await deps.locate(mod);
    const elapsedMs = deps.now() - startedAt;
    devlog_debug(`[BoringSSL plaintext] ${mod.name}: locator finished in ${elapsedMs} ms`);
    if (!hasAnyFunction(located)) return null;
    notifyLocatorResolved(deps.onLocatorResolved, mod, located, elapsedMs);
    return located;
}

async function mergedApi(mod: PlaintextModule, deps: PlaintextResolverDeps): Promise<ResolvedPlaintextApi | null> {
    const merge = new PlaintextApiMerge(mod, deps);
    merge.take(plaintextApiFromOffsets(deps.readOffsets(), mod), "offsets");
    // Partial --offsets (e.g. only SSL_write) must not hide the other function's sources.
    if (merge.missing()) merge.take(learnedApi(mod, deps), "learned");
    if (merge.missing()) merge.take(await locatorApi(mod, deps), "locator");
    return merge.result();
}

/**
 * SSL_read/SSL_write of the BoringSSL in `mod`, or null (after a once-per-module
 * notice) when no source has them. Never throws.
 */
export async function resolveBoringSslPlaintext(mod: PlaintextModule,
                                                overrides: Partial<PlaintextResolverDeps> = {}):
        Promise<ResolvedPlaintextApi | null> {
    const deps = { ...defaultDeps(), ...overrides };
    try {
        const api = await mergedApi(mod, deps);
        if (api) return api;
    } catch (e) {
        devlog_debug(`[BoringSSL plaintext] ${mod.name}: resolver failed: ${e}`);
    }
    noticeMissOnce(mod.name, deps);
    return null;
}

/** True when a cheap source (--offsets or a prologue-verified learned entry) has a hookable `fn`. Side-effect free. */
function cheapSourceHas(mod: PlaintextModule, fn: PlaintextFunction, deps: PlaintextResolverDeps): boolean {
    const learned = plaintextApiFromLearned(deps.learned.lookup(mod), mod, deps.hashPrologue);
    return [plaintextApiFromOffsets(deps.readOffsets(), mod), learned].some((api) => {
        const address = api === null ? null : api[API_FIELD[fn]];
        return address !== null && isHookableAddress(address, deps.arch());
    });
}

/**
 * True when the supplementary "BoringSSL plaintext (Cronet)" or "(Signal)" row will
 * hook `fn` (default: either function) of `mod`. Mirrors those rows: Android only,
 * Cronet or libsignal_jni module name, no exported SSL_read/SSL_write, and the locator (arm64) or a
 * cheap source for the function. Lets the Cronet hooker skip a false notice.
 */
export function plaintextRowWillHandle(mod: PlaintextModule, fn?: PlaintextFunction,
                                       overrides: Partial<PlaintextResolverDeps> = {}): boolean {
    const deps = { ...defaultDeps(), ...overrides };
    try {
        if (!deps.isAndroid() || !matchesCronetHookerPlaintextRow(moduleBasename(mod.name))) return false;
        if (exportsSslRecordApi(mod)) return false;
        if (deps.locatorRuns()) return true;
        return (fn ? [fn] : PLAINTEXT_FUNCTIONS).some((f) => cheapSourceHas(mod, f, deps));
    } catch (e) {
        devlog_debug(`[BoringSSL plaintext] ${mod.name}: plaintextRowWillHandle failed: ${e}`);
        return false;
    }
}
