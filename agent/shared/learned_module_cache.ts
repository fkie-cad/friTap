// agent/shared/learned_module_cache.ts
//
// Agent side of the host's generic learned-offsets cache (friTap/learned_offsets.py).
// config_batch.learned_plaintext carries, per `build_id|size|arch`, named function
// RVAs (each guarded by a prologue hash) and named layout values. Consumers ask
// for one item by name and report what their own scans found; reports are
// coalesced into one `module_offsets_learned` message per module burst.
// Tree-neutral: used by agent/tls, agent/legacy and agent/quic alike.

import { devlog_debug, _isShuttingDownNow } from "../util/log.js";
import { moduleGnuBuildId } from "./elf_build_id.js";
import { moduleMachOUuid } from "./macho_header.js";
import { modulePeIdentity } from "./pe_header.js";
import { ModuleOffsetsLearnedPayload, sendModuleOffsetsLearned } from "./shared_structures.js";
import type { LearnedFunction } from "../schemas/messages.js";
import type { ScanStatus } from "./arm64_xref.js";
import { type CacheModule, mappingKey, memoizePerMapping } from "./module_mapping.js";

export const PROLOGUE_HASH_BYTES = 32;
// Frida's Interceptor rewrites at most 16 bytes on arm64, 10 on Thumb and up to
// 30 on x86 (16-byte redirect plus nop-padded relocated instructions), so a
// window from byte 32 hashes the same whether or not the function is hooked.
export const FUNCTION_HASH_OFFSET = 32;
export const FUNCTION_HASH_BYTES = 32;
/** Layout value of a miss marker: "a clean scan of this build found nothing". */
export const MISS_MARKER = 1;
/** Largest fingerprint marker; stays inside the host's layout bound (LAYOUT_MAX). */
export const MISS_FINGERPRINT_MAX = 0xFFFFF;
const FNV_OFFSET_BASIS = 0x811c9dc5;
const FNV_PRIME = 0x01000193;
/** Reports within this window after the first one are sent as one message per module. */
const REPORT_COALESCE_MS = 50;
const LAYOUT_MIN = -0x10000;
const LAYOUT_MAX = 0x100000;

// Same limits as the host's validator, so nothing is sent that it would drop.
const ITEM_NAME_RE = /^[a-z0-9_]+(\.[A-Za-z0-9_]+){1,3}$/;
const MAX_ITEM_NAME_LENGTH = 128;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const LAYOUT_RVA_SUFFIX = "Rva";
/** Exclusive bound of `...Rva` layout values (host: LAYOUT_RVA_MAX). */
export const LAYOUT_RVA_MAX = 2 ** 32;

export interface ModuleIdentity {
    buildId: string;
    size: number;
    arch: string;
}

export interface LearnedItems {
    functions?: Record<string, NativePointer>;
    layout?: Record<string, number>;
}

export type PrologueHasher = (address: NativePointer) => string | null;

export interface LearnedModuleCacheDeps {
    identify: (mod: CacheModule) => ModuleIdentity | null;
    hashPrologue: PrologueHasher;
    emit: (payload: ModuleOffsetsLearnedPayload) => void;
    schedule: (flush: () => void) => void;
}

export type ItemField = "functions" | "layout";

// ---- shared helpers (also used by the plaintext-RVA cache) -----------------

export function learnedKey(identity: ModuleIdentity): string {
    return `${identity.buildId}|${identity.size}|${identity.arch}`;
}

export function moduleBasename(name: string): string {
    return name.split(/[\\/]/).pop() ?? name;
}

// Parsing the headers once per mapping is enough: a build id cannot change in place.
const buildIdByMapping = new Map<string, string | null>();

/**
 * build id (ELF GNU build id, else Mach-O LC_UUID, else PE CodeView GUID+age or
 * TimeDateStamp+SizeOfImage), size and Process.arch of `mod`, or null without one.
 */
export function identifyModule(mod: CacheModule): ModuleIdentity | null {
    const buildId = memoizePerMapping(buildIdByMapping, mod,
        () => moduleGnuBuildId(mod.base) ?? moduleMachOUuid(mod) ?? modulePeIdentity(mod));
    return buildId === null ? null : { buildId, size: mod.size, arch: Process.arch };
}

/** Frida's Checksum (hex SHA-256) over `length` bytes at `address`+`offset`, or null when unreadable. */
function sha256Bytes(address: NativePointer, length: number, offset: number = 0): string | null {
    try {
        if (typeof Checksum === "undefined") return null;
        const bytes = address.add(offset).readByteArray(length);
        return bytes === null ? null : Checksum.compute("sha256", bytes);
    } catch (_e) {
        return null;
    }
}

/** SHA-256 over the first PROLOGUE_HASH_BYTES at `address` (the SSL_read/SSL_write pair format). */
export function sha256Prologue(address: NativePointer): string | null {
    return sha256Bytes(address, PROLOGUE_HASH_BYTES);
}

/** SHA-256 over the code window Frida's Interceptor never patches (`functions` items). */
export function sha256FunctionBody(address: NativePointer): string | null {
    return sha256Bytes(address, FUNCTION_HASH_BYTES, FUNCTION_HASH_OFFSET);
}

/**
 * False for an even address on 32-bit ARM: BoringSSL there is Thumb-2 code, and
 * attaching at an even address would patch it in ARM mode (corrupt prologue, crash).
 */
export function isHookableAddress(address: NativePointer, arch: string): boolean {
    return arch !== "arm" || !address.and(1).isNull();
}

export function isLearnedItemName(name: unknown): name is string {
    return typeof name === "string" && name.length <= MAX_ITEM_NAME_LENGTH && ITEM_NAME_RE.test(name);
}

export function isPlainObject(value: unknown): value is Record<string, any> {
    return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** A module-relative address inside a module of `size` bytes (host rule: 0 < rva < size). */
export function isRva(value: unknown, size: number): value is number {
    return typeof value === "number" && Number.isInteger(value) && value > 0 && value < size;
}

export function isSha256Hex(value: unknown): value is string {
    return typeof value === "string" && SHA256_RE.test(value);
}

/**
 * A `...Rva` layout value: 0 < v < 2**32, not bounded by Module.size, which on
 * macOS covers only __TEXT (vtables live in __DATA_CONST past it). Consumers
 * validate the hint live.
 */
export function isLayoutRva(value: unknown): value is number {
    return typeof value === "number" && Number.isInteger(value) && value > 0 && value < LAYOUT_RVA_MAX;
}

/** Host bounds: `...Rva` names per isLayoutRva, others LAYOUT_MIN..LAYOUT_MAX. */
export function isValidLayoutValue(name: string, value: unknown): value is number {
    if (name.endsWith(LAYOUT_RVA_SUFFIX)) return isLayoutRva(value);
    return typeof value === "number" && Number.isInteger(value) && value >= LAYOUT_MIN && value <= LAYOUT_MAX;
}

/** `address` relative to `mod`, or null when absent or outside a module of `size` bytes. */
export function rvaOf(mod: CacheModule, address: NativePointer | null, size: number): number | null {
    if (address === null) return null;
    try {
        const rva = Number(address.sub(mod.base).toString());
        return isRva(rva, size) ? rva : null;
    } catch (_e) {
        return null;
    }
}

/**
 * base+rva of `mod` when `rva` lies inside it, `sha` is a SHA-256 hex digest and the
 * live prologue there still hashes to it (case-insensitive); null otherwise.
 */
export function verifiedLearnedAddress(mod: CacheModule, rva: unknown, sha: unknown,
                                       hashPrologue: PrologueHasher = sha256Prologue): NativePointer | null {
    if (!isRva(rva, mod.size) || !isSha256Hex(sha)) return null;
    const address = mod.base.add(rva);
    const actual = hashPrologue(address);
    return actual !== null && actual.toLowerCase() === sha.toLowerCase() ? address : null;
}

/** Same item: rva and (case-insensitive) hash for a function, the number for a layout value. */
function sameItem(a: unknown, b: LearnedFunction | number): boolean {
    if (typeof b === "number") return a === b;
    return isPlainObject(a) && a.rva === b.rva && typeof a.prologue_sha256 === "string"
        && a.prologue_sha256.toLowerCase() === b.prologue_sha256.toLowerCase();
}

function itemKey(field: ItemField, name: string): string {
    return `${field}:${name}`;
}

// ---- the cache ---------------------------------------------------------------

interface PendingReport {
    mod: CacheModule;
    identity: ModuleIdentity;
    functions: Record<string, LearnedFunction>;
    layout: Record<string, number>;
}

interface HostLookup {
    identity: ModuleIdentity;
    entry: Record<string, any>;
}

function defaultDeps(): LearnedModuleCacheDeps {
    return {
        identify: identifyModule,
        // Verify and report with the same hook-proof window.
        hashPrologue: sha256FunctionBody,
        emit: sendModuleOffsetsLearned,
        schedule: (flush) => { setTimeout(flush, REPORT_COALESCE_MS); },
    };
}

export class LearnedModuleCache {
    private readonly entries: Record<string, unknown>;
    private readonly deps: LearnedModuleCacheDeps;
    // Only modules an entry was learned for are worth parsing the ELF build id of.
    private readonly cachedModules: Set<unknown>;
    private readonly acceptedFromCache = new Map<string, Set<string>>();
    private readonly alreadyReported = new Map<string, Map<string, LearnedFunction | number>>();
    private readonly cacheHitSent = new Set<string>();
    private readonly pending = new Map<string, PendingReport>();
    private flushScheduled = false;

    constructor(raw: unknown, deps: Partial<LearnedModuleCacheDeps> = {}) {
        this.entries = isPlainObject(raw) ? raw : {};
        this.deps = { ...defaultDeps(), ...deps };
        this.cachedModules = new Set(Object.values(this.entries)
            .map((entry) => (isPlainObject(entry) ? entry.module : null)));
    }

    get entryCount(): number {
        return Object.keys(this.entries).length;
    }

    /** The raw host entry for `mod`'s build_id|size|arch key, or null. */
    hostEntry(mod: CacheModule): Record<string, any> | null {
        return this.hostLookup(mod)?.entry ?? null;
    }

    /** The prologue-verified address of cached function `name` in `mod`, or null. */
    learnedFunction(mod: CacheModule, name: string): NativePointer | null {
        try {
            const lookup = this.hostLookup(mod);
            const item = lookup === null ? undefined : this.itemIn(lookup.entry, "functions", name);
            if (lookup === null || !isPlainObject(item)) return null;
            const address = verifiedLearnedAddress(mod, item.rva, item.prologue_sha256, this.deps.hashPrologue);
            if (address === null) {
                devlog_debug(`[learned-cache] ${mod.name}: ${name} not verified (stale or malformed entry)`);
                return null;
            }
            if (!isHookableAddress(address, lookup.identity.arch)) {
                devlog_debug(`[learned-cache] ${mod.name}: ${name} at ${address} is an even (ARM-mode) address; ignored`);
                return null;
            }
            this.accept(mod, "functions", name);
            return address;
        } catch (e) {
            devlog_debug(`[learned-cache] ${mod.name}: ${name} lookup failed: ${e}`);
            return null;
        }
    }

    /** Cached layout value `name` for `mod` (within the host's bounds), or null. */
    learnedLayout(mod: CacheModule, name: string): number | null {
        try {
            const value = this.hostItem(mod, "layout", name);
            if (!isValidLayoutValue(name, value)) return null;
            this.accept(mod, "layout", name);
            return value;
        } catch (e) {
            devlog_debug(`[learned-cache] ${mod.name}: layout ${name} lookup failed: ${e}`);
            return null;
        }
    }

    /**
     * The cached item `name` failed live validation (or the caller's own check): a
     * value found later may be reported again (the stale one itself still never is).
     */
    reject(mod: CacheModule, field: ItemField, name: string): void {
        this.acceptedFromCache.get(mappingKey(mod))?.delete(itemKey(field, name));
    }

    /** True when `mod` has a build identity, i.e. results learned for it can be cached. */
    isCacheable(mod: CacheModule): boolean {
        try {
            return this.deps.identify(mod) !== null;
        } catch (_e) {
            return false;
        }
    }

    /** Queue scan results of `mod` for the host; items that came from the cache are never reported. */
    reportLearned(mod: CacheModule, items: LearnedItems): void {
        try {
            const identity = this.deps.identify(mod);
            if (identity === null) {
                devlog_debug(`[learned-cache] ${mod.name}: no build id; results not cacheable`);
                return;
            }
            const report = this.pendingFor(mod, identity);
            for (const [name, address] of Object.entries(items.functions ?? {})) {
                const learned = this.learnedFunctionItem(mod, identity, name, address);
                if (learned !== null && this.isNew(mod, "functions", name, learned)) report.functions[name] = learned;
            }
            for (const [name, value] of Object.entries(items.layout ?? {})) {
                if (isLearnedItemName(name) && isValidLayoutValue(name, value)
                    && this.isNew(mod, "layout", name, value)) report.layout[name] = value;
            }
            this.scheduleFlush();
        } catch (e) {
            devlog_debug(`[learned-cache] ${mod.name}: report failed: ${e}`);
        }
    }

    /** Tell the host (once per module per session) that a cached item was used, so it stays hot. */
    reportCacheHit(mod: CacheModule): void {
        const key = mappingKey(mod);
        if (this.cacheHitSent.has(key)) return;
        this.cacheHitSent.add(key);
        try {
            const identity = this.deps.identify(mod);
            if (identity === null) return;
            this.deps.emit({ ...this.keyFields(mod, identity), cache_hit: true });
        } catch (e) {
            devlog_debug(`[learned-cache] ${mod.name}: cache-hit report failed: ${e}`);
        }
    }

    /** Send every queued report: one message per module. */
    flush(): void {
        this.flushScheduled = false;
        const reports = [...this.pending.values()];
        this.pending.clear();
        for (const report of reports) this.send(report);
    }

    private send(report: PendingReport): void {
        const hasFunctions = Object.keys(report.functions).length > 0;
        const hasLayout = Object.keys(report.layout).length > 0;
        if (!hasFunctions && !hasLayout) return;
        const payload: ModuleOffsetsLearnedPayload = { ...this.keyFields(report.mod, report.identity) };
        if (hasFunctions) payload.functions = report.functions;
        if (hasLayout) payload.layout = report.layout;
        devlog_debug(`[learned-cache] ${report.mod.name}: reporting ` +
            [...Object.keys(report.functions), ...Object.keys(report.layout)].join(", "));
        try {
            this.deps.emit(payload);
        } catch (e) {
            devlog_debug(`[learned-cache] ${report.mod.name}: send failed: ${e}`);
        }
    }

    private keyFields(mod: CacheModule, identity: ModuleIdentity) {
        return { module: moduleBasename(mod.name), build_id: identity.buildId, size: identity.size, arch: identity.arch };
    }

    private hostLookup(mod: CacheModule): HostLookup | null {
        if (!this.cachedModules.has(moduleBasename(mod.name))) return null;
        const identity = this.deps.identify(mod);
        if (identity === null) return null;
        const entry = this.entries[learnedKey(identity)];
        return isPlainObject(entry) ? { identity, entry } : null;
    }

    private itemIn(entry: Record<string, any> | null, field: ItemField, name: string): unknown {
        const items = entry?.[field];
        return isPlainObject(items) ? items[name] : undefined;
    }

    private hostItem(mod: CacheModule, field: ItemField, name: string): unknown {
        return this.itemIn(this.hostEntry(mod), field, name);
    }

    private accept(mod: CacheModule, field: ItemField, name: string): void {
        memoizePerMapping(this.acceptedFromCache, mod, () => new Set<string>()).add(itemKey(field, name));
        this.reportCacheHit(mod);
    }

    private learnedFunctionItem(mod: CacheModule, identity: ModuleIdentity, name: string,
                                address: NativePointer): LearnedFunction | null {
        if (!isLearnedItemName(name)) return null;
        const rva = rvaOf(mod, address, identity.size);
        const hash = rva === null ? null : this.deps.hashPrologue(address);
        return rva === null || hash === null ? null : { rva, prologue_sha256: hash.toLowerCase() };
    }

    /** False for an item accepted from the cache, already in it, or already reported this session. */
    private isNew(mod: CacheModule, field: ItemField, name: string, value: LearnedFunction | number): boolean {
        const id = itemKey(field, name);
        if (this.acceptedFromCache.get(mappingKey(mod))?.has(id)) return false;
        if (sameItem(this.hostItem(mod, field, name), value)) return false;
        const reported = memoizePerMapping(this.alreadyReported, mod, () => new Map<string, LearnedFunction | number>());
        if (reported.has(id) && sameItem(reported.get(id), value)) return false;
        reported.set(id, value);
        return true;
    }

    private pendingFor(mod: CacheModule, identity: ModuleIdentity): PendingReport {
        return memoizePerMapping(this.pending, mod, () => ({ mod, identity, functions: {}, layout: {} }));
    }

    private scheduleFlush(): void {
        if (this.flushScheduled || this.pending.size === 0) return;
        this.flushScheduled = true;
        this.deps.schedule(() => this.flush());
    }
}

// ---- process-wide instance ---------------------------------------------------

let activeCache = new LearnedModuleCache({});

/** Load the host entries (config_batch.learned_plaintext); anything but a plain object means none. */
export function installLearnedModuleCache(raw: unknown, deps: Partial<LearnedModuleCacheDeps> = {}): LearnedModuleCache {
    activeCache = new LearnedModuleCache(raw, deps);
    devlog_debug(`[learned-cache] ${activeCache.entryCount} host entries`);
    return activeCache;
}

export function learnedFunction(mod: CacheModule, name: string): NativePointer | null {
    return activeCache.learnedFunction(mod, name);
}

export function learnedLayout(mod: CacheModule, name: string): number | null {
    return activeCache.learnedLayout(mod, name);
}

export function rejectLearnedLayout(mod: CacheModule, name: string): void {
    activeCache.reject(mod, "layout", name);
}

export function rejectLearnedFunction(mod: CacheModule, name: string): void {
    activeCache.reject(mod, "functions", name);
}

export function reportLearned(mod: CacheModule, items: LearnedItems): void {
    activeCache.reportLearned(mod, items);
}

export function isCacheableModule(mod: CacheModule): boolean {
    return activeCache.isCacheable(mod);
}

export function reportCacheHit(mod: CacheModule): void {
    activeCache.reportCacheHit(mod);
}

export function learnedHostEntry(mod: CacheModule): Record<string, any> | null {
    try {
        return activeCache.hostEntry(mod);
    } catch (e) {
        devlog_debug(`[learned-cache] ${mod.name}: host entry lookup failed: ${e}`);
        return null;
    }
}

/**
 * Miss-marker value for a scan whose outcome also depends on `inputs` (symbol
 * names, byte patterns): FNV-1a over them in order, mapped to 1..MISS_FINGERPRINT_MAX.
 */
export function missFingerprint(inputs: string[]): number {
    let hash = FNV_OFFSET_BASIS;
    for (const char of inputs.join("\u0000")) {
        hash = Math.imul(hash ^ char.codePointAt(0)!, FNV_PRIME) >>> 0;
    }
    return (hash % MISS_FINGERPRINT_MAX) + 1;
}

/** True when a previous clean scan of this build recorded miss marker `name` with value `marker`. */
export function hasLearnedMiss(mod: CacheModule, name: string, marker: number = MISS_MARKER): boolean {
    const value = activeCache.learnedLayout(mod, name);
    if (value === marker) return true;
    // A marker from other scan inputs is stale: let the fresh one be reported.
    if (value !== null) activeCache.reject(mod, "layout", name);
    return false;
}

/** Miss-marker name of learned item `name`: "miss" before its last segment ("quiche.frame.miss.CryptoConnect"). */
export function learnedMissName(name: string): string {
    const lastDot = name.lastIndexOf(".");
    return `${name.slice(0, lastDot + 1)}miss.${name.slice(lastDot + 1)}`;
}

/** Record that a clean scan of `mod` found nothing for `name` (scan results are a pure function of the build). */
export function reportLearnedMiss(mod: CacheModule, names: string[], marker: number = MISS_MARKER): void {
    reportLearnedMisses(mod, Object.fromEntries(names.map((name) => [name, marker])), { complete: true });
}

/**
 * Like reportLearnedMiss, with a marker value per name. Only a scan that ran to
 * completion proves a miss: nothing is recorded when `scan` is incomplete or the
 * agent is shutting down (a detach can cut the scan short).
 */
export function reportLearnedMisses(mod: CacheModule, markers: Record<string, number>, scan: ScanStatus): void {
    if (!scan.complete || _isShuttingDownNow()) return;
    if (Object.keys(markers).length === 0) return;
    activeCache.reportLearned(mod, { layout: markers });
}
