// agent/quic/shared/quiche_symbol_resolution.ts
//
// The order in which resolveQuicheSymbols() (google_quiche.ts) fills the QUICHE
// hook addresses, including the cross-run learned cache. The Frida-bound steps
// are injected sources, so the order is unit-testable without Frida.

import { devlog, devlog_debug } from "../../util/log.js";
import type { ScanStatus } from "../../shared/arm64_xref.js";
import {
    hasLearnedMiss, learnedFunction, learnedMissName, reportLearned, reportLearnedMisses,
} from "../../shared/learned_module_cache.js";
import type { CacheModule } from "../../shared/module_mapping.js";

const LEARNED_QUICHE_PREFIX = "quiche";

function safeItemSegment(key: string): string {
    return key.replace(/[^A-Za-z0-9_]/g, "_");
}

/** Learned-cache item name of a MANGLED_SYMBOLS key, e.g. "quiche.writeOrBufferBody". */
export function learnedQuicheName(key: string): string {
    return `${LEARNED_QUICHE_PREFIX}.${safeItemSegment(key)}`;
}

/** Learned-cache miss marker of a MANGLED_SYMBOLS key, e.g. "quiche.miss.writeOrBufferBody". */
export function learnedQuicheMissName(key: string): string {
    return learnedMissName(learnedQuicheName(key));
}

/** What one scan step found; `complete` is false when part of it failed (its misses then prove nothing). */
export interface QuicheScanResult<K extends string> {
    found: Map<K, NativePointer>;
    complete: boolean;
}

export interface QuicheSymbolSources<K extends string> {
    exported: (key: K) => NativePointer | null;
    symtab: (keys: K[]) => QuicheScanResult<K>;
    /** A throw counts as an incomplete scan. */
    patterns: (keys: K[]) => Promise<QuicheScanResult<K>>;
    /** The user's --offsets address for `key`, or null. */
    userOffset: (key: K) => NativePointer | null;
    /** True when `key` has a --offsets entry; keeps the learned cache out of that key. */
    hasUserOffset: (key: K) => boolean;
    /** Miss-marker value for the symbol names + patterns `key` is scanned with (1..MISS_FINGERPRINT_MAX). */
    missFingerprint: (key: K) => number;
}

export interface QuicheSymbolResolution<K extends string> {
    resolved: Map<K, NativePointer>;
    fromCache: number;
}

/** Copy `found` entries for keys `resolved` still lacks into both maps. */
function fillMissing<K>(resolved: Map<K, NativePointer>, learned: Map<K, NativePointer>,
                        found: Map<K, NativePointer>): void {
    found.forEach((addr, key) => {
        if (resolved.has(key) || addr.isNull()) return;
        resolved.set(key, addr);
        learned.set(key, addr);
    });
}

/** Cache verdicts for `keys`: verified addresses, and keys a clean earlier scan of this build missed. */
function consultCache<K extends string>(mod: CacheModule | null, keys: K[], sources: QuicheSymbolSources<K>):
        { hits: Map<K, NativePointer>; knownMisses: Set<K> } {
    const hits = new Map<K, NativePointer>();
    const knownMisses = new Set<K>();
    if (mod === null) return { hits, knownMisses };
    for (const key of keys) {
        if (sources.hasUserOffset(key)) continue;
        const addr = learnedFunction(mod, learnedQuicheName(key));
        if (addr !== null) hits.set(key, addr);
        else if (hasLearnedMiss(mod, learnedQuicheMissName(key), sources.missFingerprint(key))) knownMisses.add(key);
    }
    if (knownMisses.size > 0) {
        devlog_debug(`[Google QUICHE] ${mod.name}: learned cache records no ${[...knownMisses].join(", ")} ` +
                     `in this build; not scanned`);
    }
    return { hits, knownMisses };
}

function reportScanResults<K extends string>(mod: CacheModule | null, learned: Map<K, NativePointer>,
                                             misses: K[], scan: ScanStatus, sources: QuicheSymbolSources<K>): void {
    if (mod === null) return;
    if (learned.size > 0) {
        const functions: Record<string, NativePointer> = {};
        learned.forEach((addr, key) => { functions[learnedQuicheName(key)] = addr; });
        reportLearned(mod, { functions });
    }
    reportLearnedMisses(mod, Object.fromEntries(
        misses.map((key) => [learnedQuicheMissName(key), sources.missFingerprint(key)])), scan);
}

/** `sources` whose missFingerprint is computed once per key (the cache read and the miss report both ask). */
function withMemoizedFingerprint<K extends string>(sources: QuicheSymbolSources<K>): QuicheSymbolSources<K> {
    const memo = new Map<K, number>();
    return {
        ...sources,
        missFingerprint: (key) => {
            if (!memo.has(key)) memo.set(key, sources.missFingerprint(key));
            return memo.get(key)!;
        },
    };
}

/**
 * exports -> learned cache -> symtab -> byte patterns -> user --offsets.
 * The cache sits before the symtab because enumerateSymbols() on a large
 * Chrome/Cronet module costs seconds, and a prologue-verified entry for the same
 * build id is as trustworthy as the walk that produced it. A key both scans
 * missed cleanly gets a miss marker (fingerprint of the names and patterns
 * tried), so later runs on the build skip it until that set changes. Keys with
 * a --offsets entry bypass the cache, so it can never shadow the override.
 * Without `mod` the cache is neither read nor written.
 */
export async function resolveQuicheSymbolsWith<K extends string>(
    mod: CacheModule | null, keys: K[], sources: QuicheSymbolSources<K>,
): Promise<QuicheSymbolResolution<K>> {
    sources = withMemoizedFingerprint(sources);
    const resolved = new Map<K, NativePointer>();
    for (const key of keys) {
        const addr = sources.exported(key);
        if (addr !== null && !addr.isNull()) resolved.set(key, addr);
    }
    const { hits, knownMisses } = consultCache(mod, keys.filter((k) => !resolved.has(k)), sources);
    hits.forEach((addr, key) => resolved.set(key, addr));
    const toScan = () => keys.filter((k) => !resolved.has(k) && !knownMisses.has(k));

    const learned = new Map<K, NativePointer>();
    const scan: ScanStatus = { complete: true };
    if (toScan().length > 0) {
        const symtab = sources.symtab(toScan());
        fillMissing(resolved, learned, symtab.found);
        scan.complete = symtab.complete;
    }
    if (toScan().length > 0) {
        try {
            const patterns = await sources.patterns(toScan());
            fillMissing(resolved, learned, patterns.found);
            scan.complete = scan.complete && patterns.complete;
        } catch (e) {
            scan.complete = false;
            devlog_debug(`[Google QUICHE] pattern strategy failed: ${e}`);
        }
    }
    const misses = toScan();
    for (const key of keys.filter((k) => !resolved.has(k))) {
        const addr = sources.userOffset(key);
        if (addr === null) continue;
        resolved.set(key, addr);
        devlog(`[Google QUICHE] applied --offsets entry for ${key}`);
    }
    reportScanResults(mod, learned, misses, scan, sources);
    return { resolved, fromCache: hits.size };
}
