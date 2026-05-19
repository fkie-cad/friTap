// agent/tls/shared/go_symbol_resolver.ts
//
// Pre-resolution helpers for Go crypto/tls symbols. Go embeds the package
// path in every symbol name (e.g. "crypto/tls.(*Config).writeKeyLog"), so
// Frida's standard ApiResolver "exports:" pattern that the modern loader
// uses cannot locate them. This module reproduces the legacy GoTLS fuzzy
// resolution cascade in a pure-function form suitable for HookDefinition
// .symbolResolver.

import { devlog } from "../../util/log.js";

/** Canonical Go crypto/tls symbol — keylog material extraction point. */
export const GO_SYMBOL_WRITE_KEYLOG = "crypto/tls.(*Config).writeKeyLog";

/** Canonical Go crypto/tls symbol — plaintext read. */
export const GO_SYMBOL_CONN_READ = "crypto/tls.(*Conn).Read";

/** Canonical Go crypto/tls symbol — plaintext write. */
export const GO_SYMBOL_CONN_WRITE = "crypto/tls.(*Conn).Write";

const CANONICAL_SYMBOLS: readonly string[] = [
    GO_SYMBOL_WRITE_KEYLOG,
    GO_SYMBOL_CONN_READ,
    GO_SYMBOL_CONN_WRITE,
];

/**
 * Build the mangled-name variants legacy GoTLS tried. Some toolchains
 * (Unity/JNI, custom linkers) rewrite '/', '.', and '(*X)' fragments — we
 * probe each rewriting here.
 */
function getGoSymbolVariants(symbol: string): string[] {
    const variants = new Set<string>();
    variants.add(symbol);

    // Slashes → underscores; (*X) → _ptr_X; keep dots.
    variants.add(
        symbol
            .replace(/\//g, "_")
            .replace(/\(\*([^)]+)\)/g, "_ptr_$1"),
    );

    // Slashes & dots → underscores; (*X) → _ptr_X.
    variants.add(
        symbol
            .replace(/\//g, "_")
            .replace(/\(\*([^)]+)\)/g, "_ptr_$1")
            .replace(/\./g, "_"),
    );

    // Explicit Unity/JNI rewriting.
    variants.add(
        symbol
            .replace(/crypto\/tls/g, "crypto_tls")
            .replace(/\(\*Conn\)/g, "_ptr_Conn")
            .replace(/\(\*Config\)/g, "_ptr_Config")
            .replace(/\./g, "_"),
    );

    return Array.from(variants);
}

/**
 * Try Module.findGlobalExportByName for the canonical symbol and each
 * mangled variant. Returns null if nothing resolves.
 */
function tryGlobalExport(symbol: string, variants: string[]): NativePointer | null {
    for (const variant of [symbol, ...variants]) {
        try {
            const addr = Module.findGlobalExportByName(variant);
            if (addr && !addr.isNull()) return addr;
        } catch (e) {
            // continue
        }
    }
    return null;
}

/**
 * Try the module-scoped export name (and mangled variants). Returns null
 * when the module is not loaded or no variant matches.
 */
function tryModuleExport(
    moduleName: string,
    symbol: string,
    variants: string[],
): NativePointer | null {
    let mod: Module;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        return null;
    }
    for (const variant of [symbol, ...variants]) {
        try {
            const addr = mod.findExportByName(variant);
            if (addr && !addr.isNull()) return addr;
        } catch (e) {
            // continue
        }
    }
    return null;
}

/**
 * Try DebugSymbol.fromName — works on binaries with retained Go
 * runtime symbols even when they aren't dynamic exports.
 */
function tryDebugSymbol(symbol: string): NativePointer | null {
    try {
        const addr = DebugSymbol.fromName(symbol).address;
        if (addr && !addr.isNull()) return addr;
    } catch (e) {
        // continue
    }
    return null;
}

interface SymbolIndex {
    list: ModuleSymbolDetails[];
    byName: Map<string, NativePointer>;
}

function buildSymbolIndex(moduleName: string): SymbolIndex | null {
    let symbols: ModuleSymbolDetails[];
    try {
        symbols = Process.getModuleByName(moduleName).enumerateSymbols();
    } catch (e) {
        return null;
    }
    const byName = new Map<string, NativePointer>();
    for (const s of symbols) {
        if (!s.address.isNull() && !byName.has(s.name)) {
            byName.set(s.name, s.address);
        }
    }
    return { list: symbols, byName };
}

function lookupInIndex(
    index: SymbolIndex,
    symbol: string,
    variants: string[],
): NativePointer | null {
    // O(1) exact lookups against the pre-built map.
    for (const variant of [symbol, ...variants]) {
        const hit = index.byName.get(variant);
        if (hit) return hit;
    }
    // Linear: substring match against any variant.
    for (const variant of [symbol, ...variants]) {
        const partial = index.list.find((s) => s.name.includes(variant));
        if (partial && !partial.address.isNull()) return partial.address;
    }
    // Linear: fuzzy on the base method name.
    const base = symbol.split(".").pop()?.toLowerCase();
    if (base) {
        const fuzzy = index.list.find((s) => s.name.toLowerCase().includes(base));
        if (fuzzy && !fuzzy.address.isNull()) return fuzzy.address;
    }
    return null;
}

function resolveCheapStrategies(
    moduleName: string,
    symbol: string,
): NativePointer | null {
    const variants = getGoSymbolVariants(symbol);
    return (
        tryGlobalExport(symbol, variants) ||
        tryModuleExport(moduleName, symbol, variants) ||
        tryDebugSymbol(symbol)
    );
}

/**
 * Pre-resolve every canonical Go crypto/tls symbol for the given module.
 * Cheap strategies (global export → module export → debug symbol) run
 * first; if any symbol is still missing, `enumerateSymbols()` runs ONCE
 * and the resulting index is reused across the remaining symbols.
 */
export function resolveGoSymbols(moduleName: string): { [s: string]: NativePointer } {
    const out: { [s: string]: NativePointer } = {};
    const remaining: string[] = [];

    for (const symbol of CANONICAL_SYMBOLS) {
        const addr = resolveCheapStrategies(moduleName, symbol);
        if (addr) {
            out[symbol] = addr;
        } else {
            remaining.push(symbol);
        }
    }

    if (remaining.length === 0) return out;

    const index = buildSymbolIndex(moduleName);
    if (index === null) {
        for (const symbol of remaining) {
            devlog(`[gotls-resolver] Could not resolve ${symbol} in ${moduleName}`);
        }
        return out;
    }

    for (const symbol of remaining) {
        const variants = getGoSymbolVariants(symbol);
        const addr = lookupInIndex(index, symbol, variants);
        if (addr) {
            out[symbol] = addr;
        } else {
            devlog(`[gotls-resolver] Could not resolve ${symbol} in ${moduleName}`);
        }
    }
    return out;
}
