// agent/shared/module_mapping.ts
//
// Per-mapping identity, memoization and byte reads of a loaded module. Kept
// free of imports so the header parsers and range walkers can share it
// without pulling in the host messaging.

export type CacheModule = Pick<Module, "name" | "base" | "size">;

/** Reads `length` bytes at `offset` from the module base; null when unreadable. */
export type ModuleByteReader = (offset: number, length: number) => Uint8Array | null;

/** A reader over the loaded module at `base`; unreadable memory reads as null. */
export function moduleMemoryReader(base: NativePointer): ModuleByteReader {
    return (offset, length) => {
        try {
            const bytes = base.add(offset).readByteArray(length);
            return bytes === null ? null : new Uint8Array(bytes);
        } catch (_e) {
            return null;
        }
    };
}

/** Identity of one loaded mapping (Module objects are not stable identities). */
export function mappingKey(mod: CacheModule): string {
    return `${mod.name}@${mod.base}`;
}

/** mappingKey of the module containing `address` ("?" when it is in no module). */
export function mappingKeyAt(address: NativePointer): string {
    let mod: Module | null = null;
    try { mod = Process.findModuleByAddress(address); } catch (_e) { /* unmapped */ }
    return mod === null ? "?" : mappingKey(mod);
}

/**
 * `address` qualified by its mapping (name@base), so another library mapped
 * later at the same address does not share the key.
 */
export function mappingAddressKey(address: NativePointer, mapping: string = mappingKeyAt(address)): string {
    return `${mapping}#${address}`;
}

/** `compute()` once per loaded mapping of `mod`; later calls return the stored value. */
export function memoizePerMapping<T>(memo: Map<string, T>, mod: CacheModule, compute: () => T): T {
    const key = mappingKey(mod);
    if (!memo.has(key)) memo.set(key, compute());
    return memo.get(key)!;
}

/** Index of the last sorted table entry whose start is <= addr, or -1. */
export function searchSortedStarts(count: number, startAt: (i: number) => number, addr: number): number {
    let lo = 0, hi = count - 1, found = -1;
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (startAt(mid) <= addr) { found = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    return found;
}
