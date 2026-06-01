// agent/util/safe_memory.ts
//
// Native-crash-safe memory reads for struct-walking hot paths.
//
// Frida's JS try/catch does NOT catch a native SIGSEGV: dereferencing an
// unmapped/garbage pointer inside an Interceptor callback kills the whole
// target process (observed as "the connection is closed"). These helpers
// validate that an address lies in a mapped, readable range BEFORE
// dereferencing, so a bad pointer yields null/"" instead of crashing the
// target. A per-walk cache keeps the validation cheap: each struct walk
// touches a tight cluster of nearby addresses, so a cached interval test
// resolves almost every check without a fresh range lookup.
//
// Call resetReadableCache() at the top of each walk — mapped ranges can change
// as the target maps/unmaps memory between invocations.
//
// Deliberately NOT using Process.setExceptionHandler: it is process-global
// (last handler wins, conflicting with friTap's many hooks) and cannot reliably
// resume a faulting load mid-Interceptor back into JS on arm64-Android.

interface ReadableRange { base: NativePointer; end: NativePointer; }

let readableCache: ReadableRange[] = [];

// Android arm64 uses top-byte pointer tagging (Scudo heap tags / MTE, relying on
// the CPU's Top-Byte-Ignore feature): heap data pointers carry a non-zero tag in
// the top byte (e.g. 0xb4..). The hardware masks the tag on load/store, but
// Process.findRangeByAddress expects the canonical (untagged) virtual address — so
// a tagged pointer matches no range and a perfectly VALID read gets rejected. Clear
// the top byte before any range lookup. Userspace VAs on these targets are <= 56
// bits, so this is a no-op for already-canonical pointers. 64-bit only (32-bit
// platforms don't tag).
const TBI_MASK: NativePointer | null = Process.pointerSize === 8 ? ptr("0x00ffffffffffffff") : null;
function untag(p: NativePointer): NativePointer {
    return TBI_MASK !== null ? p.and(TBI_MASK) : p;
}

/** Drop the cached readable ranges. Call once at the start of each walk. */
export function resetReadableCache(): void {
    readableCache = [];
}

/**
 * True if [ptr, ptr+size) lies entirely within a single mapped, readable range.
 * Checks the per-walk cache first; on a miss, consults
 * Process.findRangeByAddress and caches the hit. Conservative (a read that
 * straddles a range boundary returns false) and never throws.
 */
export function isReadable(ptr: NativePointer, size = 1): boolean {
    if (ptr === null || ptr.isNull()) return false;
    try {
        const a = untag(ptr); // canonicalise Android tagged pointers before range lookup
        const endNeeded = a.add(size);
        for (const r of readableCache) {
            if (a.compare(r.base) >= 0 && endNeeded.compare(r.end) <= 0) return true;
        }
        const range = Process.findRangeByAddress(a);
        if (!range || range.protection[0] !== "r") return false;
        const base = range.base;
        const end = base.add(range.size);
        if (endNeeded.compare(end) > 0) return false;   // straddles the range end
        readableCache.push({ base, end });
        return true;
    } catch (e) {
        return false;
    }
}

/** readPointer() guarded by isReadable; null if the address is unreadable. */
export function safeReadPointer(ptr: NativePointer): NativePointer | null {
    if (!isReadable(ptr, Process.pointerSize)) return null;
    try { return ptr.readPointer(); } catch (e) { return null; }
}

/** readU8() guarded by isReadable; null if the address is unreadable. */
export function safeReadU8(ptr: NativePointer): number | null {
    if (!isReadable(ptr, 1)) return null;
    try { return ptr.readU8(); } catch (e) { return null; }
}

/** readULong() guarded by isReadable; null if the address is unreadable. */
export function safeReadULong(ptr: NativePointer): number | null {
    if (!isReadable(ptr, 8)) return null;
    try { return (ptr.readULong() as unknown) as number; } catch (e) { return null; }
}

/** readUtf8String(len) guarded by isReadable over the full length; "" otherwise. */
export function safeReadUtf8(ptr: NativePointer, len: number): string {
    if (len <= 0 || !isReadable(ptr, len)) return "";
    try { return ptr.readUtf8String(len) ?? ""; } catch (e) { return ""; }
}
