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

import { findDarwinRegion, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE } from "./darwin_vm_region.js";
import { moduleMemoryReader, type ModuleByteReader } from "../shared/module_mapping.js";

export { VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE };

interface ReadableRange { base: NativePointer; end: NativePointer; }

/** A mapped range holding an address: [base, end) with its "rwx" protection string. */
export interface MappedRange extends ReadableRange { protection: string; }

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
export function untag(p: NativePointer): NativePointer {
    return TBI_MASK !== null ? p.and(TBI_MASK) : p;
}

/** A plain NativePointer holding `p`'s current value (hook args / retval must not outlive their callback). */
export function copyPointer(p: NativePointer): NativePointer {
    return p.add(0);
}

/** Drop the cached readable ranges. Call once at the start of each walk. */
export function resetReadableCache(): void {
    readableCache = [];
}

function protectionString(prot: number): string {
    return ((prot & VM_PROT_READ) !== 0 ? "r" : "-") + ((prot & VM_PROT_WRITE) !== 0 ? "w" : "-")
        + ((prot & VM_PROT_EXECUTE) !== 0 ? "x" : "-");
}

/**
 * The mapped range holding `address` (pointer tags cleared), or null; never throws.
 * Darwin asks mach_vm_region: Process.findRangeByAddress costs ~42 ms per call on Chrome.
 */
export function findRange(address: NativePointer): MappedRange | null {
    try {
        const a = untag(address);
        const region = findDarwinRegion(a);
        if (region !== undefined) {
            return region === null ? null : { base: region.base, end: region.end, protection: protectionString(region.protection) };
        }
        const range = Process.findRangeByAddress(a);
        return range ? { base: range.base, end: range.base.add(range.size), protection: range.protection } : null;
    } catch (_e) {
        return null;
    }
}

/**
 * [base, end) of the module's whole mapped image. Frida's Module.size covers
 * only __TEXT on macOS, but data such as vtables lives in __DATA_CONST past it.
 */
export function moduleImageBounds(mod: Pick<Module, "base" | "size" | "enumerateRanges">): [NativePointer, NativePointer] {
    let end = mod.base.add(mod.size);
    for (const r of readableModuleRanges(mod)) {
        const rangeEnd = r.base.add(r.size);
        if (r.base.compare(mod.base) >= 0 && rangeEnd.compare(end) > 0) end = rangeEnd;
    }
    return [mod.base, end];
}

function readableModuleRanges(mod: Pick<Module, "enumerateRanges">): RangeDetails[] {
    try {
        return mod.enumerateRanges("r--");
    } catch (_e) {
        return [];
    }
}

/** The readable range holding `a`, or null. */
function findReadableRange(a: NativePointer): ReadableRange | null {
    const range = findRange(a);
    return range !== null && range.protection[0] === "r" ? range : null;
}

/**
 * True if [ptr, ptr+size) lies entirely within a single mapped, readable range.
 * Checks the per-walk cache first; on a miss, consults findRange and caches
 * the hit. Conservative (a read that straddles a range boundary returns false)
 * and never throws.
 */
export function isReadable(ptr: NativePointer, size = 1): boolean {
    if (ptr === null || ptr.isNull()) return false;
    try {
        const a = untag(ptr); // canonicalise Android tagged pointers before range lookup
        const endNeeded = a.add(size);
        for (const r of readableCache) {
            if (a.compare(r.base) >= 0 && endNeeded.compare(r.end) <= 0) return true;
        }
        const range = findReadableRange(a);
        if (range === null) return false;
        if (endNeeded.compare(range.end) > 0) return false;   // straddles the range end
        readableCache.push(range);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * True if [ptr, ptr+size) lies entirely within a single mapped range that is
 * both readable AND writable. Unlike isReadable this is uncached: write targets
 * are validated rarely (once per struct install, not per struct walk), and a
 * stale "writable" verdict is far more dangerous than a stale readable one.
 * Never throws.
 */
export function isWritable(ptr: NativePointer, size = 1): boolean {
    if (ptr === null || ptr.isNull()) return false;
    try {
        const a = untag(ptr);
        const range = findRange(a);
        if (range === null || range.protection[0] !== "r" || range.protection[1] !== "w") return false;
        return a.add(size).compare(range.end) <= 0;
    } catch (e) {
        return false;
    }
}

/** True if `p` lies in a mapped range with execute permission (pointer tags cleared); never throws. */
export function isExecutable(p: NativePointer): boolean {
    try {
        return findRange(p)?.protection.includes("x") ?? false;
    } catch (_e) {
        return false;
    }
}

/**
 * Bytes readable from `addr`, capped at `maxBytes`. Follows adjacent readable
 * mappings, so a body that spans two mappings is covered; stops at the first
 * unmapped or non-readable byte. Never throws.
 */
export function readableByteCount(addr: NativePointer, maxBytes: number): number {
    let covered = 0;
    try {
        while (covered < maxBytes) {
            const cursor = addr.add(covered);
            const range = findRange(cursor);
            if (range === null || range.protection[0] !== "r") break;
            const leftInRange = range.end.sub(cursor);
            const wanted = maxBytes - covered;
            if (leftInRange.compare(ptr(wanted)) >= 0) return maxBytes;
            const left = leftInRange.toUInt32();
            if (left === 0) break;
            covered += left;
        }
    } catch (_e) { /* best-effort: report what was covered */ }
    return covered;
}

/**
 * Bytes a decoder can read from `fn`: at most `capBytes`, never past the module
 * image end, and only over contiguous readable memory (readableByteCount). A read
 * that returns this many bytes read everything there is, so a function sitting
 * near the end of its module or range is not mistaken for an unreadable one.
 * 0 when `fn` lies outside the image or is unreadable. Never throws.
 */
export function codeBytesAvailable(fn: NativePointer, mod: Pick<Module, "base" | "size">, capBytes: number): number {
    try {
        const end = mod.base.add(mod.size);
        if (fn.compare(mod.base) < 0 || fn.compare(end) >= 0) return 0;
        const toModuleEnd = Number(end.sub(fn).toString());
        return readableByteCount(fn, Math.min(capBytes, toModuleEnd));
    } catch (_e) {
        return 0;
    }
}

/**
 * Module-offset reader bounded by the module image [0, size): a request outside
 * it, or over memory that is not readable as one range, reads as null.
 */
export function boundedModuleReader(mod: Pick<Module, "base" | "size">): ModuleByteReader {
    const read = moduleMemoryReader(mod.base);
    return (offset, length) => {
        if (offset < 0 || length <= 0 || offset + length > mod.size) return null;
        return isReadable(mod.base.add(offset), length) ? read(offset, length) : null;
    };
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

/** readU32() guarded by isReadable; null if the address is unreadable. */
export function safeReadU32(ptr: NativePointer): number | null {
    if (!isReadable(ptr, 4)) return null;
    try { return ptr.readU32(); } catch (e) { return null; }
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
