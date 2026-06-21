/**
 * scan_safety.ts — keeps the PUBLIC memory-scan engine from reading memory that
 * crashes the target (or the agent itself).
 *
 * Three classes of hazard, each handled here:
 *  1. Non-data / hostile regions — only scan readable+writable (rw, non-exec)
 *     ranges; probe readability before AND periodically during a scan (mappings
 *     can be torn down mid-scan), and skip anti-tamper-guarded modules
 *     (matchAntiTamper, currently PairIP) plus a generic VOLATILE denylist
 *     (Scudo/GWP-ASan/HWASan-MTE/guard pages) that fault or self-mutate on read.
 *     Prior recursive scans over libringrtc/libsignal SIGSEGV'd the agent — this
 *     denylist is the generic backstop (see memory signal-libringrtc-crash).
 *  2. The agent's own memory — never scan frida-gum / frida-agent / the
 *     linker-mapped JS runtime (memfd:frida*). Scanning these is pointless and
 *     can re-enter the running scanner.
 *  3. Re-entrancy — (2) also covers "never scan the range backing the scanner",
 *     because the scanner's buffers live in the agent's own (excluded) ranges.
 *
 * Pure predicates only; no scanning, no hook installation.
 */
import { matchAntiTamper } from "../../util/anti_tamper.js";
import { devlog } from "../../util/log.js";

/** Re-validate readability at least this often while walking a large range. */
export const REVALIDATE_INTERVAL_BYTES = 1024 * 1024; // 1 MiB

/** True for readable ranges (first protection char is 'r'). */
export function protectionIsReadable(protection: string): boolean {
    return protection.length >= 1 && protection[0] === "r";
}

/**
 * True for ranges worth scanning for key material: readable AND writable AND
 * NOT executable. Long-lived secrets live in writable data/heap; excluding 'x'
 * keeps us off code pages (no keys there, and some are execute-only).
 */
export function protectionIsScannable(protection: string): boolean {
    return (
        protection.length >= 3 &&
        protection[0] === "r" &&
        protection[1] === "w" &&
        protection[2] !== "x"
    );
}

/**
 * Generic denylist of mapping names/paths that fault or self-mutate when read,
 * or that belong to the instrumentation runtime. Matched against a range's
 * backing file path (and the owning module name). Author-maintained here because
 * anti_tamper.ts only tracks active anti-tamper libraries (PairIP), not these
 * allocator/sanitizer regions.
 */
const VOLATILE_PATH_PATTERNS: ReadonlyArray<RegExp> = [
    // Frida instrumentation runtime (agent's own memory — see isAgentOwnedRange too).
    /frida/i,
    /gum-js-loop/i,
    /\/memfd:.*\b(frida|gum|jit)\b/i,
    // Hardened/sanitizer allocators: reads can trip tag checks or guard pages.
    /\[anon:scudo/i,
    /\bGWP-ASan\b/i,
    /\bhwasan\b/i,
    /\[anon:.*\bmte\b/i,
    /\[anon:.*guard/i,
    /\bstack_mte_ring\b/i,
];

/** True if a backing path looks volatile/hostile to read. */
export function isVolatilePath(path: string | undefined | null): boolean {
    if (!path) return false;
    for (const re of VOLATILE_PATH_PATTERNS) {
        if (re.test(path)) return true;
    }
    return false;
}

/** A half-open address interval [base, end). */
export interface OwnedRange { base: NativePointer; end: NativePointer; }

/**
 * Build the set of memory ranges that belong to the agent itself (frida-gum,
 * frida-agent, the linker-mapped JS runtime / memfd:frida*). The engine must
 * never scan these — both to avoid wasted work and to prevent re-entering the
 * running scanner. Call once per scan and reuse the result.
 */
export function buildAgentOwnedRanges(): OwnedRange[] {
    const owned: OwnedRange[] = [];
    const seen = new Set<string>();
    const add = (base: NativePointer, size: number) => {
        if (size <= 0) return;
        const key = base.toString();
        if (seen.has(key)) return;
        seen.add(key);
        owned.push({ base, end: base.add(size) });
    };
    try {
        for (const mod of Process.enumerateModules()) {
            if (isVolatilePath(mod.path) || isVolatilePath(mod.name)) {
                add(mod.base, mod.size);
            }
        }
    } catch (e) {
        devlog(`[scan_safety] enumerateModules failed: ${e}`);
    }
    try {
        // Catch anonymous JS-runtime mappings that are not exposed as modules.
        for (const r of Process.enumerateRanges("r--")) {
            if (r.file && isVolatilePath(r.file.path)) {
                add(r.base, r.size);
            }
        }
    } catch (e) {
        devlog(`[scan_safety] enumerateRanges(r--) failed: ${e}`);
    }
    return owned;
}

/** True if [base, base+size) overlaps any agent-owned range. */
export function isAgentOwnedRange(base: NativePointer, size: number, owned: OwnedRange[]): boolean {
    const end = base.add(size);
    for (const o of owned) {
        // overlap iff base < o.end && o.base < end
        if (base.compare(o.end) < 0 && o.base.compare(end) < 0) return true;
    }
    return false;
}

/**
 * Probe that [base, base+size) is still readable. Mappings can be unmapped
 * between enumeration and access, so this is called before a range and again
 * every REVALIDATE_INTERVAL_BYTES. Reads one byte at the start and one near the
 * end; a fault (bad access) means "not readable".
 */
export function isRangeStillReadable(base: NativePointer, size: number): boolean {
    if (size <= 0) return false;
    try {
        if (base.readByteArray(1) === null) return false;
        if (size > 1) {
            if (base.add(size - 1).readByteArray(1) === null) return false;
        }
        return true;
    } catch (_e) {
        return false;
    }
}

export interface RangeSafety { safe: boolean; reason: string; }

/**
 * Decide whether a single range is safe to scan. Combines: scannable protection
 * (rw, non-exec), not agent-owned, owning module not anti-tamper-guarded,
 * backing path not volatile, and currently readable.
 */
export function isScanSafeRange(
    range: RangeDetails,
    owned: OwnedRange[],
): RangeSafety {
    if (!protectionIsScannable(range.protection)) {
        return { safe: false, reason: `protection ${range.protection} (need rw, non-exec)` };
    }
    if (isAgentOwnedRange(range.base, range.size, owned)) {
        return { safe: false, reason: "agent-owned range" };
    }
    if (range.file && isVolatilePath(range.file.path)) {
        return { safe: false, reason: `volatile path ${range.file.path}` };
    }
    const owningModule = Process.findModuleByAddress(range.base);
    if (owningModule) {
        const at = matchAntiTamper(owningModule.name);
        if (at) {
            return { safe: false, reason: `anti-tamper module ${owningModule.name} (${at.name})` };
        }
        if (isVolatilePath(owningModule.name) || isVolatilePath(owningModule.path)) {
            return { safe: false, reason: `volatile module ${owningModule.name}` };
        }
    }
    if (!isRangeStillReadable(range.base, range.size)) {
        return { safe: false, reason: "not readable (unmapped?)" };
    }
    return { safe: true, reason: "ok" };
}
