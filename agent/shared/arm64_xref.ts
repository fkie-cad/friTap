// agent/shared/arm64_xref.ts
//
// Generic AArch64 cross-reference helpers: locate an ASCII anchor string in a
// module's data, find the code sites that materialise its address, and resolve
// the first direct call reached from a site. These are the module-walking
// counterparts of the pure instruction-word decoders in arm64.ts — they operate
// on Frida `Module`/`NativePointer` objects, whereas arm64.ts stays dependency-
// free number math.
//
// They were first written inline in agent/signal/libs/signal_libsignal.ts to
// anchor libsignal's HKDF discovery on the "WhisperMessageKeys" string. They are
// lifted here UNCHANGED in behaviour so a second consumer — the BoringSSL
// last-resort anchor locator (agent/shared/boringssl_anchor_locator.ts), which
// anchors on the NSS keylog label strings — can reuse them instead of copying.
// signal_libsignal.ts now delegates to these.
//
// IMPORTANT: never whole-module Memory.scanSync — that access-violates on large
// libraries. Every scan is restricted to the module's own ranges.

import { devlog, _isShuttingDownNow } from "../util/log.js";
import { toHexPattern } from "../util/hex.js";
import {
    isADRP, isADR, isADDimm64, isLDRimmU64, isBL, isBLR, isBLRAuth, endsFallThrough, writesReg,
    decodeADRPImm, decodeADRImm, decodeADDImm12, decodeLDRU64Imm, decodeBLImm, regRd, regRn,
    addImm64ScanPattern, ldrU64ScanPattern, adrTopByteForTarget,
} from "./arm64.js";

// ---- ARM64 address arithmetic (pure decoding lives in arm64.ts) ------------

/**
 * Compute the page address an ADRP at `pc` targets:
 * (pc & ~0xFFF) + decodeADRPImm(insn). The immediate decode (sign-extend,
 * << 12) is the pure, unit-tested helper; only the pointer math is here.
 */
export function adrpTarget(pc: NativePointer, insn: number): NativePointer {
    const pageImm = decodeADRPImm(insn);
    const pcPage = pc.and(ptr("0xfff").not()); // clear low 12 bits
    return pageImm >= 0 ? pcPage.add(pageImm) : pcPage.sub(-pageImm);
}

/**
 * Compute the byte address an ADR at `pc` materialises: pc + decodeADRImm(insn).
 * Unlike ADRP there is no page masking; the reach is ±1 MB.
 */
export function adrTarget(pc: NativePointer, insn: number): NativePointer {
    const offset = decodeADRImm(insn);
    return offset >= 0 ? pc.add(offset) : pc.sub(-offset);
}

/** Resolve a direct BL's target: pc + decodeBLImm(insn) (signed byte offset). */
export function blTarget(pc: NativePointer, insn: number): NativePointer {
    const offset = decodeBLImm(insn);
    return offset >= 0 ? pc.add(offset) : pc.sub(-offset);
}

/** True iff `addr` lies within [start, end). */
export function inModule(addr: NativePointer, start: NativePointer, end: NativePointer): boolean {
    return addr.compare(start) >= 0 && addr.compare(end) < 0;
}

// ---- anchor-string / xref walks --------------------------------------------

/**
 * Scan ONLY the module's readable (non-executable preferred) ranges for the
 * anchor ASCII bytes. Returns the address of the first match, or null.
 *
 * To pin a NUL-terminated string (so a label that is a prefix of a longer one
 * cannot match), pass the terminator in `ascii` (e.g. `"CLIENT_RANDOM\u0000"`).
 */
export function findAnchorString(mod: Module, ascii: string): NativePointer | null {
    const pattern = toHexPattern(ascii);
    const ranges = mod.enumerateRanges("r--");
    for (const range of ranges) {
        try {
            const hits = Memory.scanSync(range.base, range.size, pattern);
            if (hits.length > 0) return hits[0].address;
        } catch (_e) { /* skip unreadable range */ }
    }
    // Some builds keep rodata in an r-x range; try those as a fallback.
    const rx = mod.enumerateRanges("r-x");
    for (const range of rx) {
        try {
            const hits = Memory.scanSync(range.base, range.size, pattern);
            if (hits.length > 0) return hits[0].address;
        } catch (_e) { /* skip */ }
    }
    return null;
}

/**
 * Find EVERY instruction sequence within the module's executable ranges that
 * loads the address of `target` into a register, and return the address of the
 * ADRP (or ADR) that begins each one.
 *
 * Three code shapes are handled:
 *
 *   (1) Direct address materialisation (C/C++-style, also some Rust):
 *         ADRP Xd, page(target) ; ADD Xd, Xd, #lo12(target)
 *       page+imm == target.
 *
 *   (2) Pointer-slot indirection (Rust &str => a (ptr,len) static):
 *         ADRP Xd, page(slot) ; LDR Xd, [Xd, #lo12(slot)]
 *       slot = page + imm12*8 (64-bit scaled); *slot == target.
 *
 *   (3) Linker-relaxed direct materialisation: lld rewrites an adjacent
 *       `adrp Xd ; add Xd, Xd, :lo12:` into `nop ; adr Xd, target` whenever
 *       the target is within ±1 MB (common in small libraries):
 *         ADR Xd, target
 *       The ADR itself is the returned site.
 *
 * The ADD/LDR is NOT required to be the instruction immediately after the ADRP,
 * so we scan a small forward window after each ADRP, carrying the running value
 * of the ADRP destination register, and abandon the window as soon as any other
 * instruction may overwrite that register (writesReg — conservative, so an
 * unrecognised writer drops the candidate). Scans 4-byte aligned within each
 * r-x range only.
 */
export function findStringLoadSites(mod: Module, target: NativePointer): NativePointer[] {
    const ranges = mod.enumerateRanges("r-x");
    const WINDOW = 8; // instructions to look past each ADRP for the ADD/LDR
    const sites: NativePointer[] = [];
    const MAX_SITES = 8; // a sane cap; real builds have ~1
    for (const range of ranges) {
        const start = range.base;
        const end = range.base.add(range.size);
        let cursor = start;
        while (cursor.compare(end) < 0) {
            let adrp = 0;
            try {
                adrp = cursor.readU32();
            } catch (_e) {
                break; // range became unreadable; stop this range
            }
            if (isADRP(adrp)) {
                const rdAdrp = regRd(adrp);
                // Running value held in rdAdrp as we walk the window forward.
                let regVal: NativePointer = adrpTarget(cursor, adrp);
                for (let j = 1; j <= WINDOW; j++) {
                    const at = cursor.add(j * 4);
                    if (at.compare(end) >= 0) break;
                    let insn = 0;
                    try {
                        insn = at.readU32();
                    } catch (_e) {
                        break;
                    }
                    // A second ADRP into the same reg reloads it -> stop here.
                    if (isADRP(insn) && regRd(insn) === rdAdrp) break;
                    // ADD (immediate, 64-bit), in-place into rdAdrp (Rn == Rd).
                    if (isADDimm64(insn) && regRn(insn) === rdAdrp && regRd(insn) === rdAdrp) {
                        regVal = regVal.add(decodeADDImm12(insn));
                        // Case (1): the running value now equals the string addr.
                        if (regVal.equals(target)) { sites.push(cursor); break; }
                        continue; // may still be followed by an LDR (case 2 variant)
                    }
                    // LDR (immediate, unsigned offset, 64-bit), base Rn == rdAdrp.
                    if (isLDRimmU64(insn) && regRn(insn) === rdAdrp) {
                        const slot = regVal.add(decodeLDRU64Imm(insn));
                        try {
                            // Case (2): the slot holds a (relocated) pointer to
                            // the string bytes; *slot == target on a match.
                            if (slot.readPointer().equals(target)) sites.push(cursor);
                        } catch (_e) { /* slot not mapped/readable */ }
                        break; // rdAdrp now holds *slot; further walk is moot
                    }
                    // Any other writer (MOV, LDR from another base, LDP, MOVK, ...)
                    // replaces the page value -> this ADRP no longer reaches.
                    if (writesReg(insn, rdAdrp)) break;
                }
                if (sites.length >= MAX_SITES) return sites;
            } else if (isADR(adrp) && adrTarget(cursor, adrp).equals(target)) {
                // Case (3): linker-relaxed `adr Xd, target`.
                sites.push(cursor);
                if (sites.length >= MAX_SITES) return sites;
            }
            cursor = cursor.add(4);
        }
    }
    return sites;
}

// ---- native, chunked, multi-target variants (BoringSSL tier 4) --------------
//
// findStringLoadSites() above walks every code word in JS. That is fine for
// libsignal's few MB, but on Chrome's libchrome.so (~187 MB of r-x code) it took
// ~10 minutes PER LABEL and blocked the agent's JS thread throughout. The
// variants below find the same two code shapes with native Memory.scanSync:
//
//   (1) ADRP Xd, page(T) ; ADD Xd, Xd, #lo12(T)
//       The ADD's imm12 is fixed by the target (T & 0xfff), so "ADD-imm64 with
//       this imm12, any registers" is one masked scan word. Each hit is then
//       verified by walking BACK (<= LOAD_SITE_WINDOW words) to the ADRP that
//       opens it and checking that ADRP's page is page(T).
//   (2) ADRP Xd, page(S) ; LDR Xt, [Xd, #lo12(S)]   with *S == T
//       The pointer slots S are first found natively in the module's data
//       ranges; each slot then contributes an "LDR-imm64 with imm12 = lo12(S)/8"
//       scan word, verified the same way.
//
//   (3) ADR Xd, T   (lld's relaxation of an adjacent ADRP+ADD, T within ±1 MB)
//       Scanned only in the ±1 MB code window around each T (findAdrSites).
//
// All targets share ONE pass over the ranges: each chunk is scanned for every
// distinct pattern before moving on, and the pass yields to the JS event loop
// between chunks, so other hooks, messages and detach keep working mid-scan.

/** Instructions the ADD/LDR may sit after its ADRP (same window as findStringLoadSites). */
export const LOAD_SITE_WINDOW = 8;
/** Per-target site cap (same cap as findStringLoadSites). */
export const MAX_LOAD_SITES = 8;
/** Bytes scanned per chunk before yielding to the event loop. */
export const XREF_SCAN_CHUNK_BYTES = 2 * 1024 * 1024;

export interface ScanRange { base: NativePointer; size: number; }

/** One distinct match pattern plus the handlers of every target that uses it. */
export interface ChunkScanJob {
    pattern: string;
    onMatch: (addr: NativePointer) => void;
}

/** Thrown by scanRangesChunked when the agent starts shutting down mid-scan. */
export class XrefScanAborted extends Error {
    constructor() { super("xref scan aborted: agent is shutting down"); }
}

/** Default event-loop yield between chunks (Frida and Node both provide setTimeout). */
export function yieldToEventLoop(): Promise<void> {
    return new Promise<void>((resolve) => setTimeout(resolve, 0));
}

/** Byte length of a "aa bb ?? : ff ff 00"-style pattern (tokens before the mask). */
export function patternByteLength(pattern: string): number {
    return pattern.split(":")[0].trim().split(/\s+/).filter((t) => t.length > 0).length;
}

/** Compile once per pass when Frida's MatchPattern exists (absent under Node tests). */
function compilePattern(pattern: string): string | MatchPattern {
    try {
        if (typeof MatchPattern !== "undefined") return new MatchPattern(pattern);
    } catch (_e) { /* fall back to the string form */ }
    return pattern;
}

/**
 * Scan `ranges` in `chunkBytes` slices for every job's pattern, calling each
 * job's onMatch in address order within a chunk, and yielding between chunks.
 * Slices overlap by (longest pattern - 1) bytes so no match straddling a chunk
 * boundary is lost; a match is reported only by the chunk it STARTS in.
 * An unreadable slice is skipped, never fatal. Once the agent starts shutting
 * down (detach / SIGINT) the pass stops at the next chunk with XrefScanAborted,
 * so no scan keeps spinning inside the target after the host went away.
 */
export async function scanRangesChunked(
    ranges: ScanRange[],
    jobs: ChunkScanJob[],
    chunkBytes: number = XREF_SCAN_CHUNK_BYTES,
    yieldFn: () => Promise<void> = yieldToEventLoop,
): Promise<void> {
    if (jobs.length === 0) return;
    const compiled = jobs.map((j) => compilePattern(j.pattern));
    const overlap = Math.max(...jobs.map((j) => patternByteLength(j.pattern))) - 1;
    for (const range of ranges) {
        for (let off = 0; off < range.size; off += chunkBytes) {
            if (_isShuttingDownNow()) throw new XrefScanAborted();
            const chunkStart = range.base.add(off);
            const chunkEnd = range.base.add(Math.min(off + chunkBytes, range.size));
            const scanSize = Math.min(chunkBytes + overlap, range.size - off);
            for (let i = 0; i < jobs.length; i++) {
                let hits: MemoryScanMatch[] = [];
                try {
                    hits = Memory.scanSync(chunkStart, scanSize, compiled[i]);
                } catch (_e) { continue; /* unreadable slice */ }
                for (const hit of hits) {
                    if (hit.address.compare(chunkEnd) < 0) jobs[i].onMatch(hit.address);
                }
            }
            await yieldFn();
        }
    }
}

/**
 * Walk back from the ADD/LDR at `at` (base register `reg`) to the ADRP that
 * opens its sequence, at most LOAD_SITE_WINDOW words and never before
 * `rangeStart`. Returns that ADRP's address iff it targets `page`.
 *
 * Mirrors findStringLoadSites' forward window: the nearest ADRP into `reg` is the
 * one in effect (a later one would have reloaded it); an intervening LDR off
 * `reg`, or ANY intervening instruction that may write `reg` (writesReg — MOV,
 * MOVZ/MOVK, ADD/SUB, LDR/LDP into it, writeback, ...), ends the forward walk
 * there, so it rejects here too. writesReg is conservative: fail closed.
 */
export function findOpeningAdrp(
    at: NativePointer, reg: number, page: NativePointer, rangeStart: NativePointer,
): NativePointer | null {
    for (let j = 1; j <= LOAD_SITE_WINDOW; j++) {
        const p = at.sub(j * 4);
        if (p.compare(rangeStart) < 0) return null;
        let insn = 0;
        try {
            insn = p.readU32();
        } catch (_e) {
            return null;
        }
        if (isADRP(insn) && regRd(insn) === reg) {
            return adrpTarget(p, insn).equals(page) ? p : null;
        }
        if (isADDimm64(insn) && regRd(insn) === reg) return null;
        if (isLDRimmU64(insn) && regRn(insn) === reg) return null;
        if (writesReg(insn, reg)) return null;
    }
    return null;
}

/** Page base (low 12 bits cleared) and page offset of `addr`. */
function splitPage(addr: NativePointer): { page: NativePointer; lo12: number } {
    const page = addr.and(ptr("0xfff").not());
    return { page, lo12: addr.sub(page).toInt32() };
}

/** 8-byte little-endian pattern of a pointer value (for locating pointer slots). */
export function pointerScanPattern(value: NativePointer): string {
    const hex = value.toString().replace(/^0x/i, "").padStart(16, "0");
    const bytes: string[] = [];
    for (let i = 14; i >= 0; i -= 2) bytes.push(hex.substring(i, i + 2));
    return bytes.join(" ");
}

/** Readable, NON-executable ranges of `mod` (Frida's "r--" filter includes r-x). */
function dataRanges(mod: Module): ScanRange[] {
    return mod.enumerateRanges("r--").filter((r) => !r.protection.includes("x"));
}

/** Add a handler to the job for `pattern`, creating the job on first use. */
function addJob(jobs: Map<string, ((a: NativePointer) => void)[]>, pattern: string, h: (a: NativePointer) => void): void {
    const list = jobs.get(pattern);
    if (list) list.push(h); else jobs.set(pattern, [h]);
}

function toJobs(jobs: Map<string, ((a: NativePointer) => void)[]>): ChunkScanJob[] {
    return [...jobs].map(([pattern, handlers]) => ({
        pattern,
        onMatch: (a: NativePointer) => { for (const h of handlers) h(a); },
    }));
}

/** True iff `addr` is `align`-byte aligned. */
function isAligned(addr: NativePointer, align: number): boolean {
    return (addr.and(ptr(align - 1)).toInt32()) === 0;
}

/**
 * Locate the pointer slots in the module's data ranges that hold each target
 * (shape (2)). One chunked pass for all targets; 8-byte aligned slots only.
 */
async function findPointerSlots(
    mod: Module, targets: NativePointer[], chunkBytes: number, yieldFn: () => Promise<void>,
): Promise<NativePointer[][]> {
    const slots: NativePointer[][] = targets.map(() => []);
    const jobs = new Map<string, ((a: NativePointer) => void)[]>();
    targets.forEach((t, i) => addJob(jobs, pointerScanPattern(t), (a) => {
        if (isAligned(a, 8) && slots[i].length < MAX_LOAD_SITES) slots[i].push(a);
    }));
    await scanRangesChunked(dataRanges(mod), toJobs(jobs), chunkBytes, yieldFn);
    return slots;
}

/**
 * Async, native-scan, multi-target counterpart of findStringLoadSites(): for
 * each target, the ADRP addresses of the sequences that materialise it (shape
 * (1)) or load it from a pointer slot (shape (2)), ascending, capped at
 * MAX_LOAD_SITES. Result index i belongs to targets[i]. ONE pass over the code
 * ranges serves every target, yielding between chunks.
 *
 * Shape (3), the linker-relaxed `adr Xd, target`, is found by findAdrSites:
 * an ADR reaches only ±1 MB, so only the code within that window of each
 * target is scanned for it.
 *
 * Not covered (unlike the JS walk): ADRP + ADD + LDR (computing &slot then
 * loading it). BoringSSL's labels are plain string literals, so its tier 4
 * never needs it; Signal keeps the full JS walk.
 */
export async function findStringLoadSitesAsync(
    mod: Module,
    targets: NativePointer[],
    chunkBytes: number = XREF_SCAN_CHUNK_BYTES,
    yieldFn: () => Promise<void> = yieldToEventLoop,
): Promise<NativePointer[][]> {
    const sites: NativePointer[][] = targets.map(() => []);
    const slots = await findPointerSlots(mod, targets, chunkBytes, yieldFn);
    const jobs = new Map<string, ((a: NativePointer) => void)[]>();
    let rangeStart: NativePointer = mod.base;
    const verifyAt = (i: number, page: NativePointer, isShape: (insn: number) => boolean) =>
        (at: NativePointer) => {
            if (!isAligned(at, 4)) return;
            let insn = 0;
            try { insn = at.readU32(); } catch (_e) { return; }
            if (!isShape(insn)) return;
            const adrp = findOpeningAdrp(at, regRn(insn), page, rangeStart);
            if (adrp !== null) sites[i].push(adrp);
        };
    targets.forEach((t, i) => {
        const { page, lo12 } = splitPage(t);
        // Shape (1): in-place ADD (Rd == Rn), as findStringLoadSites requires.
        addJob(jobs, addImm64ScanPattern(lo12), verifyAt(i, page,
            (w) => isADDimm64(w) && regRd(w) === regRn(w)));
        // Shape (2): LDR from each slot holding the target.
        for (const slot of slots[i]) {
            const s = splitPage(slot);
            addJob(jobs, ldrU64ScanPattern(s.lo12 / 8), verifyAt(i, s.page, (w) => isLDRimmU64(w)));
        }
    });
    const codeJobs = toJobs(jobs);
    for (const range of mod.enumerateRanges("r-x")) {
        rangeStart = range.base;
        await scanRangesChunked([range], codeJobs, chunkBytes, yieldFn);
    }
    await findAdrSites(mod, targets, sites, chunkBytes, yieldFn);
    return sites.map((list) => dedupeSorted(list).slice(0, MAX_LOAD_SITES));
}

// ---- shape (3): linker-relaxed ADR ------------------------------------------

/** ADR's signed 21-bit byte immediate reaches [-1 MB, +1 MB). */
export const ADR_REACH_BYTES = 1024 * 1024;
/** Slack past the window's high end so the top byte of its last word is scanned. */
const ADR_WINDOW_SLACK = 8;

/** `range` ∩ [lo, hi), or null when they do not overlap. */
function clipRange(range: ScanRange, lo: NativePointer, hi: NativePointer): ScanRange | null {
    const end = range.base.add(range.size);
    const base = range.base.compare(lo) > 0 ? range.base : lo;
    const top = end.compare(hi) < 0 ? end : hi;
    return base.compare(top) < 0 ? { base, size: top.sub(base).toInt32() } : null;
}

/** Sort by base and coalesce overlapping / touching ranges. */
function mergeRanges(list: ScanRange[]): ScanRange[] {
    const sorted = [...list].sort((a, b) => a.base.compare(b.base));
    const out: ScanRange[] = [];
    for (const r of sorted) {
        const last = out[out.length - 1];
        if (last && r.base.compare(last.base.add(last.size)) <= 0) {
            const end = r.base.add(r.size);
            if (end.compare(last.base.add(last.size)) > 0) last.size = end.sub(last.base).toInt32();
        } else {
            out.push({ base: r.base, size: r.size });
        }
    }
    return out;
}

/**
 * The code an ADR to any of `targets` could sit in: each code range clipped to
 * [target - 1 MB, target + 1 MB), unioned over the targets. Everything outside
 * cannot hold such an ADR, so it is never scanned.
 */
export function adrScanWindows(codeRanges: ScanRange[], targets: NativePointer[]): ScanRange[] {
    const reach = ptr(ADR_REACH_BYTES);
    const windows: ScanRange[] = [];
    for (const t of targets) {
        const lo = t.compare(reach) >= 0 ? t.sub(reach) : ptr(0);
        const hi = t.add(ADR_REACH_BYTES + ADR_WINDOW_SLACK);
        for (const r of codeRanges) {
            const w = clipRange(r, lo, hi);
            if (w !== null) windows.push(w);
        }
    }
    return mergeRanges(windows);
}

/** True iff `addr` starts a whole 4-byte word inside one of `ranges`. */
function wordInRanges(addr: NativePointer, ranges: ScanRange[]): boolean {
    return ranges.some((r) => addr.compare(r.base) >= 0 && addr.add(4).compare(r.base.add(r.size)) <= 0);
}

/**
 * Append to sites[i] every `ADR Xd, targets[i]` in the module's code. Targets
 * are grouped by their low 2 bits, which fix the ADR's top byte (see
 * adrTopByteForTarget); each group scans only its ±1 MB windows for that one
 * byte, natively and chunked (shutdown-aware, yielding), and verifies each hit
 * by decoding the whole word.
 */
async function findAdrSites(
    mod: Module, targets: NativePointer[], sites: NativePointer[][],
    chunkBytes: number, yieldFn: () => Promise<void>,
): Promise<void> {
    const code = mod.enumerateRanges("r-x") as ScanRange[];
    for (let low2 = 0; low2 < 4; low2++) {
        const group = targets.filter((t) => t.and(ptr(3)).toInt32() === low2);
        if (group.length === 0) continue;
        const byAddress = new Map<string, number[]>(); // target address -> target indices
        targets.forEach((t, i) => {
            if (t.and(ptr(3)).toInt32() === low2) byAddress.set(t.toString(), [...(byAddress.get(t.toString()) ?? []), i]);
        });
        const onTopByte = (hit: NativePointer) => {
            const at = hit.sub(3); // the top byte is the word's last byte in memory
            if (!isAligned(at, 4) || !wordInRanges(at, code)) return;
            let insn = 0;
            try { insn = at.readU32(); } catch (_e) { return; }
            if (!isADR(insn)) return;
            for (const i of byAddress.get(adrTarget(at, insn).toString()) ?? []) sites[i].push(at);
        };
        const needle = adrTopByteForTarget(low2).toString(16).padStart(2, "0");
        await scanRangesChunked(adrScanWindows(code, group), [{ pattern: needle, onMatch: onTopByte }],
            chunkBytes, yieldFn);
    }
}

/** Ascending, duplicate-free copy of `list`. */
function dedupeSorted(list: NativePointer[]): NativePointer[] {
    const sorted = [...list].sort((a, b) => a.compare(b));
    return sorted.filter((p, k) => k === 0 || !p.equals(sorted[k - 1]));
}

/**
 * Async multi-string counterpart of findAnchorString(): the first address of
 * each ASCII string (pass the NUL in it to pin the terminator), or null. Data
 * ranges are scanned first; executable ranges only for strings still missing,
 * matching findAnchorString's r-- then r-x fallback. One chunked pass per group.
 */
export async function findAnchorStringsAsync(
    mod: Module,
    asciis: string[],
    chunkBytes: number = XREF_SCAN_CHUNK_BYTES,
    yieldFn: () => Promise<void> = yieldToEventLoop,
): Promise<(NativePointer | null)[]> {
    const found: (NativePointer | null)[] = asciis.map(() => null);
    for (const ranges of [dataRanges(mod), mod.enumerateRanges("r-x") as ScanRange[]]) {
        const jobs = new Map<string, ((a: NativePointer) => void)[]>();
        asciis.forEach((s, i) => {
            if (found[i] === null) addJob(jobs, toHexPattern(s), (a) => { if (found[i] === null) found[i] = a; });
        });
        if (jobs.size === 0) break;
        await scanRangesChunked(ranges, toJobs(jobs), chunkBytes, yieldFn);
    }
    return found;
}

/**
 * Walk forward from `from` (exclusive of its own instruction) toward `limit` and
 * return the resolved target of the FIRST BL/BLR encountered. BL has a
 * PC-relative immediate; BLR is an indirect call whose target we cannot
 * statically resolve, so a BLR makes discovery unreliable and we bail.
 *
 * The walk models straight-line fall-through, so it also stops (null) at any
 * instruction after which execution does not fall through (endsFallThrough:
 * unconditional B, RET/RETAA/RETAB, BR*, BRK/UDF). Without this, a site that
 * tail-calls its callee (`b ssl_log_secret`) or simply returns would "resolve"
 * the first BL of the NEXT function. An unconditional B is deliberately not
 * followed nor voted for: from the word alone a tail call cannot be told apart
 * from an intra-function jump (loop, if/else join, cross-jumped call block),
 * so its target is not known to be the callee. Losing that site's vote is the
 * fail-closed outcome.
 */
export function firstCallTargetForward(
    from: NativePointer, limit: NativePointer, modStart: NativePointer, modEnd: NativePointer,
): NativePointer | null {
    let cursor = from.add(4);
    const maxWalk = 0x400; // ~256 instructions; the call is very close
    let walked = 0;
    while (cursor.compare(limit) < 0 && walked < maxWalk) {
        let insn = 0;
        try {
            insn = cursor.readU32();
        } catch (_e) {
            return null;
        }
        // BL is a direct, resolvable PC-relative call.
        if (isBL(insn)) {
            const tgt = blTarget(cursor, insn);
            if (inModule(tgt, modStart, modEnd)) return tgt;
        }
        // BLR is an indirect call whose target we cannot statically resolve.
        if (isBLR(insn) || isBLRAuth(insn)) {
            devlog(`[arm64-xref] forward walk hit unresolvable BLR @ ${cursor}`);
            return null;
        }
        // Tail call, return, indirect jump or trap: the next word is not reached.
        if (endsFallThrough(insn)) {
            devlog(`[arm64-xref] forward walk hit a non-fall-through instruction @ ${cursor} before any BL`);
            return null;
        }
        cursor = cursor.add(4);
        walked += 4;
    }
    return null;
}
