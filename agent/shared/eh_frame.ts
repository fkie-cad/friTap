// agent/shared/eh_frame.ts
//
// Function boundaries of a loaded ELF module from its in-memory .eh_frame_hdr
// binary-search table (PT_GNU_EH_FRAME). Stripped builds (Chrome's
// libmonochrome, Cronet) keep this table for C++ unwinding, so it bounds every
// function without symbols. functionBoundsFor() falls back to landing-pad bounds where no FDE covers an address.

import { BTI_C, PACIASP, endsFallThrough, isLandingPadWord } from "./arm64.js";
import type { FunctionBoundsSource } from "./arm64_xref.js";

const PT_LOAD = 1;
const PT_GNU_EH_FRAME = 0x6474e550;
const DW_EH_PE_udata4 = 0x03;
const DW_EH_PE_datarel_sdata4 = 0x3b;

/** Index of the last sorted table entry whose start is <= addr, or -1. */
export function searchSortedStarts(count: number, startAt: (i: number) => number, addr: number): number {
    let lo = 0, hi = count - 1, found = -1;
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (startAt(mid) <= addr) { found = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    return found;
}

/**
 * [start, end) of a function; end is null when its FDE is not decodable (or,
 * for landing-pad bounds, when no next landing pad was found).
 */
export interface FunctionBounds { start: NativePointer; end: NativePointer | null; }

/** Function boundaries from a module's in-memory .eh_frame_hdr binary-search table. */
export class EhFrameFunctionTable {
    private constructor(private readonly hdr: NativePointer, private readonly count: number) {}

    static fromModule(mod: Module): EhFrameFunctionTable | null {
        try {
            const hdr = ehFrameHdrOf(mod.base);
            if (hdr === null) return null;
            const [version, countEnc, tableEnc] = [hdr.readU8(), hdr.add(2).readU8(), hdr.add(3).readU8()];
            if (version !== 1 || countEnc !== DW_EH_PE_udata4 || tableEnc !== DW_EH_PE_datarel_sdata4) return null;
            const count = hdr.add(8).readU32();
            return count > 0 ? new EhFrameFunctionTable(hdr, count) : null;
        } catch (_e) {
            return null;
        }
    }

    private entryStart(i: number): number {
        return this.hdr.add(12 + i * 8).readS32();        // relative to hdr (datarel)
    }

    /** Bounds of the function containing `addr`, or null when no FDE covers it. */
    bounds(addr: NativePointer): FunctionBounds | null {
        try {
            const rel = addr.sub(this.hdr).toInt32();
            const i = searchSortedStarts(this.count, (k) => this.entryStart(k), rel);
            if (i < 0) return null;
            const start = this.hdr.add(this.entryStart(i));
            const end = this.fdeEnd(i, start);
            if (end !== null && addr.compare(end) >= 0) return null;   // not covered: missing FDE
            return { start, end };
        } catch (_e) {
            return null;
        }
    }

    /** FDE: u32 length, s32 CIE pointer, pc_begin (pcrel sdata4), pc_range. */
    private fdeEnd(i: number, start: NativePointer): NativePointer | null {
        const fde = this.hdr.add(this.hdr.add(12 + i * 8 + 4).readS32());
        const pcBeginField = fde.add(8);
        if (fde.readU32() === 0xffffffff || !pcBeginField.add(pcBeginField.readS32()).equals(start)) return null;
        return start.add(fde.add(12).readU32());
    }
}

/** Address of the module's .eh_frame_hdr (64-bit ELF program headers), or null. */
function ehFrameHdrOf(base: NativePointer): NativePointer | null {
    if (base.readU32() !== 0x464c457f) return null;             // "\x7fELF"
    const phoff = base.add(0x20).readU64().toNumber();
    const phentsize = base.add(0x36).readU16();
    const phnum = base.add(0x38).readU16();
    let ehVaddr = -1, minLoad = Number.MAX_SAFE_INTEGER;
    for (let i = 0; i < phnum; i++) {
        const ph = base.add(phoff + i * phentsize);
        const type = ph.readU32();
        const vaddr = ph.add(0x10).readU64().toNumber();
        if (type === PT_LOAD) minLoad = Math.min(minLoad, vaddr);
        if (type === PT_GNU_EH_FRAME) ehVaddr = vaddr;
    }
    if (ehVaddr < 0 || minLoad === Number.MAX_SAFE_INTEGER) return null;
    return base.add(ehVaddr - (minLoad - (minLoad % 0x1000)));
}

/** Identity of one loaded module (name + base + size) for the per-module caches. */
const moduleKey = (mod: Module) => `${mod.name}@${mod.base}+${mod.size}`;

const tablesByModule = new Map<string, EhFrameFunctionTable | null>();

/** The module's function table, built once per loaded module (name + base + size). */
export function ehFrameTableFor(mod: Module): EhFrameFunctionTable | null {
    const key = moduleKey(mod);
    if (!tablesByModule.has(key)) tablesByModule.set(key, EhFrameFunctionTable.fromModule(mod));
    return tablesByModule.get(key)!;
}

// --- Landing-pad fallback for addresses no FDE covers ---
//
// Some builds keep .eh_frame for only a few % of .text. With -mbranch-protection nearly every
// function starts with PACIASP or `bti c`, so the nearest pad at/before an address is its entry
// and the next pad after it approximates the end. Shrink-wrapping can put a `bti c` a few words
// before the PACIASP; that `bti c` is the entry. A function entered without a pad (static leaf,
// tail-called helper) is attributed to the preceding one, so this only backs up FDE bounds.

/** Furthest a landing-pad scan reaches back (start) or forward (end). */
export const LANDING_PAD_MAX_SCAN_BYTES = 0x10000;
/** First chunk a landing-pad scan reads in each direction; later chunks double. */
export const LANDING_PAD_FIRST_CHUNK_BYTES = 0x1000;
/** How far before a PACIASP a shrink-wrapped function's `bti c` entry may sit. */
export const BTI_BEFORE_PACIASP_MAX_WORDS = 16;

/** The 32-bit word at a byte address (any origin), or null when unreadable. */
export type WordReader = (at: number) => number | null;

/** `length` bytes at offset `from`, or null when unreadable. */
export type ByteRangeReader = (from: number, length: number) => ArrayBuffer | null;

const alignDown4 = (x: number) => Math.floor(x / 4) * 4;
const alignUp4 = (x: number) => Math.ceil(x / 4) * 4;

/** A function entry and the landing pad the backward scan stopped at (they differ when shrink-wrapped). */
interface LandingPadEntry { entry: number; pad: number; }

/**
 * Entry of the function containing `addr`: the nearest PACIASP or `bti c` at or
 * before it, scanning no further back than max(lowerBound, addr - maxBack).
 * Null when none is found in the window or a word is unreadable.
 */
export function findLandingPadStart(readU32: WordReader, addr: number, lowerBound: number,
                                    maxBack: number = LANDING_PAD_MAX_SCAN_BYTES): number | null {
    return scanLandingPadStart(readU32, addr, lowerBound, maxBack)?.entry ?? null;
}

function scanLandingPadStart(readU32: WordReader, addr: number, lowerBound: number,
                             maxBack: number): LandingPadEntry | null {
    const floor = alignUp4(Math.max(lowerBound, addr - maxBack));
    for (let at = alignDown4(addr); at >= floor; at -= 4) {
        const w = readU32(at);
        if (w === null) return null;
        if ((w >>> 0) === BTI_C) return { entry: at, pad: at };
        if ((w >>> 0) === PACIASP) return { entry: btiEntryBeforePaciasp(readU32, at, floor) ?? at, pad: at };
    }
    return null;
}

/** A `bti c` reached from `paciasp` through fall-through words only (shrink-wrapped prologue). */
function btiEntryBeforePaciasp(readU32: WordReader, paciasp: number, floor: number): number | null {
    for (let at = paciasp - 4; at >= floor && at >= paciasp - 4 * BTI_BEFORE_PACIASP_MAX_WORDS; at -= 4) {
        const w = readU32(at);
        if (w === null || endsFallThrough(w)) return null;
        if ((w >>> 0) === BTI_C) return at;
    }
    return null;
}

/**
 * Exclusive end of the function containing `addr`: the first PACIASP or `bti c`
 * strictly after it, below min(upperBound, addr + maxForward). Null when none.
 */
export function findLandingPadEnd(readU32: WordReader, addr: number, upperBound: number,
                                  maxForward: number = LANDING_PAD_MAX_SCAN_BYTES): number | null {
    const limit = Math.min(upperBound, addr + maxForward);
    for (let at = alignDown4(addr) + 4; at + 4 <= limit; at += 4) {
        const w = readU32(at);
        if (w === null) return null;
        if (isLandingPadWord(w)) return at;
    }
    return null;
}

/**
 * WordReader over the window [0, length) that reads lazily, outward from
 * `origin`: chunks of firstChunk, 2*firstChunk, ... bytes in each direction.
 * Words must be read at offsets congruent to `origin` mod 4 (the scans do), so
 * no word straddles two chunks. A failed chunk read makes that word unreadable.
 */
class ChunkedWordReader {
    private lo: number;
    private hi: number;
    private backChunk: number;
    private forwardChunk: number;
    private readonly chunks: { from: number; view: DataView }[] = [];

    constructor(private readonly readBytes: ByteRangeReader, private readonly length: number,
                origin: number, firstChunk: number = LANDING_PAD_FIRST_CHUNK_BYTES) {
        this.lo = this.hi = origin;
        this.backChunk = this.forwardChunk = firstChunk;
    }

    readonly read: WordReader = (at) => {
        if (at < 0 || at + 4 > this.length) return null;
        while (at < this.lo) if (!this.load(Math.max(0, this.lo - this.nextBackChunk()), this.lo)) return null;
        while (at + 4 > this.hi) if (!this.load(this.hi, Math.min(this.length, this.hi + this.nextForwardChunk()))) return null;
        const chunk = this.chunks.find((c) => at >= c.from && at + 4 <= c.from + c.view.byteLength)!;
        return chunk.view.getUint32(at - chunk.from, true);
    };

    private nextBackChunk(): number { const size = this.backChunk; this.backChunk *= 2; return size; }
    private nextForwardChunk(): number { const size = this.forwardChunk; this.forwardChunk *= 2; return size; }

    /** Load [from, to) (adjacent to the loaded span) and widen the span; false when unreadable. */
    private load(from: number, to: number): boolean {
        const buf = this.readBytes(from, to - from);
        if (buf === null) return false;
        this.chunks.push({ from, view: new DataView(buf) });
        this.lo = Math.min(this.lo, from);
        this.hi = Math.max(this.hi, to);
        return true;
    }
}

/** Sorted, non-overlapping [lo, hi) intervals, each with a value; looked up by a point inside. */
export class IntervalCache<T> {
    private readonly entries: { lo: number; hi: number; value: T }[] = [];

    get size(): number { return this.entries.length; }

    find(x: number): T | null {
        const i = searchSortedStarts(this.entries.length, (k) => this.entries[k].lo, x);
        return i >= 0 && x < this.entries[i].hi ? this.entries[i].value : null;
    }

    /** Insert [lo, hi); ignored when empty or overlapping a cached interval. */
    add(lo: number, hi: number, value: T): void {
        if (hi <= lo) return;
        const i = searchSortedStarts(this.entries.length, (k) => this.entries[k].lo, lo);
        const prev = this.entries[i], next = this.entries[i + 1];
        if ((prev && prev.hi > lo) || (next && next.lo < hi)) return;
        this.entries.splice(i + 1, 0, { lo, hi, value });
    }
}

/** [start, end) as module offsets. */
export interface OffsetBounds { start: number; end: number | null; }

/** The executable span [lo, hi) (module offsets, already clipped to the module) around a site. */
export type ExecSpanLookup = () => { lo: number; hi: number } | null;

/**
 * Landing-pad bounds per module, cached as [pad, end) so later sites in the same function skip
 * the scan. The interval starts at the pad, not the entry: a shrink-wrapped `bti c` prefix
 * scanned on its own ends at the PACIASP.
 */
export class LandingPadScanner {
    private readonly found = new IntervalCache<OffsetBounds>();

    constructor(private readonly readBytes: ByteRangeReader) {}

    bounds(off: number, execSpan: ExecSpanLookup): OffsetBounds | null {
        const cached = this.found.find(off);
        if (cached !== null) return cached;
        const span = execSpan();
        if (span === null) return null;
        const aligned = alignDown4(off);
        const low = Math.max(span.lo, aligned - LANDING_PAD_MAX_SCAN_BYTES);
        const high = Math.min(span.hi, aligned + LANDING_PAD_MAX_SCAN_BYTES + 4);
        if (aligned < low || aligned >= high) return null;
        const length = high - low, site = aligned - low;
        const reader = new ChunkedWordReader((from, len) => this.readBytes(low + from, len), length, site);
        // Offsets are relative to `low`, which the scans never pass.
        const start = scanLandingPadStart(reader.read, site, 0, LANDING_PAD_MAX_SCAN_BYTES);
        if (start === null) return null;
        const end = findLandingPadEnd(reader.read, site, length);
        const bounds: OffsetBounds = { start: low + start.entry, end: end === null ? null : low + end };
        if (end !== null) this.found.add(low + start.pad, low + end, bounds);
        return bounds;
    }
}

/** Landing-pad bounds inside one module; caches its executable ranges and found functions. */
class LandingPadFunctionBounds implements FunctionBoundsSource {
    private readonly scanner: LandingPadScanner;
    private execRanges: RangeDetails[] | null = null;

    constructor(private readonly mod: Module) {
        this.scanner = new LandingPadScanner((from, len) => mod.base.add(from).readByteArray(len));
    }

    bounds(addr: NativePointer): FunctionBounds | null {
        try {
            const base = this.mod.base;
            if (addr.compare(base) < 0 || addr.compare(base.add(this.mod.size)) >= 0) return null;
            const found = this.scanner.bounds(addr.sub(base).toUInt32(), () => this.execSpan(addr));
            if (found === null) return null;
            return { start: base.add(found.start), end: found.end === null ? null : base.add(found.end) };
        } catch (_e) {
            return null;
        }
    }

    /** The r-x range holding `addr` as module offsets clipped to the module, or null. */
    private execSpan(addr: NativePointer): { lo: number; hi: number } | null {
        this.execRanges ??= this.mod.enumerateRanges("r-x");
        const range = this.execRanges.find((r) => addr.compare(r.base) >= 0 && addr.compare(r.base.add(r.size)) < 0);
        if (range === undefined) return null;
        const base = this.mod.base, rangeEnd = range.base.add(range.size);
        const lo = range.base.compare(base) > 0 ? range.base.sub(base).toUInt32() : 0;
        const hi = rangeEnd.compare(base.add(this.mod.size)) < 0 ? rangeEnd.sub(base).toUInt32() : this.mod.size;
        return { lo, hi };
    }
}

/**
 * `primary` when it has [start, end). A `primary` start without an end keeps that start and
 * borrows only the fallback's end; with no `primary` at all, `fallback` alone.
 */
export class FallbackFunctionBounds implements FunctionBoundsSource {
    constructor(private readonly primary: FunctionBoundsSource,
                private readonly fallback: FunctionBoundsSource) {}

    bounds(addr: NativePointer): FunctionBounds | null {
        const primary = this.primary.bounds(addr);
        if (primary !== null && primary.end !== null) return primary;
        const fallback = this.fallback.bounds(addr);
        if (primary === null) return fallback;
        // The pad scan's start can be an earlier function's PACIASP; its end is the next pad after addr.
        return fallback !== null && fallback.end !== null ? { start: primary.start, end: fallback.end } : primary;
    }
}

/** `table` with `fallback` behind it, or `fallback` alone when there is no table. */
export function composeFunctionBounds(table: FunctionBoundsSource | null,
                                      fallback: FunctionBoundsSource): FunctionBoundsSource {
    return table === null ? fallback : new FallbackFunctionBounds(table, fallback);
}

const functionBoundsByModule = new Map<string, FunctionBoundsSource>();
const NO_FUNCTION_BOUNDS: FunctionBoundsSource = { bounds: () => null };

/**
 * Built once per module: FDE bounds where .eh_frame covers an address, landing-pad bounds
 * elsewhere. The pad encodings are AArch64, so other architectures get FDE bounds only.
 */
export function functionBoundsFor(mod: Module): FunctionBoundsSource {
    const key = moduleKey(mod);
    let source = functionBoundsByModule.get(key);
    if (source === undefined) {
        source = Process.arch === "arm64"
            ? composeFunctionBounds(ehFrameTableFor(mod), new LandingPadFunctionBounds(mod))
            : ehFrameTableFor(mod) ?? NO_FUNCTION_BOUNDS;
        functionBoundsByModule.set(key, source);
    }
    return source;
}
