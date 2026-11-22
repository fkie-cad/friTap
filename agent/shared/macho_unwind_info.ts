// agent/shared/macho_unwind_info.ts
//
// Function boundaries of a loaded arm64 Mach-O image from __TEXT,__unwind_info
// (compact unwind). Chrome/Electron frameworks carry no LC_FUNCTION_STARTS and
// almost no symbols, but every function has a compact-unwind entry. lld folds
// adjacent functions with identical encodings into one entry, so a table range
// can hold several functions; splitMergedRange() recovers their entries.

import {
    endsFallThrough, directBranchOffset, isBL, isEntryPrologueWord, isFrameSetupWord, isTrap, isUnconditionalB,
    isIndirectBranch,
} from "./arm64.js";
import type { FunctionBoundsSource } from "./arm64_xref.js";
import type { FunctionBounds, OffsetBounds } from "./eh_frame.js";
import { machOSectionRange } from "./macho_header.js";
import { type ModuleByteReader, moduleMemoryReader, searchSortedStarts } from "./module_mapping.js";

const UNWIND_SECTION_VERSION = 1;
const UNWIND_HEADER_BYTES = 28;
const FIRST_LEVEL_ENTRY_BYTES = 12;
const SECOND_LEVEL_REGULAR = 2;
const SECOND_LEVEL_COMPRESSED = 3;
const REGULAR_ENTRY_BYTES = 8;
/** Largest table range read in one piece to split merged functions; larger ones stay whole. */
export const MERGED_SPLIT_MAX_BYTES = 0x400000;

/** Sorted unique function starts (image offsets) and the sentinel end of the last one. */
export interface UnwindStartTable { starts: Uint32Array; end: number | null; }

/**
 * Function starts from an __unwind_info section (v1): first-level index, then
 * REGULAR (offset, encoding) or COMPRESSED (24-bit offset from the index entry)
 * second-level pages. Null when malformed. Never throws.
 */
export function parseUnwindInfoStarts(info: Uint8Array): UnwindStartTable | null {
    try {
        const dv = new DataView(info.buffer, info.byteOffset, info.byteLength);
        if (dv.getUint32(0, true) !== UNWIND_SECTION_VERSION || info.length < UNWIND_HEADER_BYTES) return null;
        const indexOffset = dv.getUint32(20, true), indexCount = dv.getUint32(24, true);
        if (indexCount === 0) return null;
        const pageAt = (i: number) => dv.getUint32(indexOffset + i * FIRST_LEVEL_ENTRY_BYTES + 4, true);
        let total = 0;
        for (let i = 0; i + 1 < indexCount; i++) total += secondLevelEntryCount(dv, pageAt(i));
        const all = new Uint32Array(total);
        let n = 0;
        for (let i = 0; i + 1 < indexCount; i++) {
            n = readSecondLevelPage(dv, pageAt(i), dv.getUint32(indexOffset + i * FIRST_LEVEL_ENTRY_BYTES, true), all, n);
        }
        const starts = sortedUnique(all.subarray(0, n));
        const sentinel = dv.getUint32(indexOffset + (indexCount - 1) * FIRST_LEVEL_ENTRY_BYTES, true);
        return starts.length > 0 ? { starts, end: sentinel > starts[starts.length - 1] ? sentinel : null } : null;
    } catch (_e) {
        return null;
    }
}

/** Entries of a REGULAR / COMPRESSED page; 0 for no page or an unknown kind. */
function secondLevelEntryCount(dv: DataView, page: number): number {
    if (page === 0) return 0;
    const kind = dv.getUint32(page, true);
    return kind === SECOND_LEVEL_REGULAR || kind === SECOND_LEVEL_COMPRESSED ? dv.getUint16(page + 6, true) : 0;
}

/** Writes the page's function starts into `out` from index `n`; returns the next free index. */
function readSecondLevelPage(dv: DataView, page: number, pageFunctionBase: number, out: Uint32Array, n: number): number {
    const count = secondLevelEntryCount(dv, page);
    if (count === 0) return n;
    const compressed = dv.getUint32(page, true) === SECOND_LEVEL_COMPRESSED;
    const entries = page + dv.getUint16(page + 4, true);
    for (let k = 0; k < count; k++) {
        out[n++] = compressed ? pageFunctionBase + (dv.getUint32(entries + k * 4, true) & 0xffffff)
                              : dv.getUint32(entries + k * REGULAR_ENTRY_BYTES, true);
    }
    return n;
}

/** `a` sorted (in place, only when not already ascending) with adjacent duplicates dropped. */
function sortedUnique(a: Uint32Array): Uint32Array {
    for (let k = 1; k < a.length; k++) {
        if (a[k] < a[k - 1]) { a.sort(); break; }
    }
    let m = 0;
    for (let k = 0; k < a.length; k++) if (m === 0 || a[k] !== a[m - 1]) a[m++] = a[k];
    return a.subarray(0, m);
}

const CONDITIONAL_TARGET = 1;
const UNCONDITIONAL_TARGET = 2;

/** Per word of `words`: which kinds of direct branch in the range target it; and whether a BR is present. */
function branchTargets(words: Uint32Array): { targets: Uint8Array; hasIndirectJump: boolean } {
    const targets = new Uint8Array(words.length);
    let hasIndirectJump = false;
    for (let k = 0; k < words.length; k++) {
        const w = words[k];
        if (isIndirectBranch(w)) { hasIndirectJump = true; continue; }
        const off = directBranchOffset(w);
        if (off === null) continue;
        const t = k + off / 4;
        if (t >= 0 && t < words.length) targets[t] |= isUnconditionalB(w) ? UNCONDITIONAL_TARGET : CONDITIONAL_TARGET;
    }
    return { targets, hasIndirectJump };
}

/**
 * Function entries inside one table range [start, end) given its words: start itself,
 * plus each word no conditional branch in the range targets (that would be an inner
 * label) that is a prologue after RET / B / BR / BRK / padding, or frame setup after a
 * BL (a noreturn call ends the previous function; no frame is set up after a call in
 * the same function). A word no B targets either also starts a (leaf) function after
 * BRK / padding, or after RET / B in a range without BR, whose jump-table targets are
 * reached indirectly.
 */
export function splitMergedRange(words: Uint32Array, start: number): Uint32Array {
    const entries = [start];
    const { targets, hasIndirectJump } = branchTargets(words);
    for (let k = 1; k < words.length; k++) {
        const w = words[k], prev = words[k - 1];
        if ((targets[k] & CONDITIONAL_TARGET) !== 0 || isTrap(w)) continue;
        const prologue = isEntryPrologueWord(w) && (endsFallThrough(prev) || (isBL(prev) && isFrameSetupWord(w)));
        const unreachedLeaf = (targets[k] & UNCONDITIONAL_TARGET) === 0
            && (isTrap(prev) || (!hasIndirectJump && endsFallThrough(prev)));
        if (prologue || unreachedLeaf) entries.push(start + k * 4);
    }
    return Uint32Array.from(entries);
}

/** `length` bytes as words, viewing the buffer in place when it is word-aligned. */
function asWords(bytes: Uint8Array, length: number): Uint32Array {
    return bytes.byteOffset % 4 === 0
        ? new Uint32Array(bytes.buffer, bytes.byteOffset, length / 4)
        : new Uint32Array(bytes.slice(0, length).buffer);
}

/** Function bounds over image offsets from an unwind start table; splits merged ranges lazily. */
export class UnwindFunctionTable {
    private readonly splits = new Map<number, Uint32Array>();

    constructor(private readonly table: UnwindStartTable, readonly textStart: number, readonly textEnd: number,
                private readonly readBytes: ModuleByteReader) {}

    get starts(): Uint32Array { return this.table.starts; }

    /** [start, end) of the function containing image offset `off`, or null outside __text or the table. */
    boundsAt(off: number): OffsetBounds | null {
        if (off < this.textStart || off >= this.textEnd) return null;
        const starts = this.table.starts;
        const i = searchSortedStarts(starts.length, (k) => starts[k], off);
        if (i < 0) return null;
        const rangeEnd = i + 1 < starts.length ? starts[i + 1] : Math.min(this.table.end ?? this.textEnd, this.textEnd);
        if (off >= rangeEnd) return null;
        const entries = this.entriesIn(starts[i], rangeEnd);
        const j = searchSortedStarts(entries.length, (k) => entries[k], off);
        return { start: entries[j], end: j + 1 < entries.length ? entries[j + 1] : rangeEnd };
    }

    private entriesIn(start: number, end: number): Uint32Array {
        let entries = this.splits.get(start);
        if (entries === undefined) {
            entries = Uint32Array.of(start);
            const length = Math.floor((end - start) / 4) * 4;
            if (length > 4 && length <= MERGED_SPLIT_MAX_BYTES) {
                const bytes = this.readBytes(start, length);
                if (bytes !== null && bytes.length >= length) entries = splitMergedRange(asWords(bytes, length), start);
            }
            this.splits.set(start, entries);
        }
        return entries;
    }
}

/** FunctionBoundsSource over a loaded Mach-O image's __unwind_info. */
export class MachOUnwindFunctionBounds implements FunctionBoundsSource {
    constructor(private readonly base: NativePointer, private readonly table: UnwindFunctionTable) {}

    static fromModule(mod: Module): MachOUnwindFunctionBounds | null {
        try {
            const unwind = machOSectionRange(mod, "__TEXT", "__unwind_info");
            const text = machOSectionRange(mod, "__TEXT", "__text");
            if (unwind === null || text === null) return null;
            const bytes = unwind.base.readByteArray(unwind.size);
            const parsed = bytes === null ? null : parseUnwindInfoStarts(new Uint8Array(bytes));
            if (parsed === null) return null;
            const textStart = text.base.sub(mod.base).toUInt32();
            return new MachOUnwindFunctionBounds(mod.base,
                new UnwindFunctionTable(parsed, textStart, textStart + text.size, moduleMemoryReader(mod.base)));
        } catch (_e) {
            return null;
        }
    }

    bounds(addr: NativePointer): FunctionBounds | null {
        try {
            // Range-check as pointers: toUInt32() alone would alias addresses 4 GiB apart.
            const off = addr.sub(this.base);
            if (addr.compare(this.base) < 0 || off.compare(this.table.textEnd) >= 0) return null;
            const found = this.table.boundsAt(off.toUInt32());
            if (found === null) return null;
            return { start: this.base.add(found.start), end: found.end === null ? null : this.base.add(found.end) };
        } catch (_e) {
            return null;
        }
    }
}
