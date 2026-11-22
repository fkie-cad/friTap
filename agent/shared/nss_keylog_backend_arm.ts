// agent/shared/nss_keylog_backend_arm.ts
//
// 32-bit ARM (Thumb-2) backend of the NSS keylog-writer locator
// (nss_keylog_locator.ts). Label strings are referenced by a literal-pool
// `ldr Rx, [pc, #i]` (or movw/movt) followed by `add Rx, pc`; the writer is
// reached by `bl` or a tail `b.w`. The pure decoders take bytes plus their
// numeric address (module offset) and are unit-tested on real libnss3.so bytes.
//
// NOT device-verified: validated statically against Fenix 160.0.1 armeabi-v7a
// libnss3.so (NSS 3.132), writer 0x1bb34c (hook 0x1bb34d), client_random at
// ss+0x428. That build has no .eh_frame (only .ARM.exidx), so function ends are
// found by a linear sweep (thumbFunctionEnd) capped at WRITER_DECODE_CAP_BYTES.

import {
    addImmediate, decodeThumb, directBranch, endsFallThrough, findPcRelativeRefs, firstThumbCallTarget, isCall,
    itBlockLength, PcRelativeTracker, registerMove, thumbDirectCallTargets, thumbFunctionEnd, writtenRegisters,
    CALL_CLOBBERED, PCREL_WINDOW_HALFWORDS, SP, PC, type PcRelativeRef, type ThumbInsn, type WordReader32,
} from "./arm_xref.js";
import {
    yieldToEventLoop, MAX_LOAD_SITES, XREF_SCAN_CHUNK_BYTES, XrefScanAborted, type ScanStatus,
} from "./arm64_xref.js";
import { findLiteralOccurrences } from "./string_anchor_functions.js";
import { _isShuttingDownNow } from "../util/log.js";
import type { ModuleByteReader } from "./module_mapping.js";
import { boundedModuleReader, codeBytesAvailable, isExecutable } from "../util/safe_memory.js";
import { rvaOf } from "./learned_module_cache.js";
import { DECODE_UNREADABLE, unreadableIfShort, type Decoded } from "./keylog_guards.js";
import {
    addressesInModule, calleesPerLabel, isPlausibleWriterClientRandomOffset, readsHexTable, singleOffset,
    WRITER_DECODE_CAP_BYTES,
} from "./nss_layout_constants.js";
import type { NssLocatorBackend, NssWriterDecode } from "./nss_keylog_locator.js";

/** Bytes read after a label's `add Rx, pc` to find the call it feeds. */
const LABEL_CALL_WINDOW_BYTES = 192;
/** client_random offsets are 4-aligned in the 32-bit sslSocket. */
const CLIENT_RANDOM_ALIGN = 4;
const ARG0 = 0;

function u32le(b: Uint8Array, i: number): number {
    return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
}

function wordReader(readAt: ModuleByteReader): WordReader32 {
    return (addr) => {
        const b = readAt(addr, 4);
        return b === null || b.length < 4 ? null : u32le(b, 0);
    };
}

// ---- writer decode ---------------------------------------------------------------

/** Registers holding the entry `ss` during the decode walk: r0 until overwritten, plus its copies. */
type SsCopies = Set<number>;

/** Apply `insn`'s register writes: overwritten holders are dropped, and `mov Rd, <ss>` creates one (not under IT). */
function trackSsCopies(copies: SsCopies, insn: ThumbInsn, conditional: boolean): void {
    const move = registerMove(insn);
    const createsCopy = !conditional && move !== null && move.rd !== SP && move.rd !== PC && copies.has(move.rm);
    const written = writtenRegisters(insn) | (isCall(insn) ? CALL_CLOBBERED : 0);
    for (const reg of [...copies]) if ((written & (1 << reg)) !== 0) copies.delete(reg);
    if (createsCopy) copies.add(move!.rd);
}

/** True for a branch that ends a basic block (any immediate branch except a call). */
function isBlockBranch(insn: ThumbInsn): boolean {
    const kind = directBranch(insn)?.kind;
    return kind === "b" || kind === "bcond" || kind === "cbz";
}

/** Function start for `base`: a Thumb-bit address names the code at base - 1, where `bytes` begin. */
function thumbStart(base: number): number {
    return base - (base % 2);
}

/**
 * Decode a keylog-writer body: `bytes` at numeric address `base` (the function
 * start; a Thumb-bit address is accepted: bytes begin at base - 1), `readAt` reads the
 * same address space (literal pools, the hex table). Accepted iff (a) an
 * `ldr`/`movw`+`add Rx, pc` materialises bytes equal to "0123456789abcdef"
 * (matched by CONTENT: libnss3 has several copies) and (b) exactly ONE distinct
 * plausible immediate is added to r0-as-ss or a copy of it (`add(s).w` T3 with
 * ThumbExpandImm, `addw` T4) — that immediate is the client_random offset.
 *
 * Decoding stops at the function end (thumbFunctionEnd), before the literal
 * pool. Copy tracking is per basic block: at every dead end (`pop {…, pc}`,
 * `bx lr`, unconditional `b`/`b.w`, outside an IT block) the state rolls back
 * to the block's start, because the code after a dead end is not reached
 * through it — the 3.132 error block clobbers r0 BEFORE `mov r4, r0`.
 */
export function decodeArmKeylogWriter(bytes: Uint8Array, base: number, readAt: ModuleByteReader): NssWriterDecode | null {
    const start = thumbStart(base);
    const end = thumbFunctionEnd(bytes, start);
    let copies: SsCopies = new Set([ARG0]);
    let atBlockStart = new Set(copies);
    const pcRelative = new PcRelativeTracker(wordReader(readAt));
    const offsets = new Set<number>();
    let hexTableSeen = false;
    let conditional = 0;
    for (const insn of decodeThumb(bytes, start, start, end)) {
        const inIt = conditional > 0;
        conditional = inIt ? conditional - 1 : itBlockLength(insn);
        const literal = pcRelative.step(insn);
        if (literal !== null && readsHexTable(readAt, literal)) hexTableSeen = true;
        const add = addImmediate(insn);
        if (add !== null && copies.has(add.rn) && isPlausibleWriterClientRandomOffset(add.imm, CLIENT_RANDOM_ALIGN)) {
            offsets.add(add.imm);
        }
        trackSsCopies(copies, insn, inIt);
        const deadEnd = !inIt && endsFallThrough(insn);
        if (deadEnd) copies = new Set(atBlockStart);
        if (deadEnd || isBlockBranch(insn)) atBlockStart = new Set(copies);
    }
    return singleOffset(hexTableSeen, offsets);
}

/** Direct Thumb callees of the function in `bytes` at `base` (cut at its swept end); `blx` (A32) targets skipped. */
export function armDirectCallTargets(bytes: Uint8Array, base: number): number[] {
    const start = thumbStart(base);
    return thumbDirectCallTargets(bytes.subarray(0, thumbFunctionEnd(bytes, start) - start), start);
}

// ---- Frida side -------------------------------------------------------------------

/** Up to `length` bytes at module offset `offset`, halving the request until it reads (min 64). */
function readUpTo(read: ModuleByteReader, offset: number, length: number): Uint8Array | null {
    for (let n = length; n >= 64; n = Math.floor(n / 2)) {
        const bytes = read(offset, n);
        if (bytes !== null) return bytes;
    }
    return null;
}

/** Thumb code offset of `fn` in `mod` (Thumb bit cleared), or null outside the module. */
function codeOffset(fn: NativePointer, mod: Module): number | null {
    const off = rvaOf(mod, fn, mod.size);
    return off === null ? null : off - (off % 2);
}

/** Reads words from `chunk` (at module offset `chunkOff`) when they lie inside it, else through `fallback`. */
function chunkWordReader(chunk: Uint8Array, chunkOff: number, fallback: WordReader32): WordReader32 {
    return (addr) => {
        const i = addr - chunkOff;
        return i >= 0 && i + 4 <= chunk.length ? u32le(chunk, i) : fallback(addr);
    };
}

/**
 * Label references (`add Rx, pc` offsets) per label (index-aligned with
 * `targetSets`, each the module offsets of that label's copies), at most
 * MAX_LOAD_SITES each. Each r-x chunk is read ONCE (plus the back window an
 * `add Rx, pc` needs) and run through the pure findPcRelativeRefs; a ref is
 * kept only by the chunk its `add Rx, pc` lies in.
 */
async function findLabelRefs(mod: Module, targetSets: number[][], status: ScanStatus): Promise<number[][]> {
    const read = boundedModuleReader(mod);
    const readU32 = wordReader(read);
    const refs: number[][] = targetSets.map(() => []);
    const targets = targetSets.flat();
    if (targets.length === 0) return refs;
    const backWindow = 2 * PCREL_WINDOW_HALFWORDS;
    for (const range of mod.enumerateRanges("r-x")) {
        const rangeOff = range.base.sub(mod.base).toUInt32();
        for (let off = 0; off < range.size; off += XREF_SCAN_CHUNK_BYTES) {
            if (_isShuttingDownNow()) throw new XrefScanAborted();
            const own = Math.min(XREF_SCAN_CHUNK_BYTES, range.size - off);
            const back = Math.min(backWindow, off);
            const chunkOff = rangeOff + off - back;
            const chunk = read(chunkOff, back + own);
            if (chunk === null) {
                status.complete = false;
            } else {
                const found = findPcRelativeRefs(chunk, chunkOff, targets, chunkWordReader(chunk, chunkOff, readU32));
                collectOwnedRefs(found, chunkOff + back, chunkOff + back + own, targetSets, refs);
            }
            await yieldToEventLoop();
        }
    }
    return refs;
}

/** Add each found ref whose `add Rx, pc` lies in [ownFrom, ownTo) to its label's list (deduplicated, capped). */
function collectOwnedRefs(perTarget: PcRelativeRef[][], ownFrom: number, ownTo: number,
                          targetSets: number[][], refs: number[][]): void {
    let k = 0;
    targetSets.forEach((set, label) => set.forEach(() => {
        for (const { addPcAt } of perTarget[k]) {
            if (addPcAt < ownFrom || addPcAt >= ownTo) continue;
            if (refs[label].length < MAX_LOAD_SITES && !refs[label].includes(addPcAt)) refs[label].push(addPcAt);
        }
        k++;
    }));
}

function toThumbCallee(mod: Module, off: number): NativePointer | null {
    const [p] = addressesInModule(mod, [off]);
    return p !== undefined && isExecutable(p) ? p : null;
}

/**
 * The function bytes at `fn` (up to the cap, the module end or the readable range end),
 * its code offset and how many bytes were available to read, or null when unreadable /
 * outside `mod`.
 */
function functionBytes(fn: NativePointer, mod: Module): { off: number; bytes: Uint8Array; available: number } | null {
    const off = codeOffset(fn, mod);
    if (off === null) return null;
    const available = codeBytesAvailable(mod.base.add(off), mod, WRITER_DECODE_CAP_BYTES);
    if (available <= 0) return null;
    const read = boundedModuleReader(mod);
    const bytes = available < 64 ? read(off, available) : readUpTo(read, off, available);
    return bytes === null ? null : { off, bytes, available };
}

export const armNssLocatorBackend: NssLocatorBackend = {
    name: "arm",
    // Device-verified 2026-11-22 on a Pixel 5 (Android 14) with 32-bit Firefox 160.0.1:
    // writer +0x1bb34d, client_random +0x428, keys matched ClientHellos and decrypted.
    deviceVerified: true,

    async labelCallees(mod: Module, labels: string[], status: ScanStatus): Promise<NativePointer[][]> {
        // Every copy of a label is a target (tail-merged literals); selection stays fail-closed.
        const strings = await findLiteralOccurrences(mod, labels, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
        const targetSets = strings.map((copies) => copies.map((p) => p.sub(mod.base).toUInt32()));
        const refs = await findLabelRefs(mod, targetSets, status);
        const read = boundedModuleReader(mod);
        return calleesPerLabel(refs, (addPcAt) => {
            const window = readUpTo(read, addPcAt, LABEL_CALL_WINDOW_BYTES);
            const target = window === null ? null : firstThumbCallTarget(window, addPcAt, addPcAt);
            return target === null ? null : toThumbCallee(mod, target);
        });
    },

    directCallees(fn: NativePointer, mod: Module): NativePointer[] {
        const body = functionBytes(fn, mod);
        if (body === null) return [];
        return armDirectCallTargets(body.bytes, body.off)
            .map((target) => toThumbCallee(mod, target))
            .filter((p): p is NativePointer => p !== null);
    },

    decodeWriter(fn: NativePointer, mod: Module): Decoded<NssWriterDecode> {
        const body = functionBytes(fn, mod);
        if (body === null) return codeOffset(fn, mod) === null ? null : DECODE_UNREADABLE;
        const decoded = decodeArmKeylogWriter(body.bytes, body.off, boundedModuleReader(mod));
        // Short only against what exists: a writer near the module/range end is read in full.
        return unreadableIfShort(decoded, body.bytes.length >= body.available);
    },

    hookAddress(fn: NativePointer): NativePointer {
        return fn.or(1);
    },
};
