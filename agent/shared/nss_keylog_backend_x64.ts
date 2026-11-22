// agent/shared/nss_keylog_backend_x64.ts
//
// x86-64 backend of the NSS keylog-writer locator (nss_keylog_locator.ts).
// Only the two arch-specific steps live here: resolving label load sites
// (RIP-relative LEAs) to their callees, and decoding a candidate body as the
// keylog writer. Every walk starts at a real instruction start and goes through
// the x64_insn.ts length decoder; nothing is matched by byte scan inside a body.
//
// Statically validated only: Fenix 160.0.1 x86_64 libnss3.so (NSS 3.132),
// writer 0x292520, client_random at ss+0x650. Never run on an x86_64 device.
//
// Shape note (from the recon): on x86-64 clang folds ss+0x650 into the memory
// operand (`movzx edi, byte [r12+rsi+0x650]`); no lea/add computes it. So the
// decoder collects the displacement of EVERY memory operand (lea included)
// whose base is a live copy of rdi, plus `add <copy>, imm32`.

import {
    decodeX64Insn, endsX64FallThrough, isX64Branch, isX64Call, isX64DirectCall, isX64DirectJmp, sweepX64,
    x64RegMove, x64RegsWritten, RIP, X64, type X64Insn,
} from "./x64_insn.js";
import {
    functionByteLength, yieldToEventLoop, MAX_LOAD_SITES, XREF_SCAN_CHUNK_BYTES, type FunctionBoundsSource,
    type ScanStatus,
} from "./arm64_xref.js";
import { findLiteralOccurrences, loadSitesFor } from "./string_anchor_functions.js";
import { ehFrameTableFor, functionBoundsFor } from "./eh_frame.js";
import { boundedModuleReader, codeBytesAvailable, isExecutable } from "../util/safe_memory.js";
import { rvaOf } from "./learned_module_cache.js";
import type { ModuleByteReader } from "./module_mapping.js";
import { DECODE_UNREADABLE, type Decoded } from "./keylog_guards.js";
import {
    addressesInModule, calleesPerLabel, isPlausibleWriterClientRandomOffset, readsHexTable, singleOffset,
    WRITER_DECODE_CAP_BYTES,
} from "./nss_layout_constants.js";
import type { NssLocatorBackend, NssWriterDecode } from "./nss_keylog_locator.js";

/** Bytes walked after a label site when its function's end is unknown. */
const LABEL_SITE_WINDOW_BYTES = 256;
/** client_random offsets are 8-aligned in the 64-bit sslSocket. */
const CLIENT_RANDOM_ALIGN = 8;

// ---- pure decoders --------------------------------------------------------------

/**
 * Direct call targets in `bytes` (decoded from bytes[0] at numeric address
 * `base`), in order, deduplicated: every `call rel32` target, plus every direct
 * `jmp` whose target leaves the window (a tail call).
 */
export function x64DirectCallTargets(bytes: Uint8Array, base: number): number[] {
    const end = base + bytes.length;
    const targets: number[] = [];
    for (const insn of sweepX64(bytes, base).insns) {
        if (insn.target === null || (!isX64DirectCall(insn) && !isX64DirectJmp(insn))) continue;
        if (isX64DirectJmp(insn) && insn.target >= base && insn.target < end) continue;
        if (!targets.includes(insn.target)) targets.push(insn.target);
    }
    return targets;
}

/**
 * Target of the first `call rel32` after the label site at bytes[0] (address
 * `base`), or of a tail `jmp` that leaves the function [fnStart, fnEnd). null
 * when the walk first meets an intra-function jump, an indirect call/jmp, a
 * return or trap, undecodable bytes, or the function end.
 */
export function x64FirstCallAfterSite(bytes: Uint8Array, base: number, fnStart: number, fnEnd: number): number | null {
    const limit = Math.min(bytes.length, Math.max(0, fnEnd - base));
    for (let off = 0; off < limit;) {
        const insn = decodeX64Insn(bytes, off, base, limit);
        if (insn === null) return null;
        if (isX64DirectCall(insn)) return insn.target;
        if (isX64DirectJmp(insn)) return insn.target! < fnStart || insn.target! >= fnEnd ? insn.target : null;
        if (endsX64FallThrough(insn) || isX64Call(insn)) return null; // ret/trap/indirect jmp or call
        off += insn.length;
    }
    return null;
}

/** Live registers holding the entry `ss` (rdi until overwritten, plus its copies). */
type SsCopies = Set<number>;

/** Apply `insn`'s register writes: overwritten copies are dropped, `mov r64, <copy>` creates one. */
function trackSsCopies(copies: SsCopies, insn: X64Insn): void {
    const move = x64RegMove(insn);
    const createsCopy = move !== null && copies.has(move[1]);
    for (const reg of x64RegsWritten(insn)) copies.delete(reg);
    if (createsCopy) copies.add(move![0]);
}

/** Plausible client_random offsets this instruction adds to a live `ss` copy. */
function ssDisplacements(insn: X64Insn, copies: SsCopies): number[] {
    const found: number[] = [];
    const mem = insn.mem;
    const onCopy = mem !== null && ((mem.base !== null && copies.has(mem.base)) ||
        (mem.index !== null && mem.scale === 1 && copies.has(mem.index)));
    if (onCopy && isPlausibleWriterClientRandomOffset(mem!.disp, CLIENT_RANDOM_ALIGN)) found.push(mem!.disp);
    const addImm = !insn.vex && insn.map === 0 && insn.rexW && insn.imm !== null &&
        ((insn.opcode === 0x81 && insn.mod === 3 && (insn.reg! & 7) === 0 && copies.has(insn.rm!)) ||
         (insn.opcode === 0x05 && copies.has(X64.rax)));
    if (addImm && isPlausibleWriterClientRandomOffset(insn.imm!, CLIENT_RANDOM_ALIGN)) found.push(insn.imm!);
    return found;
}

/** True when `insn` RIP-references bytes reading "0123456789abcdef" (matched by content). */
function referencesHexTable(insn: X64Insn, readAt: ModuleByteReader): boolean {
    if (insn.mem === null || insn.mem.base !== RIP) return false;
    return readsHexTable(readAt, insn.addr + insn.length + insn.mem.disp);
}

/**
 * Decode a keylog-writer body: `bytes` at numeric address `base` (a function
 * start); `readAt` reads data in the same address space. Accepted iff (a) a
 * RIP-relative operand references bytes equal to "0123456789abcdef" (libnss3
 * has several copies) and (b) exactly ONE distinct plausible displacement is
 * applied to a live copy of rdi (memory operand base, or index with scale 1,
 * lea included; or `add <copy>, imm32`) — that value is the client_random
 * offset in sslSocket. Undecodable bytes anywhere in the body -> null.
 *
 * Copy tracking: rdi is `ss` until written (a call clobbers it); `mov r64,
 * <copy>` creates a copy, any write drops it. At every dead-end block (ret,
 * jmp, trap) the state rolls back to that block's start, so an error path laid
 * out before the `mov` (seen on arm32) does not poison the main path.
 */
export function decodeX64KeylogWriter(bytes: Uint8Array, base: number, readAt: ModuleByteReader): NssWriterDecode | null {
    const sweep = sweepX64(bytes, base);
    if (!sweep.complete) return null;
    let copies: SsCopies = new Set([X64.rdi]);
    let atBlockStart = new Set(copies);
    const offsets = new Set<number>();
    let hexTableSeen = false;
    for (const insn of sweep.insns) {
        if (referencesHexTable(insn, readAt)) hexTableSeen = true;
        for (const off of ssDisplacements(insn, copies)) offsets.add(off);
        trackSsCopies(copies, insn);
        if (endsX64FallThrough(insn)) copies = new Set(atBlockStart);
        if (isX64Branch(insn)) atBlockStart = new Set(copies);
    }
    return singleOffset(hexTableSeen, offsets);
}

// ---- Frida side -------------------------------------------------------------

/**
 * Bytes of the function starting at module offset `off`: its FDE extent when it starts
 * there, else the cap; never past the module or readable range end (null when none).
 */
function functionBytes(fn: NativePointer, off: number, mod: Module, read: ModuleByteReader): Uint8Array | null {
    const length = functionByteLength(fn, functionBoundsFor(mod), WRITER_DECODE_CAP_BYTES);
    const available = codeBytesAvailable(fn, mod, WRITER_DECODE_CAP_BYTES);
    return available <= 0 ? null : read(off, Math.min(length, available));
}

/**
 * x86 call resolution is a decode from a site found by byte search, so a target
 * is accepted only inside the module's executable ranges and, where .eh_frame
 * exists, only at a function start (PLT stubs have no FDE -> skipped).
 */
function isAcceptableCallee(p: NativePointer, mod: Module): boolean {
    if (!isExecutable(p)) return false;
    const table = ehFrameTableFor(mod);
    return table === null || (table.bounds(p)?.start.equals(p) ?? false);
}

/** The first call / tail jmp after one label site, if acceptable. */
function labelSiteCallee(site: NativePointer, mod: Module, functions: FunctionBoundsSource): NativePointer | null {
    const siteOff = rvaOf(mod, site, mod.size);
    if (siteOff === null) return null;
    const bounds = functions.bounds(site);
    const end = bounds?.end ?? null;
    const fnStart = bounds === null ? siteOff : siteOff - site.sub(bounds.start).toUInt32();
    const fnEnd = siteOff + (end === null ? LABEL_SITE_WINDOW_BYTES : end.sub(site).toUInt32());
    const length = Math.min(fnEnd - siteOff, LABEL_SITE_WINDOW_BYTES, mod.size - siteOff);
    const bytes = boundedModuleReader(mod)(siteOff, length);
    if (bytes === null) return null;
    const target = x64FirstCallAfterSite(bytes, siteOff, fnStart, fnEnd);
    const callee = target === null ? [] : addressesInModule(mod, [target]);
    return callee.length === 1 && isAcceptableCallee(callee[0], mod) ? callee[0] : null;
}

export const x64NssLocatorBackend: NssLocatorBackend = {
    name: "x64",
    deviceVerified: false,

    async labelCallees(mod: Module, labels: string[], status: ScanStatus): Promise<NativePointer[][]> {
        // Scans throw XrefScanAborted on shutdown; the locator marks the status incomplete.
        const strings = await findLiteralOccurrences(mod, labels, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
        const sites = await loadSitesFor(mod, strings, MAX_LOAD_SITES, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
        const functions = functionBoundsFor(mod);
        return calleesPerLabel(sites, (site) => labelSiteCallee(site, mod, functions));
    },

    directCallees(fn: NativePointer, mod: Module): NativePointer[] {
        const off = rvaOf(mod, fn, mod.size);
        const bytes = off === null ? null : functionBytes(fn, off, mod, boundedModuleReader(mod));
        if (off === null || bytes === null) return [];
        return addressesInModule(mod, x64DirectCallTargets(bytes, off)).filter((p) => isAcceptableCallee(p, mod));
    },

    decodeWriter(fn: NativePointer, mod: Module): Decoded<NssWriterDecode> {
        const off = rvaOf(mod, fn, mod.size);
        if (off === null) return null;
        const read = boundedModuleReader(mod);
        const bytes = functionBytes(fn, off, mod, read);
        return bytes === null ? DECODE_UNREADABLE : decodeX64KeylogWriter(bytes, off, read);
    },

    hookAddress(fn: NativePointer): NativePointer {
        return fn;
    },
};
