// agent/shared/nss_keylog_backend_arm64.ts
//
// AArch64 backend of the NSS keylog-writer locator (nss_keylog_locator.ts).
// Only the two arch-specific steps live here: resolving label load sites to
// their callees, and decoding a candidate body as the keylog writer
// (ssl3_WriteKeyLog >= NSS 3.115, ssl3_RecordKeyLog before). The pure decoders
// (directCallTargets, decodeKeylogWriter) take instruction words plus their
// numeric address, so they are unit-tested on real libnss3.so bytes
// (directCallTargets lives in arm64_xref.ts, shared with the Fizz locator).
//
// Device-verified: Fenix 160.0.1 arm64 libnss3.so (NSS 3.132), writer 0x279df4,
// client_random at ss+0x650.

import {
    isADR, isADRP, isADDimm64, isAnyCall, endsFallThrough, writesReg, regRd, regRn, decodeADRImm, decodeADRPImm,
    decodeADDImm12, directBranchOffset, movRegDest, movRegSource,
} from "./arm64.js";
import {
    directCallTargets, firstCallTargetForward, functionByteLength, readInstructionWords, yieldToEventLoop,
    MAX_LOAD_SITES, XREF_SCAN_CHUNK_BYTES, type ScanStatus,
} from "./arm64_xref.js";
import { findLiteralOccurrences, loadSitesFor } from "./string_anchor_functions.js";
import { ehFrameTableFor, functionBoundsFor } from "./eh_frame.js";
import { boundedModuleReader, codeBytesAvailable, isExecutable } from "../util/safe_memory.js";
import { rvaOf } from "./learned_module_cache.js";
import type { ModuleByteReader } from "./module_mapping.js";
import { unreadableIfShort, type Decoded } from "./keylog_guards.js";
import {
    addressesInModule, calleesPerLabel, isPlausibleWriterClientRandomOffset, readsHexTable, singleOffset,
    WRITER_DECODE_CAP_BYTES,
} from "./nss_layout_constants.js";
import type { NssLocatorBackend, NssWriterDecode } from "./nss_keylog_locator.js";

/** client_random offsets are 8-aligned in the 64-bit sslSocket. */
const CLIENT_RANDOM_ALIGN = 8;

const ARG0 = 0;
const SP_OR_ZR = 31;
/** AAPCS64 caller-saved GPRs a call may clobber: x0..x18 (x30 is covered by writesReg). */
const LAST_CALLER_SAVED = 18;
const PAGE = 0x1000;

/** Register state of the decode walk: is x0 still the entry `ss`, and which registers copy it. */
interface SsTracking { x0IsSs: boolean; copies: Set<number>; }

function cloneTracking(t: SsTracking): SsTracking {
    return { x0IsSs: t.x0IsSs, copies: new Set(t.copies) };
}

/** Apply `insn`'s register writes: overwritten copies are dropped, and `mov Xd, <ss>` creates one. */
function trackSsCopies(t: SsTracking, insn: number): void {
    const src = movRegSource(insn);
    const createsCopy = src !== null && src !== SP_OR_ZR && ((src === ARG0 && t.x0IsSs) || t.copies.has(src));
    const call = isAnyCall(insn);
    for (const reg of [...t.copies]) {
        if (writesReg(insn, reg) || (call && reg <= LAST_CALLER_SAVED)) t.copies.delete(reg);
    }
    if (call || writesReg(insn, ARG0)) t.x0IsSs = false;
    if (createsCopy) t.copies.add(movRegDest(insn)!);
}

/** Address of the literal an ADR / ADRP+ADD at `pc` materialises, else null; keeps `pages` current. */
function literalAddress(insn: number, pc: number, pages: Map<number, number>): number | null {
    let address: number | null = null;
    if (isADR(insn)) address = pc + decodeADRImm(insn);
    if (isADDimm64(insn) && pages.has(regRn(insn))) address = pages.get(regRn(insn))! + decodeADDImm12(insn);
    for (const reg of [...pages.keys()]) if (writesReg(insn, reg) || isAnyCall(insn)) pages.delete(reg);
    if (isADRP(insn)) pages.set(regRd(insn), Math.floor(pc / PAGE) * PAGE + decodeADRPImm(insn));
    return address;
}

/**
 * Decode a keylog-writer body: `words` at numeric address `base`; `readAt`
 * reads data in the same address space. Accepted iff (a) an ADR or ADRP+ADD
 * references bytes equal to "0123456789abcdef" (matched by CONTENT: libnss3 has
 * several copies) and (b) exactly ONE distinct plausible immediate is added to
 * a copy of x0 (`ADD Xd, Xn, #imm`, LSL #12 form included) — that immediate is
 * the client_random offset in sslSocket.
 *
 * Copy tracking: a linear walk where `mov Xn, x0` creates a copy while x0 still
 * holds the entry argument (no write to x0, no call before it on the walk), and
 * `mov Xm, <copy>` chains. A copy is dropped when its register is overwritten
 * (or clobbered by a call, for x0..x18). Because an error block laid out BEFORE
 * the `mov` may clobber x0 (seen on arm32), the state is rolled back at every
 * dead-end block (one ending in RET / B / BR / trap) to what it was at that
 * block's start (after the previous branch): the code after a dead end is not
 * reached through it. Several identical ADDs (duplicated paths) count once.
 */
export function decodeKeylogWriter(words: number[], base: number, readAt: ModuleByteReader): NssWriterDecode | null {
    let tracking: SsTracking = { x0IsSs: true, copies: new Set() };
    let atBlockStart = cloneTracking(tracking);
    const pages = new Map<number, number>();
    const offsets = new Set<number>();
    let hexTableSeen = false;
    words.forEach((word, i) => {
        const w = word >>> 0;
        const pc = base + i * 4;
        const literal = literalAddress(w, pc, pages);
        if (literal !== null && readsHexTable(readAt, literal)) hexTableSeen = true;
        const imm = decodeADDImm12(w);
        if (isADDimm64(w) && tracking.copies.has(regRn(w)) && isPlausibleWriterClientRandomOffset(imm, CLIENT_RANDOM_ALIGN)) {
            offsets.add(imm);
        }
        trackSsCopies(tracking, w);
        if (endsFallThrough(w)) tracking = cloneTracking(atBlockStart);
        if (endsFallThrough(w) || directBranchOffset(w) !== null) atBlockStart = cloneTracking(tracking);
    });
    return singleOffset(hexTableSeen, offsets);
}

// ---- Frida side -------------------------------------------------------------

/**
 * Instruction words of the function starting at `fn` (its bounds, else the cap; never
 * past the module or readable range end) and whether all were read.
 */
function functionWords(fn: NativePointer, mod: Module): { words: number[]; readInFull: boolean } {
    const available = codeBytesAvailable(fn, mod, WRITER_DECODE_CAP_BYTES);
    const length = Math.min(functionByteLength(fn, functionBoundsFor(mod), WRITER_DECODE_CAP_BYTES), available);
    const wanted = Math.floor(length / 4);
    const words = readInstructionWords(fn, wanted);
    return { words, readInFull: wanted > 0 && words.length >= wanted };
}

/** True when `fn` starts a function with its own .eh_frame FDE (PLT stubs have none). */
function isFunctionStart(fn: NativePointer, mod: Module): boolean {
    const table = ehFrameTableFor(mod) ?? functionBoundsFor(mod);
    return table.bounds(fn)?.start.equals(fn) ?? false;
}

export const arm64NssLocatorBackend: NssLocatorBackend = {
    name: "arm64",
    deviceVerified: true,

    async labelCallees(mod: Module, labels: string[], status: ScanStatus): Promise<NativePointer[][]> {
        // Every copy of a label is a target (tail-merged literals); selection stays fail-closed.
        const strings = await findLiteralOccurrences(mod, labels, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
        const sites = await loadSitesFor(mod, strings, MAX_LOAD_SITES, XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, status);
        const functions = functionBoundsFor(mod);
        const moduleEnd = mod.base.add(mod.size);
        return calleesPerLabel(sites, (site) => {
            const limit = functions.bounds(site)?.end ?? site.add(WRITER_DECODE_CAP_BYTES);
            // Follows a tail `b` after the epilogue too (one ECH_CONFIG site reaches the writer that way).
            return firstCallTargetForward(site, limit, mod.base, moduleEnd, functions);
        });
    },

    directCallees(fn: NativePointer, mod: Module): NativePointer[] {
        const off = rvaOf(mod, fn, mod.size);
        if (off === null) return [];
        return addressesInModule(mod, directCallTargets(functionWords(fn, mod).words, off))
            .filter((p) => isExecutable(p) && isFunctionStart(p, mod));
    },

    decodeWriter(fn: NativePointer, mod: Module): Decoded<NssWriterDecode> {
        const off = rvaOf(mod, fn, mod.size);
        if (off === null) return null;
        const { words, readInFull } = functionWords(fn, mod);
        return unreadableIfShort(decodeKeylogWriter(words, off, boundedModuleReader(mod)), readInFull);
    },

    hookAddress(fn: NativePointer): NativePointer {
        return fn;
    },
};
