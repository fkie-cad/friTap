// agent/shared/fizz_locator.ts
//
// Locates Meta Fizz's (TLS 1.3, also used by mvfst QUIC) secret derivation in a
// stripped Android library, following the same principle as the BoringSSL
// ssl_log_secret anchor locator (boringssl_anchor_locator.ts tier 4) and the NSS
// keylog locator (nss_keylog_locator.ts): no symbols, no hard-coded offsets.
//
//   L1 label vote. Fizz derives every TLS 1.3 secret through the VIRTUAL
//      KeyDerivation::deriveSecret(secret, label, messageHash, len) (2026 ABI:
//      x0 this, x1 &ret vector, x2 &Error, x3/x4 secret range, x5/x6 label range,
//      [sp]/[sp+8] message hash range, [sp+0x10] u16 length; w0 Status). Every
//      load site of the six labels ("c hs traffic", ..., NUL-terminated, without
//      the "tls13 " prefix) is followed by the call that consumes the label in x5:
//      a RELATIVE-vtable call `ldr xV,[xO]; ldrsw xS,[xV,#slot]; add xT,xV,xS;
//      blr xT` (the chain may be hoisted above the site). The slot is accepted
//      only when >= 2 labels agree on it and no other slot ties; else fail closed.
//   L2 target. RTTI name "N4fizz17KeyDerivationImplE" -> typeinfo (whose name
//      field points at it) -> the dso-local proxy slot holding &typeinfo -> the
//      relative vtable whose RTTI component (address point - 4) holds
//      proxy - address point, offset-to-top 0 -> address point + s32(ap + slot).
//      The body must decode: x5/x6 moved to callee-saved registers, `sub x?, x4,
//      x3`, and one call (direct, or through its own vtable) whose body loads the
//      "tls13 " literal (HKDF-Expand-Label).
//   L3 transcript. HandshakeContextImpl's relative vtable (same RTTI walk) slot
//      +0x8 = appendToTranscript (x0 this, x1 &Error, x2 const unique_ptr<IOBuf>&).
//
// Everything is decoded through FizzImage / FizzImageSearch (module offsets, plain
// numbers), so the decoders and the whole locate pipeline run under Node against
// real bytes (fizz_locator.test.ts). Only the classes at the bottom touch Frida.
// arm64 only; any other arch is a miss with one log line. Read-only: nothing here
// writes target memory.

import { log, devlog, _isShuttingDownNow } from "../util/log.js";
import { boundedModuleReader, readableByteCount } from "../util/safe_memory.js";
import type { ModuleByteReader } from "./module_mapping.js";
import {
    isADRP, isADR, isADDimm64, isLDRimmU64, isAnyCall, isBLR, isUnconditionalB, isAnyReturn,
    isIndirectBranch, isTrap, endsFallThrough, writesReg, isLDRSWimmU, isADDreg64, isSUBreg64,
    decodeADRPImm, decodeADRImm, decodeADDImm12, decodeLDRU64Imm, decodeLDRSWImm, decodeBLImm,
    regRd, regRn, regRm, movRegSource, movRegDest,
} from "./arm64.js";
import {
    directCallTargets, findStringLoadSitesAsync, moduleOffsetLabel, pointerScanPattern, readInstructionWords,
    scanRangesChunked, yieldToEventLoop, XrefScanAborted, XREF_SCAN_CHUNK_BYTES, MAX_LOAD_SITES, type ScanRange,
    type ScanStatus,
} from "./arm64_xref.js";
import { findLiteralOccurrences } from "./string_anchor_functions.js";
import {
    hasLearnedMiss, learnedFunction, learnedLayout, learnedMissName, missFingerprint, rejectLearnedFunction,
    rejectLearnedLayout, reportLearned, reportLearnedMisses, rvaOf,
} from "./learned_module_cache.js";

// ---- constants ----------------------------------------------------------------

/** Labels whose load sites vote for the deriveSecret slot (Fizz passes them without "tls13 "). */
export const FIZZ_VOTING_LABELS = [
    "c hs traffic", "s hs traffic", "c ap traffic", "s ap traffic", "exp master", "c e traffic",
] as const;
export const FIZZ_KDF_RTTI_NAME = "N4fizz17KeyDerivationImplE";
/** Not a template in the shipped builds (one vtable serves SHA-256 and SHA-384). */
export const FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME = "N4fizz20HandshakeContextImplE";
/** The literal HKDF-Expand-Label prepends; deriveSecret must reach it within one call. */
export const HKDF_LABEL_PREFIX = "tls13 ";
/** HandshakeContext vtable slot of appendToTranscript (after the two destructors). */
export const APPEND_TO_TRANSCRIPT_SLOT = 0x8;
/** deriveSecret's label.begin() / label.end() argument registers (2026 ABI). */
export const LABEL_BEGIN_REG = 5;
export const LABEL_END_REG = 6;
export const MIN_AGREEING_LABELS = 2;

/** Words walked forward from a label site to its consuming call (the site may sit far above it). */
export const CALL_WALK_MAX_WORDS = 192;
/** Unconditional `b` followed on that walk (labels often branch into one shared call block). */
export const CALL_WALK_MAX_BRANCHES = 4;
/** Words walked backward from a `blr` to the hoisted vtable chain that computed its target. */
export const CHAIN_BACK_MAX_WORDS = 48;
/** Words of a function body decoded (the walk stops earlier at the first `ret`). */
export const BODY_MAX_WORDS = 512;
/** Words at the entry in which x5/x6 must be saved and `sub x?, x4, x3` computed. */
export const ENTRY_WINDOW_WORDS = 48;
/** Callees of deriveSecret inspected for the "tls13 " literal. */
export const MAX_REACH_CALLEES = 64;
/** Results kept per string / pointer / relative-reference search. */
export const MAX_SEARCH_HITS = 16;

const POINTER_SIZE = 8;
/** Callee-saved general-purpose registers (AAPCS64). */
const CALLEE_SAVED_MIN = 19, CALLEE_SAVED_MAX = 28;
const LINK_REG = 30;

// ---- learned cache -------------------------------------------------------------

export const LEARNED_FIZZ_DERIVE_SECRET = "fizz.derive_secret";
export const LEARNED_FIZZ_APPEND_TRANSCRIPT = "fizz.append_transcript";
export const LEARNED_FIZZ_KDF_VTABLE = "fizz.kdf_vtableRva";
export const LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE = "fizz.handshake_context_vtableRva";
export const LEARNED_FIZZ_DERIVE_SECRET_SLOT = "fizz.derive_secret_slot";
export const LEARNED_FIZZ_DERIVE_SECRET_MISS = learnedMissName(LEARNED_FIZZ_DERIVE_SECRET);
/** Bump the revision when the selection rule changes, so old miss markers go stale. */
export const FIZZ_LOCATOR_MISS_FINGERPRINT = missFingerprint([
    ...FIZZ_VOTING_LABELS, FIZZ_KDF_RTTI_NAME, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME, "revision", "2",
]);
// revision 2: relative vtables are searched in .rodata wherever it is mapped (r-x on builds
// without -z separate-code); revision-1 misses were written while that range was skipped.

// ---- image view (module offsets, plain numbers) --------------------------------

/** Synchronous reads of one loaded module, addressed by module offset. null = unreadable. */
export interface FizzImage {
    readU32(off: number): number | null;
    readS32(off: number): number | null;
    /** Up to `count` words at `off`, stopping at the first unreadable one. */
    readWords(off: number, count: number): number[];
    /** The pointer stored at `off` as a module offset; null when unreadable or outside the module. */
    readPointerOffset(off: number): number | null;
    /** Bytes at `off` up to (not including) a NUL within `maxLen`; null when unreadable or unterminated. */
    readCString(off: number, maxLen: number): string | null;
    /** True iff `off` lies in an executable range of the module. */
    isCode(off: number): boolean;
}

/** The searches the locator needs; the Frida implementation scans natively in chunks. */
export interface FizzImageSearch {
    /** Per text: offsets of its NUL-terminated occurrences (at most MAX_SEARCH_HITS each). */
    cStrings(texts: readonly string[]): Promise<number[][]>;
    /** 8-aligned offsets of slots holding a pointer to module offset `target` ("relocated" ranges). */
    pointerSlots(target: number): Promise<number[]>;
    /** 4-aligned offsets A with s32(A) == target - (A + 4) (relative-vtable RTTI components; "rodata" ranges). */
    relativeRefs(target: number): Promise<number[]>;
    /** Per string offset: offsets of the ADRP/ADR/LDR sequences that materialise it. */
    loadSites(targets: number[]): Promise<number[][]>;
}

// ---- where each searched artefact is mapped ----------------------------------------

/**
 * The mapped ranges an artefact can live in, by protection ("r-x", "r--", "rw-"):
 *  - "rodata": typeinfo names and the relative vtables themselves. Relocation-free
 *    constants in .rodata, so never writable; but builds without `-z separate-code`
 *    (Meta's libcoldstart / libstartup) keep .rodata in the FIRST, r-x segment, so
 *    executable ranges must be included.
 *  - "relocated": typeinfo objects (their name field), the dso-local typeinfo proxies and
 *    the GOT. Absolute pointers need relocation: .data.rel.ro / .got (r-- once RELRO is
 *    applied) or .data (rw-); never executable (Android arm64 forbids text relocations).
 */
export type FizzArtefactRegion = "rodata" | "relocated";

/** True iff a range mapped with `protection` can hold an artefact of `region` (pure). */
export function rangeHoldsArtefact(protection: string, region: FizzArtefactRegion): boolean {
    if (!protection.startsWith("r")) return false;
    return region === "rodata" ? !protection.includes("w") : !protection.includes("x");
}

/** The ranges of `ranges` that can hold `region`, non-executable ones first (pure). */
export function rangesHolding<T extends { protection: string }>(ranges: T[], region: FizzArtefactRegion): T[] {
    const held = ranges.filter((r) => rangeHoldsArtefact(r.protection, region));
    return [...held.filter((r) => !r.protection.includes("x")), ...held.filter((r) => r.protection.includes("x"))];
}

// ---- L1: label site -> consuming call -> relative-vtable slot -------------------

function isCallerSaved(reg: number): boolean {
    return reg < CALLEE_SAVED_MIN || reg === LINK_REG;
}

/** The (unsigned 64-bit, offset 0) vptr load `ldr xV, [xO]`. */
function isVptrLoad(w: number): boolean {
    return isLDRimmU64(w) && decodeLDRU64Imm(w) === 0;
}

/**
 * Forward register state of `ldr xV,[xO]` -> `ldrsw xS,[xV,#slot]` -> `add xT,xV,xS`.
 * A register written by anything else, or clobbered by a call, loses its role.
 */
class VtableChainTracker {
    private readonly vptr = new Set<number>();
    private readonly slotOf = new Map<number, { slot: number; vreg: number }>();
    private readonly targetSlot = new Map<number, number>();

    /** Slot of the vtable entry held in `reg`, or null when `reg` was not built by the chain. */
    slotIn(reg: number): number | null {
        return this.targetSlot.get(reg) ?? null;
    }

    step(w: number): void {
        const defined = this.definition(w);
        const dest = regRd(w);
        for (const reg of [...this.vptr]) if (writesReg(w, reg)) this.vptr.delete(reg);
        for (const reg of [...this.slotOf.keys()]) if (writesReg(w, reg)) this.slotOf.delete(reg);
        for (const reg of [...this.targetSlot.keys()]) if (writesReg(w, reg)) this.targetSlot.delete(reg);
        if (defined === null) return;
        if (defined.kind === "vptr") this.vptr.add(dest);
        else if (defined.kind === "slot") this.slotOf.set(dest, { slot: defined.slot, vreg: defined.vreg });
        else this.targetSlot.set(dest, defined.slot);
    }

    clobberCallerSaved(): void {
        for (const map of [this.slotOf, this.targetSlot]) {
            for (const reg of [...map.keys()]) if (isCallerSaved(reg)) map.delete(reg);
        }
        for (const reg of [...this.vptr]) if (isCallerSaved(reg)) this.vptr.delete(reg);
    }

    private definition(w: number): { kind: "vptr" } | { kind: "slot"; slot: number; vreg: number }
        | { kind: "target"; slot: number } | null {
        if (isVptrLoad(w)) return { kind: "vptr" };
        if (isLDRSWimmU(w) && this.vptr.has(regRn(w))) return { kind: "slot", slot: decodeLDRSWImm(w), vreg: regRn(w) };
        if (!isADDreg64(w)) return null;
        for (const [v, s] of [[regRn(w), regRm(w)], [regRm(w), regRn(w)]]) {
            const slot = this.slotOf.get(s);
            if (slot !== undefined && slot.vreg === v && this.vptr.has(v)) return { kind: "target", slot: slot.slot };
        }
        return null;
    }
}

interface WordAt { off: number; w: number; }

/**
 * Nearest earlier word (straight-line, within CHAIN_BACK_MAX_WORDS) that may write
 * `reg`. null when the walk crosses a block end (b/ret/br/trap), a call that
 * clobbers `reg`, or unreadable memory: the definition is then unknown.
 */
export function definitionBefore(img: FizzImage, off: number, reg: number,
                                 maxWords: number = CHAIN_BACK_MAX_WORDS): WordAt | null {
    for (let k = 1; k <= maxWords; k++) {
        const at = off - 4 * k;
        const w = at < 0 ? null : img.readU32(at);
        if (w === null || endsFallThrough(w)) return null;
        if (isAnyCall(w)) {
            if (isCallerSaved(reg)) return null;
            continue;
        }
        if (writesReg(w, reg)) return { off: at, w };
    }
    return null;
}

/** Slot of the relative-vtable chain that computed the `blr` target at `blrOff`, walking backward. */
export function backwardVtableCallSlot(img: FizzImage, blrOff: number): number | null {
    const blr = img.readU32(blrOff);
    if (blr === null || !isBLR(blr)) return null;
    const add = definitionBefore(img, blrOff, regRn(blr));
    if (add === null || !isADDreg64(add.w)) return null;
    for (const [v, s] of [[regRn(add.w), regRm(add.w)], [regRm(add.w), regRn(add.w)]]) {
        const slotLoad = definitionBefore(img, add.off, s);
        if (slotLoad === null || !isLDRSWimmU(slotLoad.w) || regRn(slotLoad.w) !== v) continue;
        const vptrAtAdd = definitionBefore(img, add.off, v);
        const vptrAtSlot = definitionBefore(img, slotLoad.off, v);
        if (vptrAtAdd === null || vptrAtSlot === null || vptrAtAdd.off !== vptrAtSlot.off) continue;
        if (isVptrLoad(vptrAtAdd.w)) return decodeLDRSWImm(slotLoad.w);
    }
    return null;
}

/** `add xL, xL, #lo12` / `ldr xL, [xL, #lo12]`: the completion of the site's address, not a new value. */
function completesLabelAddress(w: number, labelRegs: Set<number>): boolean {
    return (isADDimm64(w) || isLDRimmU64(w)) && regRd(w) === regRn(w) && labelRegs.has(regRd(w));
}

/**
 * Slot of the relative-vtable call that consumes the label materialised at
 * `siteOff`: the first call reached with the label in x5 (moves of the label
 * register are followed; calls without it are stepped over). null when that call
 * is direct, is not a vtable call, or is not reached within the bounded walk.
 */
export function labelCallSlot(img: FizzImage, siteOff: number): number | null {
    const first = img.readU32(siteOff);
    if (first === null) return null;
    const labelRegs = new Set<number>([regRd(first)]);
    const chain = new VtableChainTracker();
    let pc = siteOff + 4;
    let branches = 0;
    for (let n = 0; n < CALL_WALK_MAX_WORDS; n++) {
        const w = img.readU32(pc);
        if (w === null || isAnyReturn(w) || isIndirectBranch(w) || isTrap(w)) return null;
        if (isUnconditionalB(w)) {
            if (++branches > CALL_WALK_MAX_BRANCHES) return null;
            pc += decodeBLImm(w);
            continue;
        }
        if (isAnyCall(w)) {
            if (labelRegs.has(LABEL_BEGIN_REG)) {
                return isBLR(w) ? chain.slotIn(regRn(w)) ?? backwardVtableCallSlot(img, pc) : null;
            }
            for (const reg of [...labelRegs]) if (isCallerSaved(reg)) labelRegs.delete(reg);
            chain.clobberCallerSaved();
            pc += 4;
            continue;
        }
        if (!completesLabelAddress(w, labelRegs)) {
            const source = movRegSource(w);
            const carries = source !== null && labelRegs.has(source);
            for (const reg of [...labelRegs]) if (writesReg(w, reg)) labelRegs.delete(reg);
            if (carries) labelRegs.add(movRegDest(w)!);
        }
        chain.step(w);
        pc += 4;
    }
    return null;
}

export interface SlotVote { slot: number; labels: number; }

/**
 * The slot most labels agree on (each label counts once per slot), accepted only
 * with >= MIN_AGREEING_LABELS labels and no other slot as popular; else null.
 */
export function voteSlot(slotsPerLabel: (number | null)[][]): SlotVote | null {
    const labelsBySlot = new Map<number, number>();
    for (const slots of slotsPerLabel) {
        for (const slot of new Set(slots.filter((s): s is number => s !== null))) {
            labelsBySlot.set(slot, (labelsBySlot.get(slot) ?? 0) + 1);
        }
    }
    let best: SlotVote | null = null;
    let tie = false;
    for (const [slot, labels] of labelsBySlot) {
        if (best === null || labels > best.labels) { best = { slot, labels }; tie = false; }
        else if (labels === best.labels) tie = true;
    }
    return best !== null && !tie && best.labels >= MIN_AGREEING_LABELS ? best : null;
}

// ---- L2/L3: RTTI -> relative vtable -> slot target -------------------------------

/** Slot target of the relative vtable at address point `ap` (entries are relative to `ap`), or null. */
export function vtableSlotTarget(img: FizzImage, ap: number, slot: number): number | null {
    const rel = img.readS32(ap + slot);
    if (rel === null) return null;
    const target = ap + rel;
    return target % 4 === 0 && img.isCode(target) ? target : null;
}

/**
 * True iff `ap` is the address point of a primary relative vtable whose RTTI
 * component leads to a typeinfo named `rttiName`: offset-to-top (ap-8) is 0, the
 * RTTI component (ap-4) holds proxy - ap, *proxy is the typeinfo, and the
 * typeinfo's name field (+8) points at "rttiName\0".
 */
export function addressPointMatchesRtti(img: FizzImage, ap: number, rttiName: string): boolean {
    const offsetToTop = img.readS32(ap - 8);
    const rel = img.readS32(ap - 4);
    if (offsetToTop !== 0 || rel === null || rel === 0) return false;
    const typeinfo = img.readPointerOffset(ap + rel);
    const name = typeinfo === null ? null : img.readPointerOffset(typeinfo + POINTER_SIZE);
    return name !== null && img.readCString(name, rttiName.length + 1) === rttiName;
}

/** Address points of every relative vtable of the class named `rttiName` (normally exactly one). */
export async function relativeVtablesFor(img: FizzImage, search: FizzImageSearch, rttiName: string): Promise<number[]> {
    const found = new Set<number>();
    const [names] = await search.cStrings([rttiName]);
    for (const name of names) {
        for (const nameField of await search.pointerSlots(name)) {
            const typeinfo = nameField - POINTER_SIZE;
            if (typeinfo < 0) continue;
            for (const proxy of await search.pointerSlots(typeinfo)) {
                for (const component of await search.relativeRefs(proxy)) {
                    const ap = component + 4;
                    if (addressPointMatchesRtti(img, ap, rttiName)) found.add(ap);
                }
            }
        }
    }
    return [...found];
}

/** The one slot target all address points agree on, or null (none, or ambiguous). */
export function uniqueSlotTarget(img: FizzImage, aps: number[], slot: number): { ap: number; target: number } | null {
    let picked: { ap: number; target: number } | null = null;
    for (const ap of aps) {
        const target = vtableSlotTarget(img, ap, slot);
        if (target === null) continue;
        if (picked !== null && picked.target !== target) return null;
        picked ??= { ap, target };
    }
    return picked;
}

// ---- body validation -------------------------------------------------------------

/** Words of the function at `fnOff` up to and including its first `ret` (at most maxWords). */
export function functionWords(img: FizzImage, fnOff: number, maxWords: number = BODY_MAX_WORDS): number[] {
    const words = img.readWords(fnOff, maxWords);
    const ret = words.findIndex(isAnyReturn);
    return ret < 0 ? words : words.slice(0, ret + 1);
}

/** Module offsets materialised by ADRP+ADD (any later ADD off the ADRP register) and ADR in `words`. */
function materialisedAddresses(words: number[], fnOff: number): number[] {
    const out: number[] = [];
    words.forEach((w, i) => {
        const pc = fnOff + 4 * i;
        if (isADR(w)) out.push(pc + decodeADRImm(w));
        if (!isADRP(w)) return;
        const page = Math.floor(pc / 0x1000) * 0x1000 + decodeADRPImm(w);
        for (let j = i + 1; j < Math.min(words.length, i + 9); j++) {
            if (isADDimm64(words[j]) && regRn(words[j]) === regRd(w)) { out.push(page + decodeADDImm12(words[j])); break; }
            if (writesReg(words[j], regRd(w))) break;
        }
    });
    return out;
}

/** True iff the body at `fnOff` (up to its first ret) materialises the address of "text\0". */
export function referencesCString(img: FizzImage, fnOff: number, text: string): boolean {
    return materialisedAddresses(functionWords(img, fnOff), fnOff)
        .some((addr) => img.readCString(addr, text.length + 1) === text);
}

/** `mov xC, x<src>` with C callee-saved somewhere in `words`. */
function savesToCalleeSaved(words: number[], src: number): boolean {
    return words.some((w) => {
        const dest = movRegDest(w);
        return movRegSource(w) === src && dest !== null && dest >= CALLEE_SAVED_MIN && dest <= CALLEE_SAVED_MAX;
    });
}

/** `sub x?, x4, x3`: the secret Range's length. */
function computesSecretLength(words: number[]): boolean {
    return words.some((w) => isSUBreg64(w) && regRn(w) === 4 && regRm(w) === 3);
}

/** Own-vtable callees of the body's `blr`s, resolved through the relative vtable at `ap`. */
function vtableCallees(img: FizzImage, fnOff: number, words: number[], ap: number): number[] {
    const callees: number[] = [];
    words.forEach((w, i) => {
        if (!isBLR(w)) return;
        const slot = backwardVtableCallSlot(img, fnOff + 4 * i);
        const target = slot === null ? null : vtableSlotTarget(img, ap, slot);
        if (target !== null) callees.push(target);
    });
    return callees;
}

/** Direct callees (bl, tail-call b) then own-vtable callees (resolved through `ap`) of the body, deduplicated. */
function bodyCallees(img: FizzImage, fnOff: number, words: number[], ap: number | null): number[] {
    const direct = directCallTargets(words, fnOff);
    const viaVtable = ap === null ? [] : vtableCallees(img, fnOff, words, ap);
    return [...new Set([...direct, ...viaVtable])].slice(0, MAX_REACH_CALLEES);
}

/**
 * deriveSecret's shape: x5/x6 (label) saved to callee-saved registers and
 * `sub x?, x4, x3` near the entry, and the "tls13 " literal loaded by the body
 * itself or by one of its callees (direct `bl`, or a relative-vtable call through
 * the KeyDerivationImpl vtable at `kdfAp`).
 */
export function validateDeriveSecretBody(img: FizzImage, fnOff: number, kdfAp: number | null): boolean {
    const words = functionWords(img, fnOff);
    const entry = words.slice(0, ENTRY_WINDOW_WORDS);
    if (!savesToCalleeSaved(entry, LABEL_BEGIN_REG) || !savesToCalleeSaved(entry, LABEL_END_REG)) return false;
    if (!computesSecretLength(entry)) return false;
    if (referencesCString(img, fnOff, HKDF_LABEL_PREFIX)) return true;
    return bodyCallees(img, fnOff, words, kdfAp).some((c) => referencesCString(img, c, HKDF_LABEL_PREFIX));
}

/** Minimal check for appendToTranscript: a 4-aligned, readable offset inside the module's code. */
export function isAlignedCodeEntry(img: FizzImage, off: number): boolean {
    return off > 0 && off % 4 === 0 && img.isCode(off) && img.readU32(off) !== null;
}

// ---- locate pipeline (pure over FizzImage / FizzImageSearch) ----------------------

export interface FizzLocation {
    deriveSecret: number;
    appendToTranscript: number;
    slot: number;
    kdfVtable: number;
    handshakeContextVtable: number;
    agreeingLabels: number;
}

export type FizzLocateResult = { ok: true; location: FizzLocation } | { ok: false; why: string };

function miss(why: string): FizzLocateResult {
    return { ok: false, why };
}

/** L1: the slot the voting labels' consuming calls agree on. */
export async function voteDeriveSecretSlot(img: FizzImage, search: FizzImageSearch): Promise<SlotVote | null> {
    const strings = await search.cStrings(FIZZ_VOTING_LABELS);
    const flat = strings.flat();
    const sites = await search.loadSites(flat);
    let k = 0;
    const slotsPerLabel = strings.map((offs) => offs.flatMap(() => sites[k++]).map((site) => labelCallSlot(img, site)));
    return voteSlot(slotsPerLabel);
}

/** L1 + L2 + L3; any step that does not decode is a miss (fail closed). */
export async function locateFizzInImage(img: FizzImage, search: FizzImageSearch): Promise<FizzLocateResult> {
    const vote = await voteDeriveSecretSlot(img, search);
    if (vote === null) return miss("labels do not agree on a relative-vtable slot");
    const kdf = uniqueSlotTarget(img, await relativeVtablesFor(img, search, FIZZ_KDF_RTTI_NAME), vote.slot);
    if (kdf === null) return miss(`no unique KeyDerivationImpl vtable target for slot 0x${vote.slot.toString(16)}`);
    if (!validateDeriveSecretBody(img, kdf.target, kdf.ap)) return miss("deriveSecret body does not decode");
    const hc = uniqueSlotTarget(img, await relativeVtablesFor(img, search, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME),
        APPEND_TO_TRANSCRIPT_SLOT);
    if (hc === null || !isAlignedCodeEntry(img, hc.target)) return miss("no unique HandshakeContextImpl vtable");
    return {
        ok: true,
        location: {
            deriveSecret: kdf.target, appendToTranscript: hc.target, slot: vote.slot, kdfVtable: kdf.ap,
            handshakeContextVtable: hc.ap, agreeingLabels: vote.labels,
        },
    };
}

/** Re-validation of a learned location without any scan: both RTTI chains, both slots, the body. */
export function revalidateFizzLocation(img: FizzImage, loc: Omit<FizzLocation, "agreeingLabels">): boolean {
    return addressPointMatchesRtti(img, loc.kdfVtable, FIZZ_KDF_RTTI_NAME)
        && vtableSlotTarget(img, loc.kdfVtable, loc.slot) === loc.deriveSecret
        && validateDeriveSecretBody(img, loc.deriveSecret, loc.kdfVtable)
        && addressPointMatchesRtti(img, loc.handshakeContextVtable, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME)
        && vtableSlotTarget(img, loc.handshakeContextVtable, APPEND_TO_TRANSCRIPT_SLOT) === loc.appendToTranscript;
}

// ---- Frida implementations of the image view ---------------------------------------

/**
 * Readable, non-executable ranges of `mod` (Frida's "r--" filter also returns r-x):
 * where the relocated artefacts (typeinfo objects, proxies, GOT) live. NOT .rodata on
 * builds without -z separate-code: use moduleRodataRanges for names and vtables.
 */
export function moduleDataRanges(mod: Module): ScanRange[] {
    return rangesHolding(mod.enumerateRanges("r--"), "relocated").map((r) => ({ base: r.base, size: r.size }));
}

/** Readable, non-writable ranges of `mod`, r-- first: where .rodata (RTTI names, relative vtables) lives. */
export function moduleRodataRanges(mod: Module): ScanRange[] {
    return rangesHolding(mod.enumerateRanges("r--"), "rodata").map((r) => ({ base: r.base, size: r.size }));
}

/** Module offset of a range start (the first range may start at the base itself: offset 0). */
function rangeStart(mod: Module, range: ScanRange): number {
    return Number(range.base.sub(mod.base).toString());
}

/** FizzImage over a loaded module; every read is bounded by the module and range-checked. */
export class ModuleFizzImage implements FizzImage {
    private readonly code: [number, number][];
    private readonly read: ModuleByteReader;

    constructor(private readonly mod: Module) {
        this.read = boundedModuleReader(mod);
        this.code = mod.enumerateRanges("r-x").map((r) => {
            const start = rangeStart(mod, r);
            return [start, start + r.size] as [number, number];
        });
    }

    private view(off: number, size: number): DataView | null {
        const bytes = this.read(off, size);
        return bytes === null ? null : new DataView(bytes.buffer, bytes.byteOffset, size);
    }

    readU32(off: number): number | null {
        return this.view(off, 4)?.getUint32(0, true) ?? null;
    }

    readS32(off: number): number | null {
        return this.view(off, 4)?.getInt32(0, true) ?? null;
    }

    readWords(off: number, count: number): number[] {
        const inModule = Math.min(count, Math.floor((this.mod.size - off) / 4));
        return off < 0 || inModule <= 0 ? [] : readInstructionWords(this.mod.base.add(off), inModule);
    }

    readPointerOffset(off: number): number | null {
        if (this.read(off, POINTER_SIZE) === null) return null;
        try {
            return rvaOf(this.mod, this.mod.base.add(off).readPointer(), this.mod.size);
        } catch (_e) {
            return null;
        }
    }

    readCString(off: number, maxLen: number): string | null {
        if (off < 0 || off >= this.mod.size) return null;
        const p = this.mod.base.add(off);
        const readable = readableByteCount(p, Math.min(maxLen, this.mod.size - off));
        if (readable === 0) return null;
        try {
            const bytes = new Uint8Array(p.readByteArray(readable)!);
            const nul = bytes.indexOf(0);
            return nul < 0 ? null : String.fromCharCode(...bytes.subarray(0, nul));
        } catch (_e) {
            return null;
        }
    }

    isCode(off: number): boolean {
        return this.code.some(([start, end]) => off >= start && off < end);
    }
}

/** Bytes per relative-reference chunk: v = target - A - 4 then spans <= 2 values of its top 12 bits. */
export const RELATIVE_REF_CHUNK_BYTES = 0x100000;
/** Byte of the int32 the 2-byte needle starts at (bytes 2..3 hold the top 16 bits, little-endian). */
const RELATIVE_REF_NEEDLE_AT = 2;

/**
 * Masked needles ("X0 YY : f0 ff", matched at byte 2 of the int32) covering every
 * value target - A - 4 for A in [chunkStart, chunkStart + chunkLen): its top 12
 * bits take at most two values over a 1 MB chunk. Pure (unit-tested).
 */
export function relativeRefNeedles(target: number, chunkStart: number, chunkLen: number): string[] {
    const top12 = (v: number) => ((v | 0) >>> 20) & 0xfff;
    const tops = new Set([top12(target - chunkStart - 4), top12(target - (chunkStart + chunkLen - 4) - 4)]);
    return [...tops].map((t) => {
        const b2 = ((t & 0xf) << 4).toString(16).padStart(2, "0");
        const b3 = (t >>> 4).toString(16).padStart(2, "0");
        return `${b2} ${b3} : f0 ff`;
    });
}

/**
 * FizzImageSearch over a loaded module: native chunked scans that yield and abort on
 * shutdown. Pointer slots are searched in the relocated ranges, relative references in
 * the .rodata ranges (see FizzArtefactRegion; both listed once); strings data first
 * (findLiteralOccurrences).
 */
export class ModuleFizzSearch implements FizzImageSearch {
    private readonly dataRanges: ScanRange[];
    private readonly rodataRanges: ScanRange[];

    constructor(private readonly mod: Module, readonly status: ScanStatus = { complete: true }) {
        this.dataRanges = moduleDataRanges(mod);
        this.rodataRanges = moduleRodataRanges(mod);
    }

    /** Module offsets of `hits` (addresses outside the module are dropped). */
    private offsets(hits: NativePointer[]): number[] {
        return hits.map((a) => rvaOf(this.mod, a, this.mod.size)).filter((off): off is number => off !== null);
    }

    async cStrings(texts: readonly string[]): Promise<number[][]> {
        const found = await findLiteralOccurrences(this.mod, [...texts], XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, this.status);
        return found.map((hits) => this.offsets(hits).slice(0, MAX_SEARCH_HITS));
    }

    async pointerSlots(target: number): Promise<number[]> {
        const found: number[] = [];
        const onMatch = (a: NativePointer) => {
            const off = rvaOf(this.mod, a, this.mod.size);
            if (off !== null && off % POINTER_SIZE === 0 && found.length < MAX_SEARCH_HITS) found.push(off);
        };
        await scanRangesChunked(this.dataRanges, [{ pattern: pointerScanPattern(this.mod.base.add(target)), onMatch }],
            XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, this.status);
        return found;
    }

    async relativeRefs(target: number): Promise<number[]> {
        const found: number[] = [];
        for (const range of this.rodataRanges) {
            const rangeOff = rangeStart(this.mod, range);
            for (let c = 0; c + 4 <= range.size && found.length < MAX_SEARCH_HITS; c += RELATIVE_REF_CHUNK_BYTES) {
                if (_isShuttingDownNow()) throw new XrefScanAborted();
                const len = Math.min(RELATIVE_REF_CHUNK_BYTES, range.size - c) & ~3;
                for (const needle of relativeRefNeedles(target, rangeOff + c, len)) {
                    this.scanRelativeChunk(range.base.add(c), len, needle, target, found);
                }
                await yieldToEventLoop();
            }
        }
        return found;
    }

    /** Scan the int32s starting in [start, start+len) for `needle` at their byte 2 and verify each hit. */
    private scanRelativeChunk(start: NativePointer, len: number, needle: string, target: number, found: number[]): void {
        let hits: MemoryScanMatch[] = [];
        try {
            hits = Memory.scanSync(start.add(RELATIVE_REF_NEEDLE_AT), len - RELATIVE_REF_NEEDLE_AT, needle);
        } catch (_e) {
            this.status.complete = false;
            return;
        }
        for (const hit of hits) {
            const at = rvaOf(this.mod, hit.address, this.mod.size);
            const component = at === null ? -1 : at - RELATIVE_REF_NEEDLE_AT;
            if (component < 0 || component % 4 !== 0 || found.includes(component)) continue;
            try {
                if (this.mod.base.add(component).readS32() === target - (component + 4) && found.length < MAX_SEARCH_HITS) {
                    found.push(component);
                }
            } catch (_e) { /* unreadable: skipped */ }
        }
    }

    async loadSites(targets: number[]): Promise<number[][]> {
        if (targets.length === 0) return [];
        const sites = await findStringLoadSitesAsync(this.mod, targets.map((t) => this.mod.base.add(t)),
            XREF_SCAN_CHUNK_BYTES, yieldToEventLoop, MAX_LOAD_SITES, this.status);
        return sites.map((list) => this.offsets(list));
    }
}

// ---- locate with learned cache (Frida) --------------------------------------------

export interface FizzLocated {
    deriveSecret: NativePointer;
    appendToTranscript: NativePointer;
    slot: number;
    source: "scan" | "learned cache";
}

function toLocated(mod: Module, loc: Omit<FizzLocation, "agreeingLabels">, source: FizzLocated["source"]): FizzLocated {
    const located: FizzLocated = {
        deriveSecret: mod.base.add(loc.deriveSecret), appendToTranscript: mod.base.add(loc.appendToTranscript),
        slot: loc.slot, source,
    };
    log(`[*] ${mod.name}: Fizz deriveSecret ${moduleOffsetLabel(mod, located.deriveSecret)} appendToTranscript ` +
        `${moduleOffsetLabel(mod, located.appendToTranscript)} slot 0x${loc.slot.toString(16)} (backend arm64, ${source})`);
    return located;
}

function missed(mod: Module, why: string): null {
    log(`[-] ${mod.name}: Fizz deriveSecret not located (backend ${Process.arch === "arm64" ? "arm64" : `none for ${Process.arch}`}): ${why}`);
    return null;
}

/** The learned location of `mod` when every item is cached, else null. */
function learnedLocation(mod: Module): Omit<FizzLocation, "agreeingLabels"> | null {
    const deriveSecret = rvaOf(mod, learnedFunction(mod, LEARNED_FIZZ_DERIVE_SECRET), mod.size);
    const appendToTranscript = rvaOf(mod, learnedFunction(mod, LEARNED_FIZZ_APPEND_TRANSCRIPT), mod.size);
    const kdfVtable = learnedLayout(mod, LEARNED_FIZZ_KDF_VTABLE);
    const handshakeContextVtable = learnedLayout(mod, LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE);
    const slot = learnedLayout(mod, LEARNED_FIZZ_DERIVE_SECRET_SLOT);
    if (deriveSecret === null || appendToTranscript === null || kdfVtable === null || handshakeContextVtable === null
        || slot === null) return null;
    return { deriveSecret, appendToTranscript, slot, kdfVtable, handshakeContextVtable };
}

function rejectLearnedLocation(mod: Module): void {
    rejectLearnedFunction(mod, LEARNED_FIZZ_DERIVE_SECRET);
    rejectLearnedFunction(mod, LEARNED_FIZZ_APPEND_TRANSCRIPT);
    for (const name of [LEARNED_FIZZ_KDF_VTABLE, LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE, LEARNED_FIZZ_DERIVE_SECRET_SLOT]) {
        rejectLearnedLayout(mod, name);
    }
}

function reportLearnedLocation(mod: Module, loc: FizzLocation): void {
    reportLearned(mod, {
        functions: {
            [LEARNED_FIZZ_DERIVE_SECRET]: mod.base.add(loc.deriveSecret),
            [LEARNED_FIZZ_APPEND_TRANSCRIPT]: mod.base.add(loc.appendToTranscript),
        },
        layout: {
            [LEARNED_FIZZ_KDF_VTABLE]: loc.kdfVtable,
            [LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE]: loc.handshakeContextVtable,
            [LEARNED_FIZZ_DERIVE_SECRET_SLOT]: loc.slot,
        },
    });
}

/** Scan path: locate, then record the result (or a miss marker after a complete scan). */
async function scanFizz(mod: Module, img: FizzImage): Promise<FizzLocated | null> {
    const search = new ModuleFizzSearch(mod);
    let result: FizzLocateResult;
    try {
        result = await locateFizzInImage(img, search);
    } catch (e) {
        if (!(e instanceof XrefScanAborted)) devlog(`[fizz] ${mod.name}: locate failed: ${e}`);
        return missed(mod, "scan aborted");
    }
    if ("why" in result) { // `in` narrows even without strictNullChecks (the agent's tsconfig)
        reportLearnedMisses(mod, { [LEARNED_FIZZ_DERIVE_SECRET_MISS]: FIZZ_LOCATOR_MISS_FINGERPRINT }, search.status);
        return missed(mod, result.why);
    }
    devlog(`[fizz] ${mod.name}: ${result.location.agreeingLabels} labels agree on slot 0x${result.location.slot.toString(16)}`);
    reportLearnedLocation(mod, result.location);
    return toLocated(mod, result.location, "scan");
}

async function locateFizz(mod: Module): Promise<FizzLocated | null> {
    if (Process.arch !== "arm64") return missed(mod, "only arm64 is covered");
    const img = new ModuleFizzImage(mod);
    const cached = learnedLocation(mod);
    if (cached !== null && revalidateFizzLocation(img, cached)) return toLocated(mod, cached, "learned cache");
    if (cached !== null) {
        rejectLearnedLocation(mod);
        devlog(`[fizz] ${mod.name}: learned Fizz location no longer validates; scanning`);
    } else if (hasLearnedMiss(mod, LEARNED_FIZZ_DERIVE_SECRET_MISS, FIZZ_LOCATOR_MISS_FINGERPRINT)) {
        return missed(mod, "learned cache records no Fizz deriveSecret in this build");
    }
    return scanFizz(mod, img);
}

/**
 * Fizz location of `mod`: the learned cache when it still validates, else a scan.
 * Not memoized here: installFizzKeylog runs it at most once per loaded mapping.
 */
export function locateFizzCached(mod: Module): Promise<FizzLocated | null> {
    return locateFizz(mod);
}
