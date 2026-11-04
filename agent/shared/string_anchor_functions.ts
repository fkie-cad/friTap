// agent/shared/string_anchor_functions.ts
//
// "Which functions reference string X?" for stripped arm64 and x86-64 ELF modules.
//
// WHY: a function that is not exported can still be found by a string literal it uses.
// C code that logs passes its own name (`__func__`) or a unique message to the logger,
// so the literal sits in .rodata and only that function's code loads its address. The
// pipeline is: literal -> code sites that load its address (arm64: ADRP+ADD / ADRP+LDR /
// ADR via arm64_xref.ts; x86-64: `lea reg, [rip+disp32]` via x64_xref.ts) -> the function
// that contains each site (the module's .eh_frame_hdr table, eh_frame.ts).
//
// Two linker / compiler effects are handled here, so consumers do not have to:
//   - Tail merging: a short literal ("cipher_init") may only exist as the tail of a
//     longer one ("chachapoly_cipher_init"). The code then loads the tail's address, so
//     EVERY occurrence of `text\0` is a candidate target, not just the first one.
//     (AnchorSpec.literalSuffix is the opposite case: `text` is the known tail of a longer
//     literal, e.g. a __FILE__ path, and the code loads the longer literal's start.)
//   - Inlining / LTO: a literal of an inlined function is loaded from its callers too.
//     The result therefore lists every function that loads it, and agreedFunction()
//     accepts an answer only when all sites agree on one function (fail closed).
//
// Never whole-module Memory.scanSync: every scan is restricted to the module's own ranges
// and chunked (arm64_xref.ts scanRangesChunked).

import { _isShuttingDownNow } from "../util/log.js";
import { toHexPattern } from "../util/hex.js";
import {
    AnchorSpec, FunctionBoundsSource, ScanRange, XREF_SCAN_CHUNK_BYTES, XrefScanAborted,
    findStringLoadSitesAsync, literalStart, scanRangesChunked, yieldToEventLoop,
} from "./arm64_xref.js";
import { findRipLeaRefs } from "./x64_xref.js";
import { ehFrameTableFor } from "./eh_frame.js";

export type { AnchorSpec } from "./arm64_xref.js";

/** One function that loads an anchor literal, with the load sites inside it. */
export interface AnchoredFunction {
    start: NativePointer;
    /** null when the function's FDE gives no length. */
    end: NativePointer | null;
    sites: NativePointer[];
}

/** Everything that loads one anchor literal. */
export interface AnchorFunctions {
    /** Distinct containing functions, ascending by start. */
    functions: AnchoredFunction[];
    /** Load sites no function table entry covers (their function is unknown). */
    unboundedSites: NativePointer[];
}

export interface AnchorLocateOptions {
    /** Bounds source; default: the module's .eh_frame_hdr table (ehFrameTableFor). */
    functions?: FunctionBoundsSource | null;
    /**
     * Called between scan chunks (default: a setTimeout(0) yield). Pass an immediately
     * resolving one when the hooks must be installed before a spawned target resumes and
     * the module is small (the scan then finishes in the same job queue drain).
     */
    yieldFn?: () => Promise<void>;
    chunkBytes?: number;
}

/** Load sites kept per literal by default: enough to see every function that logs it. */
export const DEFAULT_MAX_ANCHOR_SITES = 64;
/** Occurrences of one literal examined (tail-merged copies are rare; a handful at most). */
const MAX_LITERAL_OCCURRENCES = 16;
/** `lea reg, [rip+disp32]` is 7 bytes; a chunk must see a LEA that starts in its last 6. */
const LEA_RIP_OVERLAP = 6;

const NO_FUNCTIONS: AnchorFunctions = { functions: [], unboundedSites: [] };

/** Readable, non-executable ranges of `mod` (Frida's "r--" filter also returns r-x). */
function dataRanges(mod: Module): ScanRange[] {
    return mod.enumerateRanges("r--").filter((r) => !r.protection.includes("x"));
}

function codeRanges(mod: Module): ScanRange[] {
    return mod.enumerateRanges("r-x") as ScanRange[];
}

/**
 * Every address of each `text\0` in the module's data (index-aligned with `texts`),
 * capped at MAX_LITERAL_OCCURRENCES each. Executable ranges are searched only for texts
 * that have no data hit (builds without -z separate-code keep .rodata in the r-x segment).
 */
export async function findLiteralOccurrences(
    mod: Module, texts: string[], chunkBytes: number, yieldFn: () => Promise<void>,
): Promise<NativePointer[][]> {
    const found: NativePointer[][] = texts.map(() => []);
    for (const ranges of [dataRanges(mod), codeRanges(mod)]) {
        const missing = texts.map((_t, i) => i).filter((i) => found[i].length === 0);
        if (missing.length === 0) break;
        const jobs = missing.map((i) => ({
            pattern: toHexPattern(texts[i] + "\u0000"),
            onMatch: (a: NativePointer) => { if (found[i].length < MAX_LITERAL_OCCURRENCES) found[i].push(a); },
        }));
        await scanRangesChunked(ranges, jobs, chunkBytes, yieldFn);
    }
    return found;
}

/** The addresses code would load for `spec`, given where `text\0` occurs. */
export function anchorTargets(spec: AnchorSpec, occurrences: NativePointer[]): NativePointer[] {
    const targets = spec.literalSuffix ? occurrences.map((hit) => literalStart(hit)) : occurrences;
    const unique = new Map<string, NativePointer>();
    for (const t of targets) unique.set(t.toString(), t);
    return [...unique.values()];
}

/**
 * x86-64: for each target set (index-aligned), the `lea reg, [rip+disp32]` sites in the
 * module's code that load one of its addresses. One chunked pass serves every set.
 */
export async function findRipLeaSitesAsync(
    mod: Module, targetSets: NativePointer[][], chunkBytes: number, yieldFn: () => Promise<void>,
): Promise<NativePointer[][]> {
    const owner = new Map<number, number[]>(); // target address -> indices of the sets holding it
    targetSets.forEach((set, i) => set.forEach((t) => {
        const a = Number(t.toString());
        owner.set(a, [...(owner.get(a) ?? []), i]);
    }));
    const sites: NativePointer[][] = targetSets.map(() => []);
    if (owner.size === 0) return sites;
    const targets = new Set<number>(owner.keys());
    for (const range of codeRanges(mod)) {
        for (let off = 0; off < range.size; off += chunkBytes) {
            if (_isShuttingDownNow()) throw new XrefScanAborted();
            const at = range.base.add(off);
            const own = Math.min(chunkBytes, range.size - off);
            let code: Uint8Array | null = null;
            try {
                const bytes = at.readByteArray(Math.min(own + LEA_RIP_OVERLAP, range.size - off));
                code = bytes ? new Uint8Array(bytes) : null;
            } catch (_e) { code = null; /* unreadable slice */ }
            if (code !== null) {
                for (const ref of findRipLeaRefs(code, Number(at.toString()), targets, own)) {
                    for (const i of owner.get(ref.target) ?? []) sites[i].push(at.add(ref.site - Number(at.toString())));
                }
            }
            await yieldFn();
        }
    }
    return sites;
}

/** Load sites of every target set, for the running architecture ([] where unsupported). */
async function loadSitesFor(
    mod: Module, targetSets: NativePointer[][], maxSites: number,
    chunkBytes: number, yieldFn: () => Promise<void>,
): Promise<NativePointer[][]> {
    if (Process.arch === "x64") return findRipLeaSitesAsync(mod, targetSets, chunkBytes, yieldFn);
    if (Process.arch !== "arm64") return targetSets.map(() => []);
    const flat = targetSets.flat();
    if (flat.length === 0) return targetSets.map(() => []);
    const perTarget = await findStringLoadSitesAsync(mod, flat, chunkBytes, yieldFn, maxSites);
    let k = 0;
    return targetSets.map((set) => set.flatMap(() => perTarget[k++]));
}

/** Group load sites by containing function (pure over `functions`). */
export function groupSitesByFunction(sites: NativePointer[], functions: FunctionBoundsSource): AnchorFunctions {
    const byStart = new Map<string, AnchoredFunction>();
    const unboundedSites: NativePointer[] = [];
    const sorted = [...sites].sort((a, b) => a.compare(b))
        .filter((p, k, all) => k === 0 || !p.equals(all[k - 1]));
    for (const site of sorted) {
        const fn = functions.bounds(site);
        if (fn === null) { unboundedSites.push(site); continue; }
        const key = fn.start.toString();
        const entry = byStart.get(key) ?? { start: fn.start, end: fn.end, sites: [] };
        entry.sites.push(site);
        byStart.set(key, entry);
    }
    const list = [...byStart.values()].sort((a, b) => a.start.compare(b.start));
    return { functions: list, unboundedSites };
}

/**
 * For every anchor (index-aligned): the functions whose code loads its literal. One data
 * pass finds all literals, one code pass all their load sites. An anchor whose literal is
 * absent or unreferenced, or a module without a usable function table, yields no functions.
 */
export async function locateFunctionsByAnchors(
    mod: Module, specs: AnchorSpec[], options: AnchorLocateOptions = {},
): Promise<AnchorFunctions[]> {
    const functions = options.functions !== undefined ? options.functions : ehFrameTableFor(mod);
    if (!functions || specs.length === 0) return specs.map(() => NO_FUNCTIONS);
    const chunkBytes = options.chunkBytes ?? XREF_SCAN_CHUNK_BYTES;
    const yieldFn = options.yieldFn ?? yieldToEventLoop;
    const occurrences = await findLiteralOccurrences(mod, specs.map((s) => s.text), chunkBytes, yieldFn);
    const targetSets = specs.map((s, i) => anchorTargets(s, occurrences[i]));
    const maxSites = Math.max(DEFAULT_MAX_ANCHOR_SITES, ...specs.map((s) => s.maxSites ?? 0));
    const sites = await loadSitesFor(mod, targetSets, maxSites, chunkBytes, yieldFn);
    return specs.map((s, i) =>
        groupSitesByFunction(sites[i].slice(0, s.maxSites ?? DEFAULT_MAX_ANCHOR_SITES), functions));
}

/** The functions whose code loads the literal of `spec` (see locateFunctionsByAnchors). */
export async function locateFunctionsByAnchor(
    mod: Module, spec: AnchorSpec, options: AnchorLocateOptions = {},
): Promise<AnchorFunctions> {
    return (await locateFunctionsByAnchors(mod, [spec], options))[0];
}

/**
 * The agreement rule for anchors that all describe ONE target function:
 *   - anchors with no load site at all are ignored (a message may not exist in every
 *     version of the target);
 *   - every other anchor must be loaded from exactly one function, with no site outside
 *     the function table;
 *   - all of them must name the same function, and at least one anchor must have sites.
 * Anything else — a literal loaded from two functions (an inlined copy, or a shared
 * literal), disagreeing anchors, an unbounded site — returns null: hooking the wrong
 * function is worse than not hooking.
 *
 * `excluded` holds anchors of OTHER functions (e.g. the target's caller's `__func__`): the
 * agreed function must load none of them. That is how a target that was inlined into its
 * caller (no copy of its own, so all its anchors agree on the caller) is told apart.
 */
export function agreedFunction(perAnchor: AnchorFunctions[], excluded: AnchorFunctions[] = []): AnchoredFunction | null {
    let agreed: AnchoredFunction | null = null;
    for (const result of perAnchor) {
        if (result.functions.length === 0 && result.unboundedSites.length === 0) continue;
        if (result.functions.length !== 1 || result.unboundedSites.length > 0) return null;
        const fn = result.functions[0];
        if (agreed !== null && !agreed.start.equals(fn.start)) return null;
        agreed = agreed ?? fn;
    }
    if (agreed === null) return null;
    const home = agreed.start;
    return excluded.some((other) => other.functions.some((f) => f.start.equals(home))) ? null : agreed;
}
