// Unit tests for the landing-pad bounds fallback in eh_frame.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { BTI_C, PACIASP } from "./arm64.js";
import {
    BTI_BEFORE_PACIASP_MAX_WORDS, FallbackFunctionBounds, FunctionBounds, IntervalCache,
    LANDING_PAD_FIRST_CHUNK_BYTES, LANDING_PAD_MAX_SCAN_BYTES, LandingPadScanner, WordReader,
    composeFunctionBounds, findLandingPadEnd, findLandingPadStart, functionBoundsFor,
} from "./eh_frame.js";

const NOP = 0xd503201f;
const RET = 0xd65f03c0;
const STP_FP_LR = 0xa9bf7bfd;       // stp x29, x30, [sp, #-16]!
const CBZ_X0 = 0xb4000040;          // cbz x0, +8 (falls through)
const BL = 0x94000010;              // bl +0x40

/** Reader over `words` placed at byte address `base`; records every address read. */
function memory(base: number, words: number[]): { read: WordReader; touched: number[] } {
    const touched: number[] = [];
    const read: WordReader = (at) => {
        touched.push(at);
        const i = (at - base) / 4;
        return Number.isInteger(i) && i >= 0 && i < words.length ? words[i] : null;
    };
    return { read, touched };
}

// 0x1000: previous fn ... ret | 0x1008: paciasp fn (site at 0x1014) | 0x1020: next fn (bti c)
const BASE = 0x1000;
const LAYOUT = [NOP, RET, PACIASP, STP_FP_LR, BL, NOP, NOP, RET, BTI_C, NOP, RET];

test("PACIASP at or before the address is the start; the next landing pad is the end", () => {
    const { read } = memory(BASE, LAYOUT);
    assert.equal(findLandingPadStart(read, 0x1014, BASE), 0x1008);
    assert.equal(findLandingPadStart(read, 0x1008, BASE), 0x1008);       // the entry itself
    assert.equal(findLandingPadEnd(read, 0x1014, BASE + LAYOUT.length * 4), 0x1020);
});

test("`bti c` entries (address-taken functions without PAC) are starts too", () => {
    const { read } = memory(BASE, LAYOUT);
    assert.equal(findLandingPadStart(read, 0x1024, BASE), 0x1020);
    assert.equal(findLandingPadEnd(read, 0x1024, BASE + LAYOUT.length * 4), null);   // nothing after
});

test("shrink-wrapped PACIASP below a `bti c` + fall-through prefix resolves to the `bti c` entry", () => {
    // ret | bti c | cbz x0 | paciasp | stp | bl  (site at the bl)
    const { read } = memory(BASE, [RET, BTI_C, CBZ_X0, PACIASP, STP_FP_LR, BL]);
    assert.equal(findLandingPadStart(read, 0x1014, BASE), 0x1004);
});

test("a `bti c` behind a non-fall-through word belongs to the PREVIOUS function", () => {
    // bti c | ret (leaf ends) | paciasp | stp | bl
    const { read } = memory(BASE, [BTI_C, RET, PACIASP, STP_FP_LR, BL]);
    assert.equal(findLandingPadStart(read, 0x1010, BASE), 0x1008);
});

test("the `bti c` look-behind is limited to BTI_BEFORE_PACIASP_MAX_WORDS words", () => {
    const prefix = new Array(BTI_BEFORE_PACIASP_MAX_WORDS).fill(NOP);
    const { read } = memory(BASE, [BTI_C, ...prefix, PACIASP, BL]);
    const paciasp = BASE + 4 * (1 + BTI_BEFORE_PACIASP_MAX_WORDS);
    assert.equal(findLandingPadStart(read, paciasp + 4, BASE), paciasp);
});

test("no landing pad within the scan window -> null", () => {
    const { read } = memory(BASE, new Array(64).fill(NOP));
    assert.equal(findLandingPadStart(read, BASE + 0x80, BASE), null);
    // A PACIASP exists, but further back than maxBack allows.
    const far = memory(BASE, [PACIASP, ...new Array(63).fill(NOP)]);
    assert.equal(findLandingPadStart(far.read, BASE + 0xfc, BASE, 0x40), null);
    assert.equal(findLandingPadEnd(far.read, BASE, BASE + 0x100, 0x40), null);
});

test("the backward scan never reads below lowerBound (nor past maxBack)", () => {
    const { read, touched } = memory(BASE, [PACIASP, ...new Array(15).fill(NOP)]);
    // The PACIASP at BASE lies below the bound, so it must be neither read nor returned.
    assert.equal(findLandingPadStart(read, BASE + 0x3c, BASE + 0x10), null);
    assert.ok(touched.every((at) => at >= BASE + 0x10), `read below bound: ${touched}`);
    touched.length = 0;
    findLandingPadStart(read, BASE + 0x3c, 0, 0x10);
    assert.ok(touched.every((at) => at >= BASE + 0x2c), `read past maxBack: ${touched}`);
});

test("the shrink-wrap look-behind also stays above lowerBound", () => {
    const { read, touched } = memory(BASE, [BTI_C, NOP, PACIASP, BL]);
    assert.equal(findLandingPadStart(read, BASE + 0xc, BASE + 8), BASE + 8);
    assert.ok(touched.every((at) => at >= BASE + 8));
});

test("the forward scan stops at upperBound", () => {
    const { read, touched } = memory(BASE, LAYOUT);
    assert.equal(findLandingPadEnd(read, 0x1014, 0x1020), null);         // bti c at 0x1020 is out of range
    assert.ok(touched.every((at) => at + 4 <= 0x1020));
});

test("an unreadable word ends the scan with null", () => {
    const { read } = memory(BASE + 0x10, [NOP, NOP]);                  // nothing mapped below 0x1010
    assert.equal(findLandingPadStart(read, BASE + 0x14, 0), null);
});

test("unaligned addresses scan from their instruction", () => {
    const { read } = memory(BASE, LAYOUT);
    assert.equal(findLandingPadStart(read, 0x1016, BASE), 0x1008);
});

test("default scan window is 64 KiB", () => {
    assert.equal(LANDING_PAD_MAX_SCAN_BYTES, 0x10000);
});

// ---- FDE-first composition --------------------------------------------------

const fakePtr = (n: number) => ({ n }) as unknown as NativePointer;

test("FDE-covered addresses keep their FDE bounds, unchanged; the fallback is not consulted", () => {
    const fde: FunctionBounds = { start: fakePtr(0x100), end: fakePtr(0x180) };
    let fallbackCalls = 0;
    const source = new FallbackFunctionBounds({ bounds: () => fde }, { bounds: () => { fallbackCalls++; return null; } });
    assert.equal(source.bounds(fakePtr(0x140)), fde);                   // same object
    assert.deepEqual(Object.keys(fde), ["start", "end"]);               // no extra fields added
    assert.equal(fallbackCalls, 0);
});

test("addresses no FDE covers get the fallback's bounds; both missing -> null", () => {
    const guessed: FunctionBounds = { start: fakePtr(0x200), end: null };
    const covered = new FallbackFunctionBounds({ bounds: () => null }, { bounds: () => guessed });
    assert.equal(covered.bounds(fakePtr(0x240)), guessed);
    const none = new FallbackFunctionBounds({ bounds: () => null }, { bounds: () => null });
    assert.equal(none.bounds(fakePtr(0x240)), null);
});

test("an FDE result with an unverified end keeps the FDE start and takes only the landing-pad end", () => {
    const unverified: FunctionBounds = { start: fakePtr(0x100), end: null };
    // the pad scan stopped at an earlier function's PACIASP
    const guessed: FunctionBounds = { start: fakePtr(0x80), end: fakePtr(0x280) };
    const source = composeFunctionBounds({ bounds: () => unverified }, { bounds: () => guessed });
    assert.deepEqual(source.bounds(fakePtr(0x240)), { start: fakePtr(0x100), end: fakePtr(0x280) });
});

test("an FDE result with an unverified end is kept when the landing-pad scan finds no end", () => {
    const unverified: FunctionBounds = { start: fakePtr(0x100), end: null };
    const source = new FallbackFunctionBounds({ bounds: () => unverified },
        { bounds: () => ({ start: fakePtr(0x80), end: null }) });
    assert.equal(source.bounds(fakePtr(0x240)), unverified);
});

test("an FDE result with an unverified end is kept when the landing-pad scan finds nothing", () => {
    const unverified: FunctionBounds = { start: fakePtr(0x100), end: null };
    const source = new FallbackFunctionBounds({ bounds: () => unverified }, { bounds: () => null });
    assert.equal(source.bounds(fakePtr(0x240)), unverified);           // same object
});

test("a module without an .eh_frame_hdr table uses the landing-pad bounds alone", () => {
    const fallback = { bounds: () => null };
    assert.equal(composeFunctionBounds(null, fallback), fallback);
});

test("a module with a table keeps FDE bounds first and falls back per address", () => {
    const fde: FunctionBounds = { start: fakePtr(0x100), end: fakePtr(0x180) };
    const guessed: FunctionBounds = { start: fakePtr(0x200), end: null };
    const covered = composeFunctionBounds({ bounds: () => fde }, { bounds: () => guessed });
    assert.equal(covered.bounds(fakePtr(0x140)), fde);
    const uncovered = composeFunctionBounds({ bounds: () => null }, { bounds: () => guessed });
    assert.equal(uncovered.bounds(fakePtr(0x240)), guessed);
});

// ---- interval cache ----------------------------------------------------------

test("IntervalCache finds the interval holding a point; hi is exclusive", () => {
    const cache = new IntervalCache<string>();
    cache.add(0x200, 0x300, "b");
    cache.add(0x100, 0x180, "a");
    assert.equal(cache.find(0x100), "a");
    assert.equal(cache.find(0x17c), "a");
    assert.equal(cache.find(0x180), null);
    assert.equal(cache.find(0x2fc), "b");
    assert.equal(cache.find(0x300), null);
    assert.equal(cache.find(0x80), null);
});

test("IntervalCache ignores empty and overlapping intervals", () => {
    const cache = new IntervalCache<string>();
    cache.add(0x100, 0x200, "a");
    cache.add(0x180, 0x280, "overlap");
    cache.add(0x80, 0x104, "overlap");
    cache.add(0x300, 0x300, "empty");
    assert.equal(cache.size, 1);
    assert.equal(cache.find(0x1fc), "a");
});

// ---- LandingPadScanner: chunked reads + per-module cache ---------------------

/** Module image of `bytes` NOP words with landing pads at `pads`; records every read. */
function image(bytes: number, pads: Record<number, number>) {
    const view = new DataView(new ArrayBuffer(bytes));
    for (let at = 0; at < bytes; at += 4) view.setUint32(at, pads[at] ?? NOP, true);
    const reads: { from: number; length: number }[] = [];
    const readBytes = (from: number, length: number) => {
        reads.push({ from, length });
        return from >= 0 && from + length <= bytes ? view.buffer.slice(from, from + length) : null;
    };
    let spanLookups = 0;
    const span = () => { spanLookups++; return { lo: 0, hi: bytes }; };
    return { readBytes, reads, span, spanLookups: () => spanLookups };
}

test("a nearby landing pad costs one first chunk in each direction, not the whole window", () => {
    const img = image(0x20000, { 0x8000: PACIASP, 0x8100: BTI_C });
    const found = new LandingPadScanner(img.readBytes).bounds(0x8040, img.span);
    assert.deepEqual(found, { start: 0x8000, end: 0x8100 });
    assert.ok(img.reads.every((r) => r.length === LANDING_PAD_FIRST_CHUNK_BYTES), JSON.stringify(img.reads));
    assert.equal(img.reads.length, 2);
});

test("chunked reads double until they reach a boundary beyond the first 4 KiB", () => {
    const img = image(0x20000, { 0x1000: PACIASP, 0xd000: BTI_C });   // both > 4 KiB from the site
    const found = new LandingPadScanner(img.readBytes).bounds(0x8000, img.span);
    assert.deepEqual(found, { start: 0x1000, end: 0xd000 });
    const lengths = img.reads.map((r) => r.length);
    assert.equal(lengths[0], LANDING_PAD_FIRST_CHUNK_BYTES);
    assert.ok(lengths.some((n) => n > LANDING_PAD_FIRST_CHUNK_BYTES), `no growth: ${lengths}`);
    const total = lengths.reduce((a, b) => a + b, 0);
    assert.ok(total <= 2 * LANDING_PAD_MAX_SCAN_BYTES + 4, `read ${total} bytes`);
});

test("chunked reads stay inside the 64 KiB scan bound", () => {
    const img = image(0x40000, { 0x0: PACIASP });                    // too far back from the site
    assert.equal(new LandingPadScanner(img.readBytes).bounds(0x20000, img.span), null);
    assert.ok(img.reads.every((r) => r.from >= 0x20000 - LANDING_PAD_MAX_SCAN_BYTES
                                     && r.from + r.length <= 0x20000 + LANDING_PAD_MAX_SCAN_BYTES + 4),
              JSON.stringify(img.reads));
});

test("an address inside a cached function reuses it without reading memory", () => {
    const img = image(0x20000, { 0x8000: PACIASP, 0x8100: BTI_C });
    const scanner = new LandingPadScanner(img.readBytes);
    const first = scanner.bounds(0x8040, img.span);
    const [reads, lookups] = [img.reads.length, img.spanLookups()];
    assert.equal(scanner.bounds(0x80fc, img.span), first);              // same cached object
    assert.equal(scanner.bounds(0x8000, img.span), first);
    assert.equal(img.reads.length, reads);
    assert.equal(img.spanLookups(), lookups);
    scanner.bounds(0x8100, img.span);                                   // the next function: a fresh scan
    assert.ok(img.reads.length > reads);
});

test("unbounded results (no end found) are not cached", () => {
    const img = image(0x2000, { 0x100: PACIASP });
    const scanner = new LandingPadScanner(img.readBytes);
    assert.deepEqual(scanner.bounds(0x200, img.span), { start: 0x100, end: null });
    const reads = img.reads.length;
    scanner.bounds(0x200, img.span);
    assert.ok(img.reads.length > reads);
});

test("a shrink-wrapped function caches from its PACIASP, so its `bti c` prefix is scanned afresh", () => {
    // bti c @0x1004 | cbz x0 | paciasp @0x100c | stp | bl | ... | bti c @0x1100
    const img = image(0x4000, { 0x1004: BTI_C, 0x1008: CBZ_X0, 0x100c: PACIASP, 0x1010: STP_FP_LR, 0x1100: BTI_C });
    const scanner = new LandingPadScanner(img.readBytes);
    assert.deepEqual(scanner.bounds(0x1014, img.span), { start: 0x1004, end: 0x1100 });
    // Uncached, the prefix's own scan ends at the PACIASP.
    assert.deepEqual(scanner.bounds(0x1008, img.span), { start: 0x1004, end: 0x100c });
});

test("no executable span -> null; addresses outside the span -> null", () => {
    const img = image(0x2000, { 0x100: PACIASP, 0x200: BTI_C });
    const scanner = new LandingPadScanner(img.readBytes);
    assert.equal(scanner.bounds(0x140, () => null), null);
    assert.equal(scanner.bounds(0x140, () => ({ lo: 0x400, hi: 0x2000 })), null);
});

test("chunked, uncached scans match the former full-window scan at every site", () => {
    let seed = 7;
    const rand = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
    const size = 0x30000, pads: Record<number, number> = {};
    for (let at = 0; at < size; at += 4) {
        const r = rand();
        if (r < 0.0004) pads[at] = PACIASP; else if (r < 0.0006) pads[at] = BTI_C; else if (r < 0.0008) pads[at] = RET;
    }
    const img = image(size, pads);
    const full = new DataView(img.readBytes(0, size)!);
    for (let site = 0; site < size; site += 0x1f2) {
        // Reference: one read of [low, high), scans relative to low.
        const aligned = site & ~3;
        const low = Math.max(0, aligned - LANDING_PAD_MAX_SCAN_BYTES);
        const high = Math.min(size, aligned + LANDING_PAD_MAX_SCAN_BYTES + 4);
        const read: WordReader = (at) => at >= 0 && at + 4 <= high - low ? full.getUint32(low + at, true) : null;
        const start = findLandingPadStart(read, aligned - low, 0);
        const end = start === null ? null : findLandingPadEnd(read, aligned - low, high - low);
        const expected = start === null ? null : { start: low + start, end: end === null ? null : low + end };
        assert.deepEqual(new LandingPadScanner(img.readBytes).bounds(site, img.span), expected, `site 0x${site.toString(16)}`);
    }
});

// ---- architecture gate --------------------------------------------------------

/** Numeric NativePointer stand-in; reading memory through it fails (no .eh_frame_hdr). */
function numPtr(n: number): NativePointer {
    const value = (o: unknown) => typeof o === "number" ? o : (o as { n: number }).n;
    return {
        n, readU32: () => { throw new Error("unmapped"); }, toString: () => "0x" + n.toString(16),
        compare: (o: unknown) => Math.sign(n - value(o)), add: (o: unknown) => numPtr(n + value(o)),
        sub: (o: unknown) => numPtr(n - value(o)), toUInt32: () => n,
    } as unknown as NativePointer;
}

/** functionBoundsFor(...).bounds() on a table-less module under `arch`; counts r-x range lookups. */
function boundsWithoutTable(arch: string): { bounds: FunctionBounds | null; rangeLookups: number } {
    let rangeLookups = 0;
    const mod = {
        name: `lib-${arch}.so`, base: numPtr(0x7000), size: 0x1000,
        enumerateRanges: () => { rangeLookups++; return []; },
    } as unknown as Module;
    const previousArch = Process.arch;
    (Process as { arch: string }).arch = arch;
    try {
        return { bounds: functionBoundsFor(mod).bounds(numPtr(0x7010)), rangeLookups };
    } finally {
        (Process as { arch: string }).arch = previousArch;
    }
}

test("functionBoundsFor scans for landing pads only on arm64", () => {
    assert.deepEqual(boundsWithoutTable("x64"), { bounds: null, rangeLookups: 0 });
    assert.deepEqual(boundsWithoutTable("arm64"), { bounds: null, rangeLookups: 1 });
});
