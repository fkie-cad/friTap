// Unit tests for the generic AArch64 xref helpers in arm64_xref.ts.
//
// Run: npm run test:agent
//
// These walk real Frida Module/NativePointer objects, so the suite backs them
// with a synthetic arm64 byte buffer and a minimal NativePointer/Module/Memory
// polyfill. It pins the three primitives the BoringSSL anchor locator (tier 4)
// and the Signal libsignal discovery both rely on:
//   findAnchorString    — locate a NUL-terminated string in a module range;
//   findStringLoadSites — find the ADRP/ADD site that materialises its address;
//   firstCallTargetForward — resolve the next direct BL from that site.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

// A synthetic module: a 0x2000 buffer based at 0x100000, split into a data range
// (r--) holding the anchor string and a code range (r-x) holding the loads/call.
const BASE = 0x100000;
const SIZE = 0x2000;
const DATA_RANGE = { base: BASE, size: 0x100 };        // 0x100000 .. 0x100100
const CODE_RANGE = { base: BASE + 0x100, size: 0x100 }; // 0x100100 .. 0x100200
const buf = new Uint8Array(SIZE);

/** NativePointer stand-in backed by `buf` (reads) plus plain address arithmetic. */
class BufPtr {
    constructor(public addr: number) {}
    isNull() { return this.addr === 0; }
    toString() { return "0x" + (this.addr >>> 0).toString(16); }
    equals(o: BufPtr) { return this.addr === o.addr; }
    compare(o: BufPtr) { return this.addr < o.addr ? -1 : this.addr > o.addr ? 1 : 0; }
    add(n: number | BufPtr) { return new BufPtr(this.addr + (typeof n === "number" ? n : n.addr)); }
    sub(n: number | BufPtr) { return new BufPtr(this.addr - (typeof n === "number" ? n : n.addr)); }
    and(o: BufPtr) { return new BufPtr(this.addr & o.addr); }
    not() { return new BufPtr(~this.addr); }
    toInt32() { return this.addr | 0; }
    readU32() {
        const off = this.addr - BASE;
        if (off < 0 || off + 4 > SIZE) throw new Error("read out of range");
        return (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0;
    }
    readPointer() {
        const off = this.addr - BASE;
        if (off < 0 || off + 8 > SIZE) throw new Error("read out of range");
        let v = 0;
        for (let i = 0; i < 8; i++) v += buf[off + i] * 2 ** (8 * i);
        return new BufPtr(v);
    }
    readCString() {
        let off = this.addr - BASE;
        let s = "";
        while (off < SIZE && buf[off] !== 0) { s += String.fromCharCode(buf[off]); off++; }
        return s;
    }
}

const fakeModule = {
    base: new BufPtr(BASE),
    size: SIZE,
    name: "libfake.so",
    enumerateRanges(prot: string) {
        const r = prot === "r-x" ? CODE_RANGE : DATA_RANGE;
        return [{ base: new BufPtr(r.base), size: r.size, protection: prot }];
    },
} as unknown as Module;

// Wire the globals the helpers reach at call time (after frida-test-stubs loads).
G.ptr = (v: any) => new BufPtr(typeof v === "string" ? parseInt(v, 16) : Number(v));
// Supports Frida's "aa bb : ff 0f" mask form and returns EVERY match in range,
// like the real scanSync (matches are byte-granular, not word-aligned).
G.Memory.scanSync = (base: any, size: number, pattern: string) => {
    const [needleStr, maskStr] = pattern.split(":");
    const needle = needleStr.trim().split(/\s+/).map((h) => parseInt(h, 16));
    const mask = maskStr ? maskStr.trim().split(/\s+/).map((h) => parseInt(h, 16)) : needle.map(() => 0xff);
    const start = base.addr - BASE;
    const hits: { address: BufPtr }[] = [];
    for (let i = start; i + needle.length <= start + size && i + needle.length <= SIZE; i++) {
        let ok = true;
        for (let j = 0; j < needle.length; j++) {
            if ((buf[i + j] & mask[j]) !== (needle[j] & mask[j])) { ok = false; break; }
        }
        if (ok) hits.push({ address: new BufPtr(BASE + i) });
    }
    return hits;
};

import {
    findAnchorString, findStringLoadSites, firstCallTargetForward,
    adrpTarget, blTarget, inModule,
    findStringLoadSitesAsync, findAnchorStringsAsync, findOpeningAdrp,
    scanRangesChunked, patternByteLength, pointerScanPattern, LOAD_SITE_WINDOW, withoutLeadingWildcards,
    adrTarget, adrScanWindows, ADR_REACH_BYTES,
    outlinedStubBody, ARG_SETUP_STUB, REGISTER_SAVE_STUB, isRegisterMove, isRegisterSave, isEpilogueLinkReload,
} from "./arm64_xref.js";

// ---- instruction / buffer builders -----------------------------------------

function writeU32(byteOff: number, word: number): void {
    buf[byteOff] = word & 0xff;
    buf[byteOff + 1] = (word >>> 8) & 0xff;
    buf[byteOff + 2] = (word >>> 16) & 0xff;
    buf[byteOff + 3] = (word >>> 24) & 0xff;
}
function writeString(byteOff: number, s: string): void {
    for (let i = 0; i < s.length; i++) buf[byteOff + i] = s.charCodeAt(i);
    buf[byteOff + s.length] = 0; // NUL
}
/** ADRP Xrd, <same page as pc> (imm == 0). */
const adrpSamePage = (rd: number) => (0x90000000 | rd) >>> 0;
/** ADD Xrd, Xrn, #imm (64-bit, no shift). */
const addImm = (rd: number, rn: number, imm: number) =>
    (0x91000000 | (imm << 10) | (rn << 5) | rd) >>> 0;
/** ADRP Xrd, <page of pc + pages*0x1000>. */
const adrpPages = (rd: number, pages: number) =>
    (0x90000000 | ((pages & 0x3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | rd) >>> 0;
/** LDR Xrt, [Xrn, #byteOff] (unsigned offset, 64-bit). */
const ldr64 = (rt: number, rn: number, byteOff: number) =>
    (0xf9400000 | ((byteOff / 8) << 10) | (rn << 5) | rt) >>> 0;
const NOP = 0xd503201f;
function writePtr(byteOff: number, value: number): void {
    for (let i = 0; i < 8; i++) buf[byteOff + i] = Math.floor(value / 2 ** (8 * i)) & 0xff;
}
/** BL <pc-relative>. */
const bl = (pc: number, target: number) =>
    (0x94000000 | (((target - pc) / 4) & 0x03ffffff)) >>> 0;

// Layout: string "CLIENT_RANDOM" at 0x100040; at 0x100100 an ADRP/ADD pair that
// materialises 0x100040, then a BL to 0x100180; a stray BLR would be unresolved.
const STR_OFF = 0x40;                 // -> address 0x100040
const SITE = BASE + 0x100;            // 0x100100
const CALL_TARGET = BASE + 0x180;     // 0x100180

writeString(STR_OFF, "CLIENT_RANDOM");
writeU32(0x100, adrpSamePage(1));                      // adrp x1, page(0x100000)
writeU32(0x104, addImm(1, 1, 0x40));                   // add  x1, x1, #0x40  -> 0x100040
writeU32(0x108, bl(SITE + 8, CALL_TARGET));            // bl   0x100180

// Second label for the multi-target (native scan) tests, plus distractors that
// the verification must reject. All in the module's single page 0x100000.
const EXP_OFF = 0x60;                 // "EXPORTER_SECRET" -> 0x100060
const SLOT_OFF = 0x80;                // pointer slot holding 0x100060
const OTHER_CALLEE = BASE + 0x1c0;
writeString(EXP_OFF, "EXPORTER_SECRET");
writePtr(SLOT_OFF, BASE + EXP_OFF);
// 0x110: wrong page — adrp x3, page+1 ; add x3, x3, #0x40   (reject)
writeU32(0x110, adrpPages(3, 1));
writeU32(0x114, addImm(3, 3, 0x40));
// 0x120: pointer slot — adrp x2 ; ldr x2, [x2, #0x80] ; bl CALL_TARGET
writeU32(0x120, adrpSamePage(2));
writeU32(0x124, ldr64(2, 2, SLOT_OFF));
writeU32(0x128, bl(BASE + 0x128, CALL_TARGET));
// 0x130: direct — adrp x4 ; add x4, x4, #0x60 ; bl OTHER_CALLEE
writeU32(0x130, adrpSamePage(4));
writeU32(0x134, addImm(4, 4, EXP_OFF));
writeU32(0x138, bl(BASE + 0x138, OTHER_CALLEE));
// 0x140: not in-place — adrp x6 ; add x7, x6, #0x40   (reject, as the JS walk does)
writeU32(0x140, adrpSamePage(6));
writeU32(0x144, addImm(7, 6, 0x40));
// 0x150: intervening add — adrp x8 ; add x8,x8,#8 ; add x8,x8,#0x40   (reject)
writeU32(0x150, adrpSamePage(8));
writeU32(0x154, addImm(8, 8, 0x8));
writeU32(0x158, addImm(8, 8, 0x40));

// 0x160: linker-relaxed — adr x5, 0x100091 ; bl CALL_TARGET   (shape 3, odd target)
// 0x168: adr x6, 0x100095 — same low 2 bits, different address   (reject)
const HS_OFF = 0x91;                  // "CLIENT_HANDSHAKE_TRAFFIC_SECRET" -> 0x100091
/** ADR Xrd, <target> at `pc`. */
const adr = (rd: number, pc: number, target: number) => {
    const imm = target - pc;
    return (0x10000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7ffff) << 5) | rd) >>> 0;
};
writeString(HS_OFF, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
writeU32(0x160, adr(5, BASE + 0x160, BASE + HS_OFF));
writeU32(0x164, bl(BASE + 0x164, CALL_TARGET));
writeU32(0x168, adr(6, BASE + 0x168, BASE + HS_OFF + 4));

const modStart = new BufPtr(BASE);
const modEnd = new BufPtr(BASE + SIZE);

test("findAnchorString locates a NUL-terminated string in a module range", () => {
    const at = findAnchorString(fakeModule, "CLIENT_RANDOM\u0000");
    assert.ok(at, "string not found");
    assert.equal((at as unknown as BufPtr).addr, BASE + STR_OFF);
});

test("findStringLoadSites finds the ADRP/ADD site that materialises the address", () => {
    const target = new BufPtr(BASE + STR_OFF) as unknown as NativePointer;
    const sites = findStringLoadSites(fakeModule, target);
    assert.equal(sites.length, 1);
    assert.equal((sites[0] as unknown as BufPtr).addr, SITE);
});

test("firstCallTargetForward resolves the next direct BL from the load site", () => {
    const site = new BufPtr(SITE) as unknown as NativePointer;
    const callee = firstCallTargetForward(site, modEnd as any, modStart as any, modEnd as any);
    assert.ok(callee, "no call resolved");
    assert.equal((callee as unknown as BufPtr).addr, CALL_TARGET);
});

test("end-to-end: anchor string -> load site -> call target", () => {
    const at = findAnchorString(fakeModule, "CLIENT_RANDOM\u0000")!;
    const sites = findStringLoadSites(fakeModule, at);
    const callee = firstCallTargetForward(sites[0], modEnd as any, modStart as any, modEnd as any);
    assert.equal((callee as unknown as BufPtr).addr, CALL_TARGET);
});

test("findStringLoadSites returns nothing for an unreferenced address", () => {
    const target = new BufPtr(BASE + 0x7f8) as unknown as NativePointer; // nothing loads this
    assert.deepEqual(findStringLoadSites(fakeModule, target), []);
});

test("adrpTarget clears the low 12 bits of pc before adding the page immediate", () => {
    // adrp with imm==0 targets pc's own page.
    const page = adrpTarget(new BufPtr(SITE) as any, adrpSamePage(1));
    assert.equal((page as unknown as BufPtr).addr, BASE);
});

test("blTarget resolves a positive PC-relative offset; inModule bounds it", () => {
    const t = blTarget(new BufPtr(SITE + 8) as any, bl(SITE + 8, CALL_TARGET));
    assert.equal((t as unknown as BufPtr).addr, CALL_TARGET);
    assert.equal(inModule(t, modStart as any, modEnd as any), true);
    assert.equal(inModule(new BufPtr(BASE + SIZE + 4) as any, modStart as any, modEnd as any), false);
});

// ---- native, chunked, multi-target variants --------------------------------

const P = (off: number) => new BufPtr(BASE + off) as unknown as NativePointer;
const addrs = (list: NativePointer[]) => list.map((p) => (p as unknown as BufPtr).addr - BASE);

test("findOpeningAdrp returns the ADRP whose page matches", () => {
    const at = findOpeningAdrp(P(0x104), 1, P(0), P(0x100));
    assert.equal((at as unknown as BufPtr).addr, SITE);
});

test("findOpeningAdrp rejects an ADRP to a different page", () => {
    assert.equal(findOpeningAdrp(P(0x114), 3, P(0), P(0x100)), null);
});

test("findOpeningAdrp rejects an intervening ADD into the register", () => {
    assert.equal(findOpeningAdrp(P(0x158), 8, P(0), P(0x100)), null);
});

test("findOpeningAdrp never walks before the range start", () => {
    assert.equal(findOpeningAdrp(P(0x104), 1, P(0), P(0x104)), null);
});

test("findOpeningAdrp gives up beyond the window", () => {
    // A synthetic walk: the ADRP sits LOAD_SITE_WINDOW+1 words back.
    const off = 0x1d0;
    writeU32(off, adrpSamePage(9));
    for (let k = 1; k <= LOAD_SITE_WINDOW; k++) writeU32(off + 4 * k, NOP);
    assert.equal(findOpeningAdrp(P(off + 4 * (LOAD_SITE_WINDOW + 1)), 9, P(0), P(0x100)), null);
    assert.equal((findOpeningAdrp(P(off + 4 * LOAD_SITE_WINDOW), 9, P(0), P(0x100)) as any).addr, BASE + off);
    for (let k = 0; k <= LOAD_SITE_WINDOW; k++) writeU32(off + 4 * k, 0);
});

test("one pass finds every label's sites (direct ADD and pointer slot), rejecting distractors", async () => {
    const sites = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF), P(EXP_OFF)]);
    assert.deepEqual(addrs(sites[0]), [0x100]);          // CLIENT_RANDOM: direct only
    assert.deepEqual(addrs(sites[1]), [0x120, 0x130]);   // EXPORTER_SECRET: slot + direct, ascending
});

test("the multi-target result agrees with the JS walk for the shapes both cover", async () => {
    const [fast] = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF)]);
    assert.deepEqual(addrs(fast), addrs(findStringLoadSites(fakeModule, P(STR_OFF))));
});

test("tiny chunks yield between slices and still find the same sites", async () => {
    let yields = 0;
    const yieldFn = async () => { yields++; };
    const sites = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF), P(EXP_OFF)], 0x10, yieldFn);
    assert.deepEqual(addrs(sites[0]), [0x100]);
    assert.deepEqual(addrs(sites[1]), [0x120, 0x130]);
    assert.ok(yields >= 0x100 / 0x10, `expected per-chunk yields, got ${yields}`);
});

test("findStringLoadSitesAsync completes asynchronously (does not block the caller)", async () => {
    let settled = false;
    const p = findStringLoadSitesAsync(fakeModule, [P(STR_OFF)]).then(() => { settled = true; });
    assert.equal(settled, false, "must not settle synchronously");
    await p;
    assert.equal(settled, true);
});

test("findAnchorStringsAsync finds several strings, including one straddling a chunk edge", async () => {
    // With 0x10-byte chunks the string at 0x40 is split across 0x40..0x50,
    // and EXPORTER_SECRET at 0x60 (16 bytes incl. NUL) ends exactly on 0x70.
    const found = await findAnchorStringsAsync(fakeModule,
        ["CLIENT_RANDOM\u0000", "EXPORTER_SECRET\u0000", "MISSING_LABEL\u0000", "RANDOM\u0000"],
        0x10, async () => { });
    assert.deepEqual(found.map((p) => p === null ? null : (p as unknown as BufPtr).addr - BASE),
        [STR_OFF, EXP_OFF, null, STR_OFF + 7]);
});

test("scanRangesChunked reports a straddling match exactly once", async () => {
    const hits: number[] = [];
    await scanRangesChunked([{ base: P(0x40), size: 0x20 }],
        [{ pattern: "5f 52 41", onMatch: (a) => hits.push((a as any).addr - BASE) }], 0x7, async () => { });
    assert.deepEqual(hits, [0x46]); // "_RA" of CLIENT_RANDOM, split by the 0x47 edge
});

test("scanRangesChunked clears status.complete on an unreadable slice (clean scans leave it set)", async () => {
    const realScan = G.Memory.scanSync;
    const clean = { complete: true };
    await scanRangesChunked([{ base: P(0x40), size: 0x20 }], [{ pattern: "5f 52 41", onMatch: () => { } }], 0x10, async () => { }, clean);
    assert.equal(clean.complete, true);
    const faulted = { complete: true };
    G.Memory.scanSync = () => { throw new Error("access violation"); };
    try {
        await scanRangesChunked([{ base: P(0x40), size: 0x20 }], [{ pattern: "5f 52 41", onMatch: () => { } }], 0x10, async () => { }, faulted);
    } finally {
        G.Memory.scanSync = realScan;
    }
    assert.equal(faulted.complete, false);
    assert.equal(clean.complete, true, "another call's fault does not leak into this status");
});

test("withoutLeadingWildcards drops leading masked / ?? bytes (Frida <= 17.15 rejects them)", () => {
    assert.deepEqual(withoutLeadingWildcards("00 20 03 91 : 00 fc ff ff"), { pattern: "20 03 91 : fc ff ff", skipped: 1 });
    assert.deepEqual(withoutLeadingWildcards("?? ?? 41 42"), { pattern: "41 42", skipped: 2 });
    assert.deepEqual(withoutLeadingWildcards("43 4c 49"), { pattern: "43 4c 49", skipped: 0 });
    assert.deepEqual(withoutLeadingWildcards("00 00 : 00 00"), { pattern: "00 00 : 00 00", skipped: 0 }, "all wildcards: unchanged");
});

test("scanRangesChunked: a leading-wildcard pattern reports where the FULL pattern starts, once", async () => {
    // Behave like Frida 17.15: a pattern whose first byte is a wildcard is invalid.
    const realScan = G.Memory.scanSync;
    G.Memory.scanSync = (base: any, size: number, pattern: string) => {
        if (withoutLeadingWildcards(pattern).skipped > 0) throw new Error("invalid match pattern");
        return realScan(base, size, pattern);
    };
    try {
        // "?? 52 41" matches "_RA" (0x46) of CLIENT_RANDOM; split by a chunk edge at 0x47 / 0x48.
        for (const chunk of [0x7, 0x8, 0x20]) {
            const hits: number[] = [];
            await scanRangesChunked([{ base: P(0x40), size: 0x20 }],
                [{ pattern: "00 52 41 : 00 ff ff", onMatch: (a) => hits.push((a as any).addr - BASE) }], chunk, async () => { });
            assert.deepEqual(hits, [0x46], `chunk 0x${chunk.toString(16)}`);
        }
    } finally {
        G.Memory.scanSync = realScan;
    }
});

test("findStringLoadSitesAsync on a Frida that rejects leading wildcards finds the same sites", async () => {
    // Every ADD/LDR-imm word pattern starts with a register-only (fully masked) byte.
    const expected = (await findStringLoadSitesAsync(fakeModule, [P(STR_OFF), P(EXP_OFF)], 0x10, async () => { }))
        .map(addrs);
    assert.deepEqual(expected, [[0x100], [0x120, 0x130]]);
    const realScan = G.Memory.scanSync;
    let rejected = 0;
    G.Memory.scanSync = (base: any, size: number, pattern: string) => {
        const tokens = pattern.split(":");
        const firstMask = tokens[1]?.trim().split(/\s+/)[0];
        if (tokens[0].trim().startsWith("??") || firstMask === "00") { rejected++; throw new Error("invalid match pattern"); }
        return realScan(base, size, pattern);
    };
    try {
        for (const chunk of [0x10, 0x2000]) {
            const sites = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF), P(EXP_OFF)], chunk, async () => { });
            assert.deepEqual(sites.map(addrs), expected, `chunk 0x${chunk.toString(16)}`);
        }
    } finally {
        G.Memory.scanSync = realScan;
    }
    assert.equal(rejected, 0, "no leading-wildcard pattern reaches Memory.scanSync");
});

test("scanRangesChunked: a leading-wildcard match that would start before the range is dropped", async () => {
    const hits: number[] = [];
    // The range starts at "RA" (0x47): "?? 52 41" would begin at 0x46, outside the range.
    await scanRangesChunked([{ base: P(0x47), size: 0x10 }],
        [{ pattern: "?? 52 41", onMatch: (a) => hits.push((a as any).addr - BASE) }], 0x10, async () => { });
    assert.deepEqual(hits, []);
});

test("patternByteLength ignores the mask half", () => {
    assert.equal(patternByteLength("00 00 01 91 : 00 fc ff ff"), 4);
    assert.equal(patternByteLength("43 4c 49"), 3);
});

test("pointerScanPattern is the 8-byte little-endian pointer value", () => {
    assert.equal(pointerScanPattern(P(0x60)), "60 00 10 00 00 00 00 00");
});

// ---- scratch-area helpers (0x1d0..0x200, cleared after each test) ----------

const SCRATCH = 0x1d0;
function withScratch(words: number[], body: () => void | Promise<void>): void | Promise<void> {
    words.forEach((w, k) => writeU32(SCRATCH + 4 * k, w));
    const clear = () => { for (let k = 0; k < words.length; k++) writeU32(SCRATCH + 4 * k, 0); };
    try {
        const r = body();
        if (r instanceof Promise) return r.finally(clear);
        clear();
        return r;
    } catch (e) { clear(); throw e; }
}
const B = (pc: number, target: number) => (0x14000000 | (((target - pc) / 4) & 0x03ffffff)) >>> 0;
const RET = 0xd65f03c0, RETAA = 0xd65f0bff, BR_X16 = 0xd61f0200, BRK1 = 0xd4200020;
const MOV_X9_X5 = 0xaa0503e9;           // mov x9, x5
const LDR_X9_X3 = 0xf9400469;           // ldr x9, [x3, #8]
const LDP_X2_X9 = 0xa94024a2;           // ldp x2, x9, [x5]
const MOVK_X9 = 0xf2a000a9;             // movk x9, #5, lsl #16
const STR_X9_X5 = 0xf90000a9;           // str x9, [x5]       (reads x9, does not write)
const CMP_X9 = 0xf100113f;              // cmp x9, #4
const LDR_X2_X5 = 0xf94004a2;           // ldr x2, [x5, #8]
const BEQ_FWD = 0x54000040;             // b.eq .+8

// ---- S2: the forward walk stays inside the site's fall-through --------------

test("firstCallTargetForward stops at a tail-call B instead of voting the next function's BL", () =>
    withScratch([NOP, B(BASE + SCRATCH + 4, CALL_TARGET), bl(BASE + SCRATCH + 8, OTHER_CALLEE)], () => {
        assert.equal(firstCallTargetForward(P(SCRATCH), modEnd as any, modStart as any, modEnd as any), null);
    }));

for (const [name, word] of [["RET", RET], ["RETAA", RETAA], ["BR x16", BR_X16], ["BRK #1", BRK1]] as const) {
    test(`firstCallTargetForward stops at ${name}`, () =>
        withScratch([NOP, word, bl(BASE + SCRATCH + 8, OTHER_CALLEE)], () => {
            assert.equal(firstCallTargetForward(P(SCRATCH), modEnd as any, modStart as any, modEnd as any), null);
        }));
}

test("firstCallTargetForward walks past a conditional branch to the BL", () =>
    withScratch([NOP, BEQ_FWD, NOP, bl(BASE + SCRATCH + 12, OTHER_CALLEE)], () => {
        const c = firstCallTargetForward(P(SCRATCH), modEnd as any, modStart as any, modEnd as any);
        assert.equal((c as unknown as BufPtr).addr, OTHER_CALLEE);
    }));

test("firstCallTargetForward bails on an authenticated indirect call (BLRAA)", () =>
    withScratch([NOP, 0xd73f0909, bl(BASE + SCRATCH + 8, OTHER_CALLEE)], () => {
        assert.equal(firstCallTargetForward(P(SCRATCH), modEnd as any, modStart as any, modEnd as any), null);
    }));

// ---- S4: any intervening writer breaks the ADRP -> ADD/LDR link ---------------

for (const [name, word] of [["mov x9, x5", MOV_X9_X5], ["ldr x9, [x3, #8]", LDR_X9_X3],
    ["ldp x2, x9, [x5]", LDP_X2_X9], ["movk x9", MOVK_X9]] as const) {
    test(`findOpeningAdrp rejects an intervening ${name}`, () =>
        withScratch([adrpSamePage(9), word, addImm(9, 9, STR_OFF)], () => {
            assert.equal(findOpeningAdrp(P(SCRATCH + 8), 9, P(0), P(0x100)), null);
        }));
    test(`findStringLoadSites (JS walk) rejects an intervening ${name}`, () =>
        withScratch([adrpSamePage(9), word, addImm(9, 9, STR_OFF)], () => {
            assert.deepEqual(addrs(findStringLoadSites(fakeModule, P(STR_OFF))), [0x100]);
        }));
}

test("findOpeningAdrp still accepts non-writers between ADRP and ADD (str/cmp/ldr other/b.cond/nop)", () =>
    withScratch([adrpSamePage(9), STR_X9_X5, CMP_X9, LDR_X2_X5, BEQ_FWD, NOP, addImm(9, 9, STR_OFF)], () => {
        assert.equal((findOpeningAdrp(P(SCRATCH + 24), 9, P(0), P(0x100)) as any).addr, BASE + SCRATCH);
        assert.deepEqual(addrs(findStringLoadSites(fakeModule, P(STR_OFF))), [0x100, SCRATCH]);
    }));

test("findStringLoadSitesAsync rejects an intervening writer but keeps the harmless shape", async () => {
    await withScratch([adrpSamePage(9), MOV_X9_X5, addImm(9, 9, STR_OFF)], async () => {
        const [s] = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF)]);
        assert.deepEqual(addrs(s), [0x100]);
    });
    await withScratch([adrpSamePage(9), STR_X9_X5, CMP_X9, addImm(9, 9, STR_OFF)], async () => {
        const [s] = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF)]);
        assert.deepEqual(addrs(s), [0x100, SCRATCH]);
    });
});

// ---- S3: linker-relaxed ADR sites -----------------------------------------------

test("adrTarget resolves a negative, unaligned PC-relative byte offset", () => {
    assert.equal((adrTarget(P(0x160), adr(5, BASE + 0x160, BASE + HS_OFF)) as any).addr, BASE + HS_OFF);
});

test("findStringLoadSites (JS walk) finds the ADR site and rejects the off-target ADR", () => {
    assert.deepEqual(addrs(findStringLoadSites(fakeModule, P(HS_OFF))), [0x160]);
});

test("findStringLoadSitesAsync finds the ADR site, agreeing with the JS walk", async () => {
    const sites = await findStringLoadSitesAsync(fakeModule, [P(STR_OFF), P(EXP_OFF), P(HS_OFF)]);
    assert.deepEqual(addrs(sites[0]), [0x100]);
    assert.deepEqual(addrs(sites[1]), [0x120, 0x130]);
    assert.deepEqual(addrs(sites[2]), [0x160]);
});

test("the ADR pass also works in tiny chunks (straddling top bytes, per-chunk yields)", async () => {
    let yields = 0;
    const sites = await findStringLoadSitesAsync(fakeModule, [P(HS_OFF)], 0x6, async () => { yields++; });
    assert.deepEqual(addrs(sites[0]), [0x160]);
    assert.ok(yields > 0);
});

test("end-to-end: ADR site -> first BL resolves the callee", () => {
    const [site] = findStringLoadSites(fakeModule, P(HS_OFF));
    const c = firstCallTargetForward(site, modEnd as any, modStart as any, modEnd as any);
    assert.equal((c as unknown as BufPtr).addr, CALL_TARGET);
});

test("adrScanWindows clips each code range to ±1 MB of the targets and merges overlaps", () => {
    const A = (n: number) => new BufPtr(n) as unknown as NativePointer;
    const code = [{ base: A(0x1000000), size: 0x1000000 }];      // 16 MB of code
    const w = adrScanWindows(code, [A(0x1800000), A(0x1880000), A(0x1000010), A(0x3000000)]);
    const MB = ADR_REACH_BYTES;
    assert.deepEqual(w.map((r) => [(r.base as any).addr, r.size]), [
        [0x1000000, 0x1000010 + MB + 8 - 0x1000000],           // clamped to the range start
        [0x1800000 - MB, (0x1880000 + MB + 8) - (0x1800000 - MB)], // two windows merged
    ]);                                                          // 0x3000000 is out of reach
    assert.deepEqual(adrScanWindows(code, []), []);
});

// ---- outlined arg-setup stubs and epilogue tail calls (Flutter's libflutter.so) ----
//
// Words below are copied from a release libflutter.so (BoringSSL c7eb007f),
// whose ssl_log_secret sits at 0x77d778: CLIENT_HANDSHAKE_TRAFFIC_SECRET's site
// does `bl 0xaac40c` (mov x0, x20; mov x2, x21; ret) then `bl ssl_log_secret`;
// three labels tail-call it after the epilogue reloads x30.

const HIGH = 0x1000;                      // code area outside the scanned ranges
const SITE_AT = HIGH;                     // the label load site
const STUB_AT = HIGH + 0x800;             // tiny arg-setup stub
const LONG_STUB_AT = HIGH + 0x840;        // 5 moves + ret: too long to be skipped
const SSL_LOG_AT = HIGH + 0x900;          // stands in for ssl_log_secret
const MOV_X0_X20 = 0xaa1403e0, MOV_X2_X21 = 0xaa1503e2, MOV_W2_W3 = 0x2a0303e2;
const LDR_X30_POST = 0xf84207fe;          // ldr x30, [sp], #0x20
const LDP_X30_X21_POST = 0xa8c257fe;      // ldp x30, x21, [sp], #0x20
const SSL_LOG_PROLOGUE = [0xd101c3ff, 0xa9045ffe, 0x940cb475, 0xf9403408]; // sub sp; stp x30, x23; bl; ldr
const STP_X22_X21 = 0xa90557f6;           // stp x22, x21, [sp, #0x50]

function withWordsAt(regions: [number, number[]][], body: () => void): void {
    for (const [off, words] of regions) words.forEach((w, k) => writeU32(off + 4 * k, w));
    try { body(); } finally {
        for (const [off, words] of regions) words.forEach((_w, k) => writeU32(off + 4 * k, 0));
    }
}
const flutterCode = (site: number[]): [number, number[]][] => [
    [SITE_AT, site],
    [STUB_AT, [MOV_X0_X20, MOV_X2_X21, RET]],
    [LONG_STUB_AT, [MOV_X0_X20, MOV_X2_X21, MOV_X0_X20, MOV_X2_X21, MOV_X0_X20, RET]],
    [SSL_LOG_AT, SSL_LOG_PROLOGUE],
];
const walkFrom = (off: number) => {
    const c = firstCallTargetForward(P(off), modEnd as any, modStart as any, modEnd as any);
    return c === null ? null : (c as unknown as BufPtr).addr - BASE;
};
const at = (off: number) => BASE + off;

test("stub shapes: register moves and stp/str saves before a RET, bounded", () => {
    assert.ok(isRegisterMove(MOV_X0_X20) && isRegisterMove(MOV_W2_W3));
    assert.ok(isRegisterSave(STP_X22_X21) && !isRegisterSave(0xa9bf7bfd)); // stp x29, x30, [sp, #-16]! writes back
    assert.deepEqual(outlinedStubBody([MOV_X0_X20, MOV_X2_X21, RET], ARG_SETUP_STUB), [MOV_X0_X20, MOV_X2_X21]);
    assert.deepEqual(outlinedStubBody([RET], ARG_SETUP_STUB), []);
    assert.equal(outlinedStubBody([STP_X22_X21, RET], ARG_SETUP_STUB), null);
    assert.deepEqual(outlinedStubBody([STP_X22_X21, RET], REGISTER_SAVE_STUB), [STP_X22_X21]);
    assert.equal(outlinedStubBody([...new Array(5).fill(MOV_X0_X20), RET], ARG_SETUP_STUB), null);
    assert.equal(outlinedStubBody([...new Array(8).fill(MOV_X0_X20), RET], REGISTER_SAVE_STUB), null);
    assert.equal(outlinedStubBody([MOV_X0_X20, MOV_X2_X21], ARG_SETUP_STUB), null);   // no RET
    assert.equal(outlinedStubBody([0x91002001, RET], REGISTER_SAVE_STUB), null);      // add x1, x0, #8
});

test("firstCallTargetForward skips a BL into an arg-setup stub and resolves the real call", () =>
    withWordsAt(flutterCode([NOP, bl(at(SITE_AT + 4), at(STUB_AT)), bl(at(SITE_AT + 8), at(SSL_LOG_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), SSL_LOG_AT);
    }));

test("firstCallTargetForward still votes for a BL whose callee is too long to be a stub", () =>
    withWordsAt(flutterCode([NOP, bl(at(SITE_AT + 4), at(LONG_STUB_AT)), bl(at(SITE_AT + 8), at(SSL_LOG_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), LONG_STUB_AT);
    }));

for (const [name, epilogue] of [["ldr x30, [sp], #0x20", LDR_X30_POST], ["ldp x30, x21, [sp], #0x20", LDP_X30_X21_POST]] as const) {
    test(`firstCallTargetForward votes for a tail call B after \`${name}\``, () =>
        withWordsAt(flutterCode([NOP, NOP, epilogue, B(at(SITE_AT + 12), at(SSL_LOG_AT))]), () => {
            assert.equal(walkFrom(SITE_AT), SSL_LOG_AT);
        }));
}

test("a skipped stub BL (which writes x30) does not make a later B a tail call", () =>
    withWordsAt(flutterCode([NOP, bl(at(SITE_AT + 4), at(STUB_AT)), B(at(SITE_AT + 8), at(SSL_LOG_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), null);
    }));

test("a tail call B out of the module is not a vote", () =>
    withWordsAt(flutterCode([NOP, LDR_X30_POST, B(at(SITE_AT + 8), at(SIZE + 0x100))]), () => {
        assert.equal(walkFrom(SITE_AT), null);
    }));

test("all three libflutter.so site shapes resolve the same ssl_log_secret", () => {
    const shapes = [
        [NOP, NOP, bl(at(SITE_AT + 8), at(SSL_LOG_AT))],                                    // plain bl
        [NOP, bl(at(SITE_AT + 4), at(STUB_AT)), bl(at(SITE_AT + 8), at(SSL_LOG_AT))],         // stub, then bl
        [NOP, LDP_X30_X21_POST, B(at(SITE_AT + 8), at(SSL_LOG_AT))],                         // epilogue + b
    ];
    for (const site of shapes) withWordsAt(flutterCode(site), () => assert.equal(walkFrom(SITE_AT), SSL_LOG_AT));
});

// ---- tail-call B votes need a real epilogue and a function-entry target ----

const LOOP_AT = HIGH + 0x700;              // in-function label: no prologue word there
const MOV_X30_X5 = 0xaa0503fe;             // mov x30, x5 (x30 as a scratch GPR)
const walkWith = (off: number, functions: any) => {
    const c = firstCallTargetForward(P(off), modEnd as any, modStart as any, modEnd as any, functions);
    return c === null ? null : (c as unknown as BufPtr).addr - BASE;
};

test("isEpilogueLinkReload accepts only sp-based x30 reloads", () => {
    for (const w of [LDR_X30_POST, LDP_X30_X21_POST, 0xa8c17bfd /* ldp x29, x30, [sp], #0x10 */,
        0xa9417bfd /* ldp x29, x30, [sp, #0x10] */, 0xf94007fe /* ldr x30, [sp, #8] */,
        0xf8410ffe /* ldr x30, [sp, #0x10]! */]) assert.ok(isEpilogueLinkReload(w), w.toString(16));
    for (const w of [MOV_X30_X5, 0xf94004be /* ldr x30, [x5, #8] */, 0x9100041e /* add x30, x0, #1 */,
        0xa8c17ba1 /* ldp x1, x30, [x29], #0x10 */, 0xa8c157e1 /* ldp x1, x21, [sp], #0x10 */])
        assert.ok(!isEpilogueLinkReload(w), w.toString(16));
});

test("a scratch write of x30 does not arm the tail-call vote (in-function loop B)", () =>
    withWordsAt(flutterCode([NOP, MOV_X30_X5, B(at(SITE_AT + 8), at(SSL_LOG_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), null);
    }));

test("an x30 write after the epilogue reload disarms the tail-call vote", () =>
    withWordsAt(flutterCode([NOP, LDR_X30_POST, MOV_X30_X5, B(at(SITE_AT + 12), at(SSL_LOG_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), null);
    }));

test("without bounds, an epilogue B to a non-prologue label is not a vote", () =>
    withWordsAt(flutterCode([NOP, LDR_X30_POST, B(at(SITE_AT + 8), at(LOOP_AT))]), () => {
        assert.equal(walkFrom(SITE_AT), null);
    }));

test("with function bounds, a tail call must leave the site's function", () =>
    withWordsAt(flutterCode([NOP, LDR_X30_POST, B(at(SITE_AT + 8), at(SSL_LOG_AT))]), () => {
        const inside = { bounds: () => ({ start: P(SITE_AT - 0x10), end: P(SSL_LOG_AT + 0x10) }) };
        const outside = { bounds: () => ({ start: P(SITE_AT - 0x10), end: P(SITE_AT + 0x40) }) };
        assert.equal(walkWith(SITE_AT, inside), null);           // prologue-looking but in-function
        assert.equal(walkWith(SITE_AT, outside), SSL_LOG_AT);
        assert.equal(walkWith(SITE_AT, { bounds: () => null }), SSL_LOG_AT); // unknown: prologue check
    }));

test("with function bounds, an out-of-function tail call needs no prologue word", () =>
    withWordsAt(flutterCode([NOP, LDR_X30_POST, B(at(SITE_AT + 8), at(LOOP_AT))]), () => {
        const fn = { bounds: () => ({ start: P(SITE_AT - 0x10), end: P(SITE_AT + 0x40) }) };
        assert.equal(walkWith(SITE_AT, fn), LOOP_AT);
    }));

// ---- Mach-O anchor passes: string sections, data, then r-x only for what is still missing ----

const MACHO_CSTRING_OFF = 0x1c00, MACHO_OSLOG_OFF = 0x1c80, MACHO_TEXT_OFF = 0x1c40;
const MACHO_HEADER = (() => {
    // mach_header_64 (MH_MAGIC_64, ncmds 1, sizeofcmds 8) + one inert 8-byte load command.
    const h = new Uint8Array(40);
    const dv = new DataView(h.buffer);
    dv.setUint32(0, 0xfeedfacf, true);
    dv.setUint32(16, 1, true);
    dv.setUint32(20, 8, true);
    dv.setUint32(36, 8, true);
    return h;
})();

/** Module base that reads as a Mach-O header (everything else reads from `buf`). */
class MachOBufPtr extends BufPtr {
    add(n: number | BufPtr) { return new MachOBufPtr(super.add(n).addr); }
    readByteArray(length: number) {
        const off = this.addr - BASE;
        if (off + length > MACHO_HEADER.length) throw new Error("read out of range");
        return MACHO_HEADER.slice(off, off + length).buffer;
    }
}

function fakeMachOModule(onCodeRanges: () => void): Module {
    return {
        base: new MachOBufPtr(BASE),
        size: SIZE,
        name: "libfake_anchor_passes.dylib",
        enumerateSections: () => [
            { id: "1.__TEXT.__cstring", name: "__cstring", address: new BufPtr(BASE + MACHO_CSTRING_OFF), size: 0x40 },
        ],
        enumerateRanges(prot: string) {
            if (prot === "r-x") {
                onCodeRanges();
                return [{ base: new BufPtr(BASE + MACHO_TEXT_OFF), size: 0x80, protection: prot }];
            }
            return [{ base: new BufPtr(DATA_RANGE.base), size: DATA_RANGE.size, protection: prot }];
        },
    } as unknown as Module;
}

test("Mach-O anchors: __cstring first; an anchor in another __TEXT section is found by the lazy r-x pass", async () => {
    writeString(MACHO_CSTRING_OFF, "CSTRING_ANCHOR");
    writeString(MACHO_OSLOG_OFF, "OSLOG_ANCHOR");          // e.g. __oslogstring: r-x only
    let codePasses = 0;
    const mod = fakeMachOModule(() => { codePasses++; });
    const onlySection = await findAnchorStringsAsync(mod, ["CSTRING_ANCHOR\u0000"], 0x10, async () => { });
    assert.deepEqual(onlySection.map((p) => p === null ? null : (p as unknown as BufPtr).addr - BASE), [MACHO_CSTRING_OFF]);
    assert.equal(codePasses, 0);                              // nothing missing: no r-x pass
    const both = await findAnchorStringsAsync(mod, ["CSTRING_ANCHOR\u0000", "OSLOG_ANCHOR\u0000"], 0x10, async () => { });
    assert.deepEqual(both.map((p) => p === null ? null : (p as unknown as BufPtr).addr - BASE),
        [MACHO_CSTRING_OFF, MACHO_OSLOG_OFF]);
    assert.equal(codePasses, 1);
});
