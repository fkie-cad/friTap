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
    scanRangesChunked, patternByteLength, pointerScanPattern, LOAD_SITE_WINDOW,
    adrTarget, adrScanWindows, ADR_REACH_BYTES,
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
