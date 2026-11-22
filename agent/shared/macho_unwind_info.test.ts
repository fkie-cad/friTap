// Run: npm run test:agent
//
// __unwind_info parsing (regular + compressed pages, sentinel), merged-function
// splitting, Mach-O header/UUID parsing and the ELF/Mach-O dispatch, over a
// synthetic in-memory arm64 Mach-O image.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { parseUnwindInfoStarts, splitMergedRange, UnwindFunctionTable, MachOUnwindFunctionBounds } from "./macho_unwind_info.js";
import { isMachO64, isMachOModule, moduleMachOUuid, parseMachOLoadCommands, machOSectionRange } from "./macho_header.js";
import { ehFrameTableFor } from "./eh_frame.js";
import { identifyModule } from "./learned_module_cache.js";

const NOP = 0xd503201f;
const RET = 0xd65f03c0;
const STP_PRE = 0xa9bf7bfd;     // stp x29, x30, [sp, #-16]!
const CBZ_X0_8 = 0xb4000040;    // cbz x0, +8
const BR_X16 = 0xd61f0200;      // br x16
const BTI_J = 0xd503249f;
const BRK = 0xd4200020;         // brk #1
const MOV_W0_1 = 0x52800020;    // mov w0, #1
const B_PLUS_8 = 0x14000002;    // b +8

// ---- builders ------------------------------------------------------------------

type Page = { kind: "regular"; starts: number[] } | { kind: "compressed"; starts: number[] };

/** __unwind_info v1 with one first-level entry per page plus a sentinel at `end`. */
function buildUnwindInfo(pages: Page[], end: number): Uint8Array {
    const indexOffset = 28, indexCount = pages.length + 1;
    let at = indexOffset + indexCount * 12;
    const out = new Uint8Array(at + pages.reduce((n, p) => n + 12 + p.starts.length * 8, 0));
    const dv = new DataView(out.buffer);
    dv.setUint32(0, 1, true);
    dv.setUint32(20, indexOffset, true);
    dv.setUint32(24, indexCount, true);
    pages.forEach((p, i) => {
        const pageBase = Math.min(...p.starts);
        dv.setUint32(indexOffset + i * 12, pageBase, true);
        dv.setUint32(indexOffset + i * 12 + 4, at, true);
        if (p.kind === "regular") {
            dv.setUint32(at, 2, true); dv.setUint16(at + 4, 8, true); dv.setUint16(at + 6, p.starts.length, true);
            p.starts.forEach((s, k) => { dv.setUint32(at + 8 + k * 8, s, true); dv.setUint32(at + 12 + k * 8, 0x04000000, true); });
            at += 8 + p.starts.length * 8;
        } else {
            dv.setUint32(at, 3, true); dv.setUint16(at + 4, 12, true); dv.setUint16(at + 6, p.starts.length, true);
            p.starts.forEach((s, k) => dv.setUint32(at + 12 + k * 4, ((k & 3) << 24) | (s - pageBase), true));
            at += 12 + p.starts.length * 4;
        }
    });
    dv.setUint32(indexOffset + pages.length * 12, end, true);
    return out;
}

const TEXT_OFF = 0x1000, TEXT_SIZE = 0x1000, UNWIND_OFF = 0x3000, IMAGE_SIZE = 0x4000;
const VMADDR = 0x100000000;
const UUID = [0x4c, 0x4c, 0x44, 0xad, 0x55, 0x55, 0x31, 0x44, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18];
const UUID_HEX = "4c4c44ad55553144a1b2c3d4e5f60718";

function putName(img: Uint8Array, at: number, name: string): void {
    [...name].forEach((c, i) => { img[at + i] = c.charCodeAt(0); });
}

/** mach header + LC_SEGMENT_64 __TEXT (__text, __unwind_info) + LC_UUID; code words at TEXT_OFF. */
function machOImage(code: Map<number, number>, unwind: Uint8Array): Uint8Array {
    const img = new Uint8Array(IMAGE_SIZE);
    const dv = new DataView(img.buffer);
    const segSize = 72 + 2 * 80;
    dv.setUint32(0, 0xfeedfacf, true); dv.setUint32(4, 0x0100000c, true); dv.setUint32(12, 6, true);
    dv.setUint32(16, 2, true); dv.setUint32(20, segSize + 24, true);
    let at = 32;
    dv.setUint32(at, 0x19, true); dv.setUint32(at + 4, segSize, true); putName(img, at + 8, "__TEXT");
    dv.setBigUint64(at + 24, BigInt(VMADDR), true); dv.setBigUint64(at + 32, BigInt(IMAGE_SIZE), true);
    dv.setUint32(at + 64, 2, true);
    const sections: [string, number, number][] = [["__text", TEXT_OFF, TEXT_SIZE], ["__unwind_info", UNWIND_OFF, unwind.length]];
    sections.forEach(([name, off, size], s) => {
        const sec = at + 72 + s * 80;
        putName(img, sec, name); putName(img, sec + 16, "__TEXT");
        dv.setBigUint64(sec + 32, BigInt(VMADDR + off), true); dv.setBigUint64(sec + 40, BigInt(size), true);
    });
    at += segSize;
    dv.setUint32(at, 0x1b, true); dv.setUint32(at + 4, 24, true); img.set(UUID, at + 8);
    for (let a = TEXT_OFF; a < TEXT_OFF + TEXT_SIZE; a += 4) dv.setUint32(a, code.get(a) ?? NOP, true);
    img.set(unwind, UNWIND_OFF);
    return img;
}

/** NativePointer stand-in over `img` mapped at `base`. */
function memPtr(img: Uint8Array, base: number, n: number): NativePointer {
    const value = (o: unknown) => typeof o === "number" ? o : (o as { n: number }).n;
    const check = (len: number) => { if (n < base || n + len > base + img.length) throw new Error("unmapped"); };
    return {
        n, toString: () => "0x" + n.toString(16), toUInt32: () => n >>> 0,
        compare: (o: unknown) => Math.sign(n - value(o)), equals: (o: unknown) => n === value(o),
        add: (o: unknown) => memPtr(img, base, n + value(o)), sub: (o: unknown) => memPtr(img, base, n - value(o)),
        readU32: () => { check(4); return new DataView(img.buffer).getUint32(n - base, true); },
        readByteArray: (len: number) => { check(len); return img.slice(n - base, n - base + len).buffer; },
    } as unknown as NativePointer;
}

const BASE = 0x10000;
function machOModule(img: Uint8Array, name: string, extra: object = {}): Module {
    return { name, base: memPtr(img, BASE, BASE), size: img.length, enumerateRanges: () => [], ...extra } as unknown as Module;
}

// 0x1000 fn A: stp | nop | ret   0x100c merged fn B: stp | nop | cbz ->0x101c | ret | 0x101c stp (inner label) | nop | ret
// then brk padding up to the next table start 0x1040
const MERGED_CODE = new Map<number, number>([
    [0x1000, STP_PRE], [0x1008, RET],
    [0x100c, STP_PRE], [0x1014, CBZ_X0_8], [0x1018, RET], [0x101c, STP_PRE], [0x1024, RET],
    ...Array.from({ length: 6 }, (_, k): [number, number] => [0x1028 + k * 4, BRK]),
]);
const PAGES: Page[] = [
    { kind: "regular", starts: [0x1000, 0x1040, 0x1080] },
    { kind: "compressed", starts: [0x1100, 0x1180, 0x1180] },
];

// ---- parsing ---------------------------------------------------------------------

test("regular and compressed pages yield sorted unique starts; the sentinel bounds the last", () => {
    const parsed = parseUnwindInfoStarts(buildUnwindInfo(PAGES, 0x1200))!;
    assert.deepEqual([Array.from(parsed.starts), parsed.end], [[0x1000, 0x1040, 0x1080, 0x1100, 0x1180], 0x1200]);
});

test("compressed offsets are relative to their first-level entry, across several pages", () => {
    const pages: Page[] = [{ kind: "compressed", starts: [0x2000, 0x2010] }, { kind: "compressed", starts: [0x3000, 0x3ff0] }];
    assert.deepEqual(Array.from(parseUnwindInfoStarts(buildUnwindInfo(pages, 0x4000))!.starts), [0x2000, 0x2010, 0x3000, 0x3ff0]);
});

test("out-of-order pages are sorted and deduplicated", () => {
    const pages: Page[] = [{ kind: "regular", starts: [0x3000, 0x3010] }, { kind: "regular", starts: [0x2000, 0x3000] }];
    assert.deepEqual(Array.from(parseUnwindInfoStarts(buildUnwindInfo(pages, 0x4000))!.starts), [0x2000, 0x3000, 0x3010]);
});

test("a wrong version or a truncated section parses as null", () => {
    const bad = buildUnwindInfo(PAGES, 0x1200);
    new DataView(bad.buffer).setUint32(0, 2, true);
    assert.equal(parseUnwindInfoStarts(bad), null);
    assert.equal(parseUnwindInfoStarts(buildUnwindInfo(PAGES, 0x1200).subarray(0, 40)), null);
    assert.equal(parseUnwindInfoStarts(new Uint8Array(8)), null);
});

// ---- merged-function split -------------------------------------------------------

test("a prologue after RET splits a merged range; a branch-targeted one does not", () => {
    const words = Uint32Array.from({ length: 16 }, (_, k) => MERGED_CODE.get(0x1000 + k * 4) ?? NOP);
    assert.deepEqual(Array.from(splitMergedRange(words, 0x1000)), [0x1000, 0x100c]);
});

test("a frameless leaf after RET splits only when nothing can branch to it", () => {
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([STP_PRE, RET, MOV_W0_1, RET]), 0x1000)), [0x1000, 0x1008]);
    // stp | cbz ->0x100c | b ->0x1010 | ret | mov (reached by the b: an inner block) | ret
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([STP_PRE, CBZ_X0_8, B_PLUS_8, RET, MOV_W0_1, RET]), 0x1000)), [0x1000]);
    // a BR in the range may reach it through a jump table
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([BR_X16, RET, MOV_W0_1, RET]), 0x1000)), [0x1000]);
    // after BRK padding it is an entry even next to a BR
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([BR_X16, BRK, MOV_W0_1, RET]), 0x1000)), [0x1000, 0x1008]);
});

test("frame setup after a BL (noreturn call) starts a function; other prologue words there do not", () => {
    const BL = 0x94000010, STP_FP_LR_OFFSET = 0xa9017bfd;   // stp x29, x30, [sp, #16]
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([STP_PRE, BL, STP_PRE, RET]), 0x1000)), [0x1000, 0x1008]);
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([STP_PRE, BL, STP_FP_LR_OFFSET, RET]), 0x1000)), [0x1000]);
});

test("a `bti j` jump-table target after BR is not a function entry", () => {
    assert.deepEqual(Array.from(splitMergedRange(Uint32Array.from([STP_PRE, BR_X16, BTI_J, NOP]), 0x1000)), [0x1000]);
});

test("UnwindFunctionTable bounds: inner function, outer function, sentinel and text end", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    const table = new UnwindFunctionTable(parseUnwindInfoStarts(img.subarray(UNWIND_OFF))!, TEXT_OFF, TEXT_OFF + TEXT_SIZE,
        (from, len) => img.subarray(from, from + len));
    assert.deepEqual(table.boundsAt(0x1004), { start: 0x1000, end: 0x100c });
    assert.deepEqual(table.boundsAt(0x1010), { start: 0x100c, end: 0x1040 });
    assert.deepEqual(table.boundsAt(0x1020), { start: 0x100c, end: 0x1040 });   // inner label stays in B
    assert.deepEqual(table.boundsAt(0x1044), { start: 0x1040, end: 0x1080 });
    assert.deepEqual(table.boundsAt(0x11f0), { start: 0x1180, end: 0x1200 });
    assert.equal(table.boundsAt(0x1200), null);
    assert.equal(table.boundsAt(0xffc), null);
});

// ---- header, UUID, dispatch ------------------------------------------------------

test("load commands: UUID as lowercase hex, sections relative to __TEXT vmaddr", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    const read = (off: number, len: number) => off + len <= img.length ? img.subarray(off, off + len) : null;
    assert.equal(isMachO64(read), true);
    const parsed = parseMachOLoadCommands(read)!;
    assert.equal(parsed.uuid, UUID_HEX);
    assert.deepEqual(parsed.sections.map((s) => [s.sectname, s.offset]), [["__text", TEXT_OFF], ["__unwind_info", UNWIND_OFF]]);
    assert.equal(moduleMachOUuid(machOModule(img, "uuid")), UUID_HEX);
});

test("an ELF header is not Mach-O and has no UUID", () => {
    const elf = new Uint8Array(64); elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    const read = (off: number, len: number) => elf.subarray(off, off + len);
    assert.equal(isMachO64(read), false);
    assert.equal(parseMachOLoadCommands(read), null);
});

test("machOSectionRange prefers Module.enumerateSections and falls back to load commands", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    const viaHeader = machOSectionRange(machOModule(img, "a"), "__TEXT", "__unwind_info")!;
    assert.equal((viaHeader.base as unknown as { n: number }).n, BASE + UNWIND_OFF);
    const sections = [{ id: "3.__TEXT.__cstring", name: "__cstring", address: memPtr(img, BASE, BASE + 0x2000), size: 0x40 }];
    const viaFrida = machOSectionRange(machOModule(img, "b", { enumerateSections: () => sections }), "__TEXT", "__cstring")!;
    assert.equal(viaFrida.size, 0x40);
});

test("Mach-O image info is parsed and enumerated once per mapping", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    let enumerations = 0;
    const mod = machOModule(img, "cached", { enumerateSections: () => { enumerations++; return []; } });
    assert.equal(isMachOModule(mod), true);
    assert.equal(machOSectionRange(mod, "__TEXT", "__cstring"), null);
    assert.equal(machOSectionRange(mod, "__TEXT", "__text"), null);
    assert.equal(enumerations, 1);
});

test("ehFrameTableFor dispatches on the header magic: Mach-O gets __unwind_info bounds", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    const table = ehFrameTableFor(machOModule(img, "Electron Framework"));
    assert.ok(table instanceof MachOUnwindFunctionBounds);
    const fn = table!.bounds(memPtr(img, BASE, BASE + 0x1010))!;
    assert.deepEqual([fn.start.toString(), fn.end?.toString()], ["0x1100c", "0x11040"]);
    assert.equal(table!.bounds(memPtr(img, BASE, BASE + 0x2000)), null);   // past __text
    assert.equal(table!.bounds(memPtr(img, BASE, BASE + 0x100001010)), null);   // 4 GiB alias of a hit
});

test("identifyModule falls back to the Mach-O UUID when there is no ELF build id", () => {
    const img = machOImage(MERGED_CODE, buildUnwindInfo(PAGES, 0x1200));
    assert.equal(identifyModule(machOModule(img, "Google Chrome Framework"))?.buildId, UUID_HEX);
});
