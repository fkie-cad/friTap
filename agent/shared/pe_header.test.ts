// Run: npm run test:agent
//
// parsePeIdentity over synthetic PE32/PE32+ mapped images (RSDS identity, the
// TimeDateStamp fallback, fail-closed cases) and over the real headers of
// Firefox 160.0.1 win64 nss3.dll; identifyModule falls back to it.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { parsePeIdentity } from "./pe_header.js";
import type { ModuleByteReader } from "./module_mapping.js";
import { identifyModule } from "./learned_module_cache.js";
import * as nss3 from "./__fixtures__/pe_nss3_win64_160.js";

// GUID {12345678-9ABC-DEF0-1122-334455667788}, as stored in RSDS (Data1..Data3 little-endian).
const GUID_BYTES = [0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const RSDS_IDENTITY = "123456789abcdef01122334455667788" + "00000001";
const TIMESTAMP = 0x6afaff77;
const IMAGE_SIZE = 0x1000;
const NT = 0x80;
const DEBUG_DIR_RVA = 0x400;
const CODEVIEW_RVA = 0x500;

interface FakePeOptions {
    pe32Plus?: boolean;
    timestamp?: number;
    debugEntries?: number;          // 0: empty debug data directory
    codeViewType?: number;
    codeViewRva?: number;
    signature?: string;
    sizeOfData?: number;
    dataDirectoryCount?: number;
}

function writeRsds(image: Uint8Array, at: number, signature: string): void {
    image.set([...signature].map((c) => c.charCodeAt(0)), at);
    image.set(GUID_BYTES, at + 4);
    new DataView(image.buffer).setUint32(at + 20, 1, true);
    image.set([...("x.pdb\0")].map((c) => c.charCodeAt(0)), at + 24);
}

/** MZ + PE headers at 0x80, debug directory at 0x400, CodeView record at 0x500. */
function fakePe({ pe32Plus = true, timestamp = TIMESTAMP, debugEntries = 1, codeViewType = 2,
                  codeViewRva = CODEVIEW_RVA, signature = "RSDS", sizeOfData = 30,
                  dataDirectoryCount = 16 }: FakePeOptions = {}): Uint8Array {
    const image = new Uint8Array(IMAGE_SIZE);
    const dv = new DataView(image.buffer);
    dv.setUint16(0, 0x5a4d, true);
    dv.setUint32(0x3c, NT, true);
    dv.setUint32(NT, 0x00004550, true);
    dv.setUint32(NT + 8, timestamp, true);
    const directories = pe32Plus ? 112 : 96;
    dv.setUint16(NT + 20, directories + 16 * 8, true);
    const opt = NT + 24;
    dv.setUint16(opt, pe32Plus ? 0x20b : 0x10b, true);
    dv.setUint32(opt + 56, IMAGE_SIZE, true);
    dv.setUint32(opt + directories - 4, dataDirectoryCount, true);
    dv.setUint32(opt + directories + 6 * 8, debugEntries === 0 ? 0 : DEBUG_DIR_RVA, true);
    dv.setUint32(opt + directories + 6 * 8 + 4, debugEntries * 28, true);
    for (let i = 0; i < debugEntries; i++) {
        const entry = DEBUG_DIR_RVA + i * 28;
        const last = i === debugEntries - 1;
        dv.setUint32(entry + 12, last ? codeViewType : 13, true);   // earlier entries: POGO
        dv.setUint32(entry + 16, sizeOfData, true);
        dv.setUint32(entry + 20, last ? codeViewRva : 0x600, true);
        dv.setUint32(entry + 24, 0x9999, true);                      // file offset: must be ignored
    }
    writeRsds(image, CODEVIEW_RVA, signature);
    return image;
}

function reader(image: Uint8Array, unreadableFrom = Infinity): ModuleByteReader {
    return (offset, length) => {
        if (offset + length > unreadableFrom) return null;
        if (offset < 0 || offset + length > image.length) return null;
        return image.slice(offset, offset + length);
    };
}

test("PE32+: RSDS GUID in canonical order + age as %08x", () => {
    assert.equal(parsePeIdentity(reader(fakePe())), RSDS_IDENTITY);
});

test("PE32: same identity through the PE32 data directory offset", () => {
    assert.equal(parsePeIdentity(reader(fakePe({ pe32Plus: false }))), RSDS_IDENTITY);
});

test("the first CodeView entry is found after other debug entries", () => {
    assert.equal(parsePeIdentity(reader(fakePe({ debugEntries: 3 }))), RSDS_IDENTITY);
});

test("no RSDS record: TimeDateStamp + SizeOfImage fallback", () => {
    const fallback = "6afaff77" + "00001000";
    assert.equal(parsePeIdentity(reader(fakePe({ debugEntries: 0 }))), fallback);
    assert.equal(parsePeIdentity(reader(fakePe({ dataDirectoryCount: 6 }))), fallback);
    assert.equal(parsePeIdentity(reader(fakePe({ codeViewType: 13 }))), fallback);
    assert.equal(parsePeIdentity(reader(fakePe({ signature: "NB10" }))), fallback);
    assert.equal(parsePeIdentity(reader(fakePe({ codeViewRva: 0 }))), fallback);
});

test("fallback with an unset timestamp fails closed", () => {
    assert.equal(parsePeIdentity(reader(fakePe({ debugEntries: 0, timestamp: 0 }))), null);
    assert.equal(parsePeIdentity(reader(fakePe({ debugEntries: 0, timestamp: 0xffffffff }))), null);
});

test("malformed CodeView entry: out-of-bounds RVA or short record yields null", () => {
    assert.equal(parsePeIdentity(reader(fakePe({ codeViewRva: IMAGE_SIZE - 8 }))), null);
    assert.equal(parsePeIdentity(reader(fakePe({ codeViewRva: 0xfffffff0 }))), null);
    assert.equal(parsePeIdentity(reader(fakePe({ sizeOfData: 20 }))), null);
});

test("truncated or unreadable images yield null without throwing", () => {
    assert.equal(parsePeIdentity(reader(fakePe(), CODEVIEW_RVA + 8)), null);
    assert.equal(parsePeIdentity(reader(fakePe(), DEBUG_DIR_RVA + 4)), null);
    assert.equal(parsePeIdentity(reader(fakePe(), NT + 30)), null);
    assert.equal(parsePeIdentity(reader(fakePe(), 0x10)), null);
    assert.equal(parsePeIdentity(() => { throw new Error("access violation"); }), null);
});

test("non-PE images yield null: zeros, ELF, Mach-O, bad e_lfanew", () => {
    assert.equal(parsePeIdentity(reader(new Uint8Array(IMAGE_SIZE))), null);
    const elf = new Uint8Array(IMAGE_SIZE);
    elf.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    assert.equal(parsePeIdentity(reader(elf)), null);
    const macho = new Uint8Array(IMAGE_SIZE);
    new DataView(macho.buffer).setUint32(0, 0xfeedfacf, true);
    assert.equal(parsePeIdentity(reader(macho)), null);
    const farNt = fakePe();
    new DataView(farNt.buffer).setUint32(0x3c, 0x20000, true);
    assert.equal(parsePeIdentity(reader(farNt)), null);
});

// ---- real bytes: Firefox 160.0.1 win64 nss3.dll ---------------------------------

function nss3Reader(): ModuleByteReader {
    const segments: Array<[number, Uint8Array]> = [[0, nss3.HEADERS], [nss3.DEBUG_SEGMENT_RVA, nss3.DEBUG_SEGMENT]];
    return (offset, length) => {
        for (const [at, bytes] of segments) {
            if (offset >= at && offset + length <= at + bytes.length) return bytes.slice(offset - at, offset - at + length);
        }
        return null;
    };
}

test("real nss3.dll (Firefox 160.0.1 win64): RSDS identity matches pefile", () => {
    assert.equal(parsePeIdentity(nss3Reader()), nss3.EXPECTED_IDENTITY);
});

// ---- identifyModule chain --------------------------------------------------------

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

test("identifyModule falls back to the PE identity when there is no ELF or Mach-O id", () => {
    const base = 0x7ff600000000;
    const img = fakePe();
    const mod = { name: "nss3.dll", base: memPtr(img, base, base), size: img.length,
                  enumerateRanges: () => [], enumerateSections: () => [] } as unknown as Module;
    assert.equal(identifyModule(mod)?.buildId, RSDS_IDENTITY);
});
