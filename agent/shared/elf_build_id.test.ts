// Run: npm run test:agent
//
// parseGnuBuildId over a synthetic ELF64/ELF32 little-endian image: the note is
// found through PT_NOTE, and anything malformed or unreadable reads as null.

import { test } from "node:test";
import assert from "node:assert/strict";
import { isElfImage, parseGnuBuildId, gnuBuildIdFromNotes, ModuleByteReader } from "./elf_build_id.js";

const BUILD_ID = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
const BUILD_ID_HEX = "deadbeef0123456789abcdef0011223344556677";

function note(name: string, type: number, desc: number[]): number[] {
    const nameBytes = [...name].map((c) => c.charCodeAt(0));
    const pad = (a: number[]) => a.concat(new Array((4 - (a.length % 4)) % 4).fill(0));
    const header = new Uint8Array(12);
    const dv = new DataView(header.buffer);
    dv.setUint32(0, nameBytes.length, true);
    dv.setUint32(4, desc.length, true);
    dv.setUint32(8, type, true);
    return [...header, ...pad(nameBytes), ...pad(desc)];
}

interface FakeElfOptions { is64?: boolean; notes?: number[]; noteType?: number; firstLoadVaddr?: number }

/** ELF header + PT_LOAD + PT_NOTE program headers + notes at 0x200 (vaddr = offset + firstLoadVaddr). */
function fakeElf({ is64 = true, notes = note("GNU\0", 3, BUILD_ID), noteType = 4, firstLoadVaddr = 0 }: FakeElfOptions = {}): Uint8Array {
    const image = new Uint8Array(0x400);
    const dv = new DataView(image.buffer);
    image.set([0x7f, 0x45, 0x4c, 0x46, is64 ? 2 : 1, 1, 1]);
    const phoff = 0x40, phentsize = is64 ? 0x38 : 0x20, notesAt = 0x200;
    if (is64) {
        dv.setBigUint64(0x20, BigInt(phoff), true);
        dv.setUint16(0x36, phentsize, true);
        dv.setUint16(0x38, 2, true);
    } else {
        dv.setUint32(0x1c, phoff, true);
        dv.setUint16(0x2a, phentsize, true);
        dv.setUint16(0x2c, 2, true);
    }
    const phdr = (i: number, type: number, vaddr: number, filesz: number) => {
        const at = phoff + i * phentsize;
        dv.setUint32(at, type, true);
        if (is64) {
            dv.setBigUint64(at + 0x10, BigInt(vaddr), true);
            dv.setBigUint64(at + 0x20, BigInt(filesz), true);
            dv.setBigUint64(at + 0x30, 4n, true);
        } else {
            dv.setUint32(at + 0x08, vaddr, true);
            dv.setUint32(at + 0x10, filesz, true);
            dv.setUint32(at + 0x1c, 4, true);
        }
    };
    phdr(0, 1, firstLoadVaddr, image.length);
    phdr(1, noteType, notesAt + firstLoadVaddr, notes.length);
    image.set(notes, notesAt);
    return image;
}

function reader(image: Uint8Array, unreadableFrom = Infinity): ModuleByteReader {
    return (offset, length) => {
        if (offset + length > unreadableFrom) return null;
        if (offset < 0 || offset + length > image.length) return null;
        return image.slice(offset, offset + length);
    };
}

test("ELF64: build id is read from the PT_NOTE segment as lowercase hex", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf())), BUILD_ID_HEX);
});

test("ELF32: build id is read as well", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf({ is64: false }))), BUILD_ID_HEX);
});

test("a non-zero first PT_LOAD vaddr is treated as the module base", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf({ firstLoadVaddr: 0x10000 }))), BUILD_ID_HEX);
});

test("a first PT_LOAD vaddr at or above 2^31 is page-aligned without 32-bit truncation", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf({ is64: false, firstLoadVaddr: 0x80001000 }))), BUILD_ID_HEX);
    assert.equal(parseGnuBuildId(reader(fakeElf({ firstLoadVaddr: 0x80001000 }))), BUILD_ID_HEX);
    assert.equal(parseGnuBuildId(reader(fakeElf({ firstLoadVaddr: 0x1_2345_6000 }))), BUILD_ID_HEX);
});

test("the build id is found after other notes in the same segment", () => {
    const notes = [...note("Android\0", 1, [1, 0, 0, 0]), ...note("GNU\0", 3, BUILD_ID)];
    assert.equal(parseGnuBuildId(reader(fakeElf({ notes }))), BUILD_ID_HEX);
});

test("no build-id note: wrong type, wrong name, or no PT_NOTE at all", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf({ notes: note("GNU\0", 1, BUILD_ID) }))), null);
    assert.equal(parseGnuBuildId(reader(fakeElf({ notes: note("GNX\0", 3, BUILD_ID) }))), null);
    assert.equal(parseGnuBuildId(reader(fakeElf({ noteType: 6 }))), null);
});

test("truncated: a note whose descriptor runs past the segment yields null", () => {
    const truncated = note("GNU\0", 3, BUILD_ID).slice(0, 20);
    assert.equal(parseGnuBuildId(reader(fakeElf({ notes: truncated }))), null);
    assert.equal(gnuBuildIdFromNotes(new Uint8Array(truncated), true), null);
});

test("unreadable memory and non-ELF images yield null without throwing", () => {
    assert.equal(parseGnuBuildId(reader(fakeElf(), 0x200)), null);
    assert.equal(parseGnuBuildId(reader(fakeElf(), 0x10)), null);
    assert.equal(parseGnuBuildId(reader(new Uint8Array(0x400))), null);
    assert.equal(parseGnuBuildId(() => { throw new Error("access violation"); }), null);
});

test("isElfImage accepts only an ELF header (NSS tier 1 is ELF-only)", () => {
    const header = (bytes: (number | null)[]): ModuleByteReader => (offset, length) => {
        const slice = bytes.slice(offset, offset + length);
        return slice.length < length || slice.includes(null) ? null : Uint8Array.from(slice as number[]);
    };
    assert.equal(isElfImage(header([0x7f, 0x45, 0x4c, 0x46])), true);
    assert.equal(isElfImage(header([0xcf, 0xfa, 0xed, 0xfe])), false); // Mach-O 64
    assert.equal(isElfImage(header([0x4d, 0x5a, 0x90, 0x00])), false); // PE "MZ"
    assert.equal(isElfImage(header([0x7f, 0x45, null, 0x46])), false); // unreadable byte
    assert.equal(isElfImage(header([])), false);
});
