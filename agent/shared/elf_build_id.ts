// agent/shared/elf_build_id.ts
//
// GNU build id (NT_GNU_BUILD_ID) of a loaded ELF module, read from its
// in-memory program headers. Identifies one exact library build, so the
// learned plaintext-RVA cache can tell a rebuilt library from a reused name.

import { toHexString } from "../util/hex.js";
import { type ModuleByteReader, moduleMemoryReader } from "./module_mapping.js";

export { moduleMemoryReader };
export type { ModuleByteReader };

const ELF_MAGIC = [0x7f, 0x45, 0x4c, 0x46];
const ELFCLASS32 = 1;
const ELFCLASS64 = 2;
const ELFDATA2LSB = 1;
const PT_LOAD = 1;
const PT_NOTE = 4;
const NT_GNU_BUILD_ID = 3;
const GNU_NOTE_NAME = "GNU\0";
const ELF_HEADER_BYTES = 64;
const MAX_PROGRAM_HEADERS = 512;
const MAX_NOTE_SEGMENT_BYTES = 64 * 1024;
const MAX_BUILD_ID_BYTES = 64;
const PAGE_SIZE = 0x1000;

interface ElfLayout {
    is64: boolean;
    littleEndian: boolean;
    phoff: number;
    phentsize: number;
    phnum: number;
}

interface ProgramHeader {
    type: number;
    vaddr: number;
    filesz: number;
    align: number;
}

function view(bytes: Uint8Array): DataView {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

// Offsets beyond 2^53 cannot be real in-memory layouts; reject rather than round.
function readWord(dv: DataView, offset: number, is64: boolean, le: boolean): number {
    if (!is64) return dv.getUint32(offset, le);
    const value = dv.getBigUint64(offset, le);
    return value > BigInt(Number.MAX_SAFE_INTEGER) ? -1 : Number(value);
}

function hasElfMagic(header: Uint8Array): boolean {
    return header.length >= ELF_MAGIC.length && ELF_MAGIC.every((b, i) => header[i] === b);
}

/** True when the image behind `read` starts with the ELF magic (an unreadable header is not ELF). */
export function isElfImage(read: ModuleByteReader): boolean {
    const header = read(0, ELF_MAGIC.length);
    return header !== null && hasElfMagic(header);
}

function parseElfHeader(header: Uint8Array | null): ElfLayout | null {
    if (header === null || header.length < ELF_HEADER_BYTES) return null;
    if (!hasElfMagic(header)) return null;
    const elfClass = header[4];
    if (elfClass !== ELFCLASS32 && elfClass !== ELFCLASS64) return null;
    const is64 = elfClass === ELFCLASS64;
    const littleEndian = header[5] === ELFDATA2LSB;
    const dv = view(header);
    return {
        is64,
        littleEndian,
        phoff: readWord(dv, is64 ? 0x20 : 0x1c, is64, littleEndian),
        phentsize: dv.getUint16(is64 ? 0x36 : 0x2a, littleEndian),
        phnum: dv.getUint16(is64 ? 0x38 : 0x2c, littleEndian),
    };
}

function parseProgramHeader(dv: DataView, at: number, layout: ElfLayout): ProgramHeader {
    const { is64, littleEndian: le } = layout;
    return {
        type: dv.getUint32(at, le),
        vaddr: readWord(dv, at + (is64 ? 0x10 : 0x08), is64, le),
        filesz: readWord(dv, at + (is64 ? 0x20 : 0x10), is64, le),
        align: readWord(dv, at + (is64 ? 0x30 : 0x1c), is64, le),
    };
}

function readProgramHeaders(read: ModuleByteReader, layout: ElfLayout): ProgramHeader[] | null {
    const minEntry = layout.is64 ? 0x38 : 0x20;
    if (layout.phoff <= 0 || layout.phentsize < minEntry) return null;
    if (layout.phnum === 0 || layout.phnum > MAX_PROGRAM_HEADERS) return null;
    const table = read(layout.phoff, layout.phnum * layout.phentsize);
    if (table === null || table.length < layout.phnum * layout.phentsize) return null;
    const dv = view(table);
    const headers: ProgramHeader[] = [];
    for (let i = 0; i < layout.phnum; i++) headers.push(parseProgramHeader(dv, i * layout.phentsize, layout));
    return headers;
}

function alignUp(value: number, alignment: number): number {
    return Math.ceil(value / alignment) * alignment;
}

/** The NT_GNU_BUILD_ID descriptor among the notes in `notes`, as lowercase hex. */
export function gnuBuildIdFromNotes(notes: Uint8Array, littleEndian: boolean, alignment: number = 4): string | null {
    const dv = view(notes);
    let at = 0;
    while (at + 12 <= notes.length) {
        const namesz = dv.getUint32(at, littleEndian);
        const descsz = dv.getUint32(at + 4, littleEndian);
        const type = dv.getUint32(at + 8, littleEndian);
        const nameAt = at + 12;
        const descAt = nameAt + alignUp(namesz, alignment);
        const next = descAt + alignUp(descsz, alignment);
        if (descAt + descsz > notes.length) return null;
        const name = String.fromCharCode(...notes.subarray(nameAt, nameAt + namesz));
        if (type === NT_GNU_BUILD_ID && name === GNU_NOTE_NAME && descsz > 0 && descsz <= MAX_BUILD_ID_BYTES) {
            return toHexString(notes.subarray(descAt, descAt + descsz));
        }
        if (next <= at) return null;
        at = next;
    }
    return null;
}

// The module base maps the page holding the lowest PT_LOAD vaddr.
function loadBias(headers: ProgramHeader[]): number {
    const loads = headers.filter((h) => h.type === PT_LOAD && h.vaddr >= 0);
    if (loads.length === 0) return 0;
    const lowest = Math.min(...loads.map((h) => h.vaddr));
    // Arithmetic, not `& ~mask`: bitwise ops truncate to signed 32 bits (vaddr >= 2^31).
    return lowest - (lowest % PAGE_SIZE);
}

function buildIdFromNoteSegment(read: ModuleByteReader, note: ProgramHeader, bias: number,
                                littleEndian: boolean): string | null {
    const offset = note.vaddr - bias;
    if (note.vaddr < 0 || offset < 0 || note.filesz <= 0 || note.filesz > MAX_NOTE_SEGMENT_BYTES) return null;
    const notes = read(offset, note.filesz);
    if (notes === null) return null;
    return gnuBuildIdFromNotes(notes, littleEndian, note.align === 8 ? 8 : 4);
}

/**
 * GNU build id of the ELF image behind `read`, as lowercase hex, or null when
 * it is not ELF, has no build-id note, or any needed byte is unreadable.
 * Never throws.
 */
export function parseGnuBuildId(read: ModuleByteReader): string | null {
    try {
        const layout = parseElfHeader(read(0, ELF_HEADER_BYTES));
        if (layout === null) return null;
        const headers = readProgramHeaders(read, layout);
        if (headers === null) return null;
        const bias = loadBias(headers);
        for (const note of headers.filter((h) => h.type === PT_NOTE)) {
            const buildId = buildIdFromNoteSegment(read, note, bias, layout.littleEndian);
            if (buildId !== null) return buildId;
        }
    } catch (_e) {
        // A malformed header must read as "no build id", never as a hook failure.
    }
    return null;
}

/** GNU build id of the module loaded at `base`, or null. */
export function moduleGnuBuildId(base: NativePointer): string | null {
    return parseGnuBuildId(moduleMemoryReader(base));
}
