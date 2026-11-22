// agent/shared/pe_header.ts
//
// Build identity of a loaded PE (Windows) module, read from its in-memory
// headers: the CodeView RSDS record (PDB GUID + age) that the linker writes for
// every build, else the COFF TimeDateStamp + SizeOfImage pair. Gives Windows
// modules a learned-cache key, the way elf_build_id.ts and macho_header.ts do
// for ELF and Mach-O.
//
// Reads go through the mapped image, so every location is an RVA (never a file
// offset such as PointerToRawData).

import { toHexString } from "../util/hex.js";
import { isReadable } from "../util/safe_memory.js";
import { type CacheModule, type ModuleByteReader, moduleMemoryReader } from "./module_mapping.js";

const IMAGE_DOS_SIGNATURE = 0x5a4d;            // "MZ"
const IMAGE_NT_SIGNATURE = 0x00004550;         // "PE\0\0"
const DOS_HEADER_BYTES = 0x40;
const E_LFANEW_OFFSET = 0x3c;
const MAX_E_LFANEW = 0x10000;
const NT_SIGNATURE_BYTES = 4;
const COFF_HEADER_BYTES = 20;
const COFF_TIMESTAMP_OFFSET = 4;               // within the COFF header
const COFF_OPTIONAL_HEADER_SIZE_OFFSET = 16;   // within the COFF header
const OPTIONAL_HEADER_OFFSET = NT_SIGNATURE_BYTES + COFF_HEADER_BYTES;
const PE32_MAGIC = 0x10b;
const PE32_PLUS_MAGIC = 0x20b;
const SIZE_OF_IMAGE_OFFSET = 56;               // same in PE32 and PE32+
const PE32_DATA_DIRECTORY_OFFSET = 96;
const PE32_PLUS_DATA_DIRECTORY_OFFSET = 112;
const DATA_DIRECTORY_ENTRY_BYTES = 8;
const IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
const DEBUG_DIRECTORY_ENTRY_BYTES = 28;
const MAX_DEBUG_DIRECTORY_ENTRIES = 16;
const DEBUG_TYPE_OFFSET = 12;
const DEBUG_SIZE_OF_DATA_OFFSET = 16;
const DEBUG_ADDRESS_OF_RAW_DATA_OFFSET = 20;
const IMAGE_DEBUG_TYPE_CODEVIEW = 2;
const CODEVIEW_RSDS_SIGNATURE = 0x53445352;    // "RSDS"
const CODEVIEW_GUID_OFFSET = 4;
const CODEVIEW_AGE_OFFSET = 20;
const CODEVIEW_MIN_BYTES = 24;
const UNSET_TIMESTAMPS = [0, 0xffffffff];

/** The debug directory parsed cleanly but holds no RSDS record: fall back to the timestamp key. */
const NO_CODEVIEW = Symbol("no-codeview");
type CodeViewLookup = string | typeof NO_CODEVIEW | null;

interface PeHeaders {
    timeDateStamp: number;
    sizeOfImage: number;
    debugRva: number;
    debugSize: number;
}

function view(bytes: Uint8Array): DataView {
    return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function hex32(value: number): string {
    return value.toString(16).padStart(8, "0");
}

function hex16(value: number): string {
    return value.toString(16).padStart(4, "0");
}

function readNtOffset(read: ModuleByteReader): number | null {
    const dos = read(0, DOS_HEADER_BYTES);
    if (dos === null || dos.length < DOS_HEADER_BYTES) return null;
    const dv = view(dos);
    if (dv.getUint16(0, true) !== IMAGE_DOS_SIGNATURE) return null;
    const nt = dv.getUint32(E_LFANEW_OFFSET, true);
    return nt === 0 || nt > MAX_E_LFANEW ? null : nt;
}

function dataDirectoryOffset(magic: number): number | null {
    if (magic === PE32_MAGIC) return PE32_DATA_DIRECTORY_OFFSET;
    if (magic === PE32_PLUS_MAGIC) return PE32_PLUS_DATA_DIRECTORY_OFFSET;
    return null;
}

/** NT signature, COFF header and optional header up to the debug data directory. */
function readPeHeaders(read: ModuleByteReader, nt: number): PeHeaders | null {
    const fixed = read(nt, OPTIONAL_HEADER_OFFSET);
    if (fixed === null || fixed.length < OPTIONAL_HEADER_OFFSET) return null;
    const fdv = view(fixed);
    if (fdv.getUint32(0, true) !== IMAGE_NT_SIGNATURE) return null;
    const timeDateStamp = fdv.getUint32(NT_SIGNATURE_BYTES + COFF_TIMESTAMP_OFFSET, true);
    const optionalSize = fdv.getUint16(NT_SIGNATURE_BYTES + COFF_OPTIONAL_HEADER_SIZE_OFFSET, true);
    const optional = read(nt + OPTIONAL_HEADER_OFFSET, optionalSize);
    if (optional === null || optional.length < optionalSize || optionalSize < 2) return null;
    const odv = view(optional);
    const directories = dataDirectoryOffset(odv.getUint16(0, true));
    if (directories === null || optionalSize < directories) return null;
    const sizeOfImage = odv.getUint32(SIZE_OF_IMAGE_OFFSET, true);
    const directoryCount = odv.getUint32(directories - 4, true);
    const debugAt = directories + IMAGE_DIRECTORY_ENTRY_DEBUG * DATA_DIRECTORY_ENTRY_BYTES;
    const hasDebug = directoryCount > IMAGE_DIRECTORY_ENTRY_DEBUG && debugAt + DATA_DIRECTORY_ENTRY_BYTES <= optionalSize;
    return {
        timeDateStamp,
        sizeOfImage,
        debugRva: hasDebug ? odv.getUint32(debugAt, true) : 0,
        debugSize: hasDebug ? odv.getUint32(debugAt + 4, true) : 0,
    };
}

function withinImage(rva: number, length: number, sizeOfImage: number): boolean {
    return rva > 0 && length > 0 && rva + length <= sizeOfImage;
}

/** GUID in canonical string order (Data1..Data3 byte-swapped from LE) + age as %08x. */
function rsdsIdentity(record: Uint8Array): string | null {
    const dv = view(record);
    if (dv.getUint32(0, true) !== CODEVIEW_RSDS_SIGNATURE) return null;
    const g = CODEVIEW_GUID_OFFSET;
    return hex32(dv.getUint32(g, true)) + hex16(dv.getUint16(g + 4, true)) + hex16(dv.getUint16(g + 6, true))
        + toHexString(record.subarray(g + 8, g + 16)) + hex32(dv.getUint32(CODEVIEW_AGE_OFFSET, true));
}

function codeViewFromEntry(read: ModuleByteReader, entry: DataView, at: number, sizeOfImage: number): CodeViewLookup {
    const size = entry.getUint32(at + DEBUG_SIZE_OF_DATA_OFFSET, true);
    const rva = entry.getUint32(at + DEBUG_ADDRESS_OF_RAW_DATA_OFFSET, true);
    if (rva === 0) return NO_CODEVIEW;   // record not mapped (file-only debug data)
    if (size < CODEVIEW_MIN_BYTES || !withinImage(rva, CODEVIEW_MIN_BYTES, sizeOfImage)) return null;
    const record = read(rva, CODEVIEW_MIN_BYTES);
    if (record === null || record.length < CODEVIEW_MIN_BYTES) return null;
    return rsdsIdentity(record) ?? NO_CODEVIEW;
}

/** First CodeView entry of the debug directory, as an RSDS identity. */
function findCodeView(read: ModuleByteReader, headers: PeHeaders): CodeViewLookup {
    if (headers.debugRva === 0 || headers.debugSize === 0) return NO_CODEVIEW;
    const count = Math.min(Math.floor(headers.debugSize / DEBUG_DIRECTORY_ENTRY_BYTES), MAX_DEBUG_DIRECTORY_ENTRIES);
    const length = count * DEBUG_DIRECTORY_ENTRY_BYTES;
    if (!withinImage(headers.debugRva, length, headers.sizeOfImage)) return null;
    const table = read(headers.debugRva, length);
    if (table === null || table.length < length) return null;
    const dv = view(table);
    for (let i = 0; i < count; i++) {
        const at = i * DEBUG_DIRECTORY_ENTRY_BYTES;
        if (dv.getUint32(at + DEBUG_TYPE_OFFSET, true) === IMAGE_DEBUG_TYPE_CODEVIEW) {
            return codeViewFromEntry(read, dv, at, headers.sizeOfImage);
        }
    }
    return NO_CODEVIEW;
}

// A missing or placeholder timestamp would collide across builds; refuse rather than mis-key.
function timestampIdentity(headers: PeHeaders): string | null {
    if (UNSET_TIMESTAMPS.includes(headers.timeDateStamp) || headers.sizeOfImage === 0) return null;
    return hex32(headers.timeDateStamp) + hex32(headers.sizeOfImage);
}

/**
 * Build identity of the PE image behind `read`, as lowercase hex: 40 chars
 * (RSDS GUID + age) when the image has a mapped CodeView record, else 16 chars
 * (TimeDateStamp + SizeOfImage). Null when it is not PE, the debug data is
 * malformed or unreadable, or the timestamp is unset. Never throws.
 */
export function parsePeIdentity(read: ModuleByteReader): string | null {
    try {
        const nt = readNtOffset(read);
        if (nt === null) return null;
        const headers = readPeHeaders(read, nt);
        if (headers === null) return null;
        const codeView = findCodeView(read, headers);
        if (codeView === null) return null;
        return codeView === NO_CODEVIEW ? timestampIdentity(headers) : codeView;
    } catch (_e) {
        // A malformed header must read as "no identity", never as a hook failure.
    }
    return null;
}

/** PE build identity of `mod`, or null. */
export function modulePeIdentity(mod: CacheModule): string | null {
    return parsePeIdentity(moduleMemoryReader(mod.base));
}

/** True when `base` starts with the PE "MZ" signature (read-only, guarded). Never throws. */
export function isPeImage(base: NativePointer): boolean {
    try {
        return isReadable(base, 2) && base.readU16() === IMAGE_DOS_SIGNATURE;
    } catch (_e) {
        return false;
    }
}
