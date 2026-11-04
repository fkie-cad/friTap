// agent/shared/go_binary_detection.ts
//
// Content-based detection of Go images (executables and -buildmode=c-shared/c-archive
// libraries). Go's crypto/tls is linked into the image itself — usually the MAIN
// EXECUTABLE, under any name — so a module-name regex cannot find it. Every Go image
// carries the build-info blob that `go version -m` reads, opened by the 14-byte magic
// "\xff Go buildinf:" and 16-byte aligned:
//
//   ELF     section ".go.buildinfo"   (magic at the section start)
//   Mach-O  section "__go_buildinfo"  (__DATA; magic at the section start)
//   PE      no own section: the blob opens the ".data" section (Go's debug/buildinfo
//           searches .data for the magic at 16-byte alignment, as done here)
//
// The check is cheap and bounded: ELF/Mach-O read the section table Frida already parses
// (all ~350 modules of a macOS process in ~8 ms) and 14 bytes; PE parses the in-memory
// section table and scans at most the first 64 KiB of .data. Results are cached per
// module (name + base), so the registry's contentFilter may call it on every load.
// Validated on Go 1.21/1.24/1.25 builds for darwin/{arm64,amd64} and windows/{arm64,amd64},
// full and `-ldflags="-s -w"` (the blob survives stripping).

import { devlog } from "../util/log.js";

/** "\xff Go buildinf:" — the magic that opens Go's build-info blob. */
export const GO_BUILDINFO_MAGIC: readonly number[] = [
    0xff, 0x20, 0x47, 0x6f, 0x20, 0x62, 0x75, 0x69, 0x6c, 0x64, 0x69, 0x6e, 0x66, 0x3a,
];

/** The blob's alignment inside the data section (cmd/link, debug/buildinfo). */
export const GO_BUILDINFO_ALIGN = 16;

/** ELF / Mach-O section names of the build-info blob. */
const GO_BUILDINFO_SECTIONS: ReadonlySet<string> = new Set([".go.buildinfo", "__go_buildinfo"]);

/** How much of a PE's .data is searched for the blob (it sits at or near the start). */
export const PE_DATA_SEARCH_BYTES = 0x10000;

/** PE headers read to parse the section table (SizeOfHeaders is 0x400 for Go, <= 0x1000 usually). */
const PE_HEADER_BYTES = 0x1000;

/** Whether `bytes` holds the build-info magic at `offset`. */
export function hasGoBuildInfoMagicAt(bytes: Uint8Array, offset: number): boolean {
    if (offset < 0 || offset + GO_BUILDINFO_MAGIC.length > bytes.length) return false;
    return GO_BUILDINFO_MAGIC.every((b, i) => bytes[offset + i] === b);
}

/** Offset of the first 16-byte-aligned build-info magic in `bytes`, or -1. */
export function findGoBuildInfoMagic(bytes: Uint8Array): number {
    for (let off = 0; off + GO_BUILDINFO_MAGIC.length <= bytes.length; off += GO_BUILDINFO_ALIGN) {
        if (hasGoBuildInfoMagicAt(bytes, off)) return off;
    }
    return -1;
}

/** One entry of a PE section table (addresses relative to the image base). */
export interface PeSection {
    name: string;
    virtualAddress: number;
    virtualSize: number;
}

/**
 * The section table of a PE image from its first bytes (the mapped headers), or null when
 * `headers` is not a PE ("MZ" ... "PE\0\0").
 */
export function parsePeSections(headers: Uint8Array): PeSection[] | null {
    const view = new DataView(headers.buffer, headers.byteOffset, headers.byteLength);
    if (headers.length < 0x40 || view.getUint16(0, true) !== 0x5a4d) return null; // "MZ"
    const nt = view.getUint32(0x3c, true);
    if (nt + 24 > headers.length || view.getUint32(nt, true) !== 0x00004550) return null; // "PE\0\0"
    const count = view.getUint16(nt + 6, true);
    const optionalHeaderSize = view.getUint16(nt + 20, true);
    const table = nt + 24 + optionalHeaderSize;
    const sections: PeSection[] = [];
    for (let i = 0; i < count; i++) {
        const entry = table + i * 40;
        if (entry + 40 > headers.length) break;
        let name = "";
        for (let j = 0; j < 8 && headers[entry + j] !== 0; j++) name += String.fromCharCode(headers[entry + j]);
        sections.push({ name, virtualSize: view.getUint32(entry + 8, true), virtualAddress: view.getUint32(entry + 12, true) });
    }
    return sections;
}

/** The minimal module surface the detector needs (a Frida Module, or a Wine PE ModuleLike). */
export interface GoDetectableModule {
    name: string;
    base: NativePointer;
    size: number;
    enumerateSections?: () => { name: string; address: NativePointer; size: number }[];
}

function readBytes(address: NativePointer, length: number): Uint8Array | null {
    const buffer = address.readByteArray(length);
    return buffer === null ? null : new Uint8Array(buffer);
}

/** PE: the blob at a 16-byte-aligned offset within the first 64 KiB of .data. */
function peHasGoBuildInfo(module: GoDetectableModule, headers: Uint8Array): boolean {
    const data = (parsePeSections(headers) ?? []).find((s) => s.name === ".data");
    if (!data || data.virtualSize === 0) return false;
    const length = Math.min(data.virtualSize, PE_DATA_SEARCH_BYTES);
    const bytes = readBytes(module.base.add(data.virtualAddress), length);
    return bytes !== null && findGoBuildInfoMagic(bytes) >= 0;
}

/** ELF / Mach-O: a ".go.buildinfo" / "__go_buildinfo" section opening with the magic. */
function sectionHasGoBuildInfo(module: GoDetectableModule): boolean {
    if (typeof module.enumerateSections !== "function") return false;
    for (const section of module.enumerateSections()) {
        if (!GO_BUILDINFO_SECTIONS.has(section.name)) continue;
        const bytes = readBytes(section.address, GO_BUILDINFO_MAGIC.length);
        if (bytes !== null && hasGoBuildInfoMagicAt(bytes, 0)) return true;
    }
    return false;
}

/** Whether `module` is a Go image (carries Go's build-info blob). Never throws. */
export function moduleHasGoBuildInfo(module: GoDetectableModule): boolean {
    try {
        const headers = readBytes(module.base, Math.min(PE_HEADER_BYTES, module.size));
        if (headers !== null && headers.length >= 2 && headers[0] === 0x4d && headers[1] === 0x5a) {
            return peHasGoBuildInfo(module, headers);
        }
        return sectionHasGoBuildInfo(module);
    } catch (e) {
        devlog(`[go-detect] ${module.name}: build-info check failed (${e}); not treated as Go`);
        return false;
    }
}

const verdicts = new Map<string, boolean>();

/**
 * Registry contentFilter for the Go TLS rows: whether the loaded module `moduleName` is a
 * Go image. Cached per name + base address (a reloaded library is re-checked).
 */
export function isGoModule(moduleName: string): boolean {
    let module: Module | null = null;
    try {
        module = Process.findModuleByName(moduleName);
    } catch (e) {
        module = null;
    }
    if (module === null) return false;
    const key = `${moduleName}@${module.base}`;
    let verdict = verdicts.get(key);
    if (verdict === undefined) {
        verdict = moduleHasGoBuildInfo(module);
        verdicts.set(key, verdict);
        if (verdict) devlog(`[go-detect] ${moduleName}: Go build info found; Go TLS hooks apply`);
    }
    return verdict;
}

/**
 * Linux module names the two historical name-based Go TLS rows match (/.*\.go.so$/ and
 * /.*go[0-9.]+$/): the excludePattern of the content-based Linux row, so no module is hooked
 * by both (ssl_library_loader invokes every matching row).
 */
export const GO_LINUX_NAMED_MODULE = /(\.go.so|go[0-9.]+)$/;

/** Test hook: forget cached verdicts. */
export function resetGoModuleCache(): void {
    verdicts.clear();
}
