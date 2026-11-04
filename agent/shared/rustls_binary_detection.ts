// agent/shared/rustls_binary_detection.ts
//
// Content-based detection of plain programs that statically link rustls. Like Go's
// crypto/tls, rustls is linked straight into the application image (the main executable
// under ANY name, or an arbitrarily named .so), so a module-name regex such as
// /.*rustls.*/ never finds a normal Rust binary like `myapp`. This is the rustls
// counterpart of agent/shared/go_binary_detection.ts.
//
// The marker: a Rust binary that links rustls reliably keeps ASCII crate source-path
// strings in .rodata — the `#[track_caller]` / panic location metadata, e.g.
//   ".../registry/src/index.crates.io-.../rustls-0.23.27/src/tls13/key_schedule.rs"
// These SURVIVE `strip`, because they are panic-machinery rodata, not symbols. The
// substring "rustls-0.2" is used as the content marker (covers 0.20 .. 0.29); the exact
// version ("0.23.27") is captured when present, to help a caller pick a pattern set.
//
// Layout handled: ELF (Linux/Android) and, incidentally, PE (Windows) — the scan walks
// the module's READABLE, non-executable ranges (where .rodata / .rdata map on both), so
// no format-specific section parsing is needed. Windows is not device-validated here.
//
// Bounded, never an unbounded whole-module Memory.scanSync: each range is read in chunks
// (XREF_SCAN_CHUNK_BYTES, as the xref scanner uses) with an overlap so a marker straddling
// a chunk boundary is still found, and the total bytes read per module are capped
// (RUSTLS_SCAN_BUDGET_BYTES) so a huge non-Rust module cannot block the agent. Verdicts
// are cached per module (name + base), so the registry's contentFilter may call it on
// every load. The pure helpers (buffer in -> result out) are unit-tested without Frida.

import { devlog } from "../util/log.js";
import { XREF_SCAN_CHUNK_BYTES } from "./arm64_xref.js";

/** The content marker: panic-location rodata keeps the crate path "...rustls-0.2x.y/...". */
export const RUSTLS_MARKER = "rustls-0.2";

/** "rustls-" prefix of the marker; the version digits start right after it. */
const RUSTLS_PREFIX = "rustls-";

/**
 * Bytes, measured from the marker start, that may hold the whole "rustls-<version>"
 * token ("rustls-" + e.g. "0.23.278"). Chunks overlap by this minus one so the marker
 * AND its version are always wholly inside the chunk whose body the marker starts in.
 */
export const RUSTLS_VERSION_SPAN = 24;

/** Chunk size for the range reads (reuses the xref scanner's bound). */
export const RUSTLS_SCAN_CHUNK_BYTES = XREF_SCAN_CHUNK_BYTES;

/** Upper bound on bytes read per module; a huge non-Rust module cannot block the agent. */
export const RUSTLS_SCAN_BUDGET_BYTES = 64 * 1024 * 1024;

const MARKER_BYTES: readonly number[] = Array.from(RUSTLS_MARKER, (c) => c.charCodeAt(0));

/** Offset of the first `RUSTLS_MARKER` occurrence in `bytes`, or -1. */
export function findRustlsMarker(bytes: Uint8Array): number {
    const first = MARKER_BYTES[0];
    const last = bytes.length - MARKER_BYTES.length;
    for (let i = 0; i <= last; i++) {
        if (bytes[i] !== first) continue;
        let j = 1;
        for (; j < MARKER_BYTES.length; j++) if (bytes[i + j] !== MARKER_BYTES[j]) break;
        if (j === MARKER_BYTES.length) return i;
    }
    return -1;
}

/**
 * The exact rustls version at a marker found at `markerOffset` ("0.23.27"), or undefined
 * when the digits after "rustls-" are not a dotted version (e.g. truncated at the buffer
 * end). Reads at most `RUSTLS_VERSION_SPAN` bytes.
 */
export function extractRustlsVersion(bytes: Uint8Array, markerOffset: number): string | undefined {
    const start = markerOffset + RUSTLS_PREFIX.length;
    let text = "";
    for (let i = start; i < bytes.length && i < start + RUSTLS_VERSION_SPAN; i++) {
        const c = bytes[i];
        if ((c >= 0x30 && c <= 0x39) || c === 0x2e) text += String.fromCharCode(c);
        else break;
    }
    const match = /^\d+\.\d+(?:\.\d+)?/.exec(text);
    return match ? match[0] : undefined;
}

export interface RustlsDetection {
    present: boolean;
    version?: string;
}

/** Whether `bytes` contains the marker, and the version when it does. */
export function scanBufferForRustls(bytes: Uint8Array): RustlsDetection {
    const offset = findRustlsMarker(bytes);
    if (offset < 0) return { present: false };
    return { present: true, version: extractRustlsVersion(bytes, offset) };
}

/** Reads `length` bytes at `offset` within the region, or null when unreadable. */
export type ChunkReader = (offset: number, length: number) => Uint8Array | null;

/**
 * Walk a region of `totalSize` bytes in `chunkBytes` slices, each overlapping the next by
 * `RUSTLS_VERSION_SPAN - 1` so a marker (and its version) straddling a boundary is not
 * lost, and return the first marker hit. An unreadable slice is skipped, never fatal.
 */
export function scanChunkedForRustls(read: ChunkReader, totalSize: number,
                                     chunkBytes: number = RUSTLS_SCAN_CHUNK_BYTES): RustlsDetection {
    const overlap = RUSTLS_VERSION_SPAN - 1;
    const step = Math.max(1, chunkBytes);
    for (let off = 0; off < totalSize; off += step) {
        const length = Math.min(step + overlap, totalSize - off);
        const chunk = read(off, length);
        if (chunk === null) continue;
        const result = scanBufferForRustls(chunk);
        if (result.present) return result;
    }
    return { present: false };
}

/** The minimal module surface the detector needs (a Frida Module, or a test double). */
export interface RustlsDetectableModule {
    name: string;
    base: NativePointer;
    size: number;
    enumerateRanges?: (protection: string) => { base: NativePointer; size: number; protection: string }[];
}

function readBytes(address: NativePointer, length: number): Uint8Array | null {
    const buffer = address.readByteArray(length);
    return buffer === null ? null : new Uint8Array(buffer);
}

/**
 * Every readable range of the module (Frida's "r--" mask is "readable, x/w don't care", so
 * this includes r-x and rw- ranges); empty when the module exposes no range enumeration.
 * The marker must NOT be restricted to non-executable ranges: this toolchain (and lld by
 * default) maps .rodata inside the SAME read+execute LOAD segment as .text, so the crate
 * path lives in an r-x range on a plain Rust binary.
 */
function readableRanges(module: RustlsDetectableModule): { base: NativePointer; size: number }[] {
    if (typeof module.enumerateRanges !== "function") return [];
    return module.enumerateRanges("r--");
}

/**
 * Whether `module` embeds rustls (its .rodata carries the "rustls-0.2" crate-path marker),
 * and the exact version when found. Bounded (RUSTLS_SCAN_BUDGET_BYTES) and chunked; never
 * throws — an unreadable module is simply "not rustls".
 */
export function moduleEmbedsRustls(module: RustlsDetectableModule): RustlsDetection {
    try {
        let budget = RUSTLS_SCAN_BUDGET_BYTES;
        for (const range of readableRanges(module)) {
            if (budget <= 0) break;
            const size = Math.min(range.size, budget);
            const result = scanChunkedForRustls(
                (off, len) => readBytes(range.base.add(off), len), size, RUSTLS_SCAN_CHUNK_BYTES);
            if (result.present) return result;
            budget -= size;
        }
    } catch (e) {
        devlog(`[rustls-detect] ${module.name}: content check failed (${e}); not treated as rustls`);
    }
    return { present: false };
}

const verdicts = new Map<string, RustlsDetection>();

/**
 * Registry contentFilter for the content-based rustls row: whether the loaded module
 * `moduleName` statically links rustls. Cached per name + base (a reloaded library is
 * re-checked). FAILS CLOSED, so a lookup that throws never claims a module as rustls.
 */
export function isRustlsModule(moduleName: string): boolean {
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
        verdict = moduleEmbedsRustls(module);
        verdicts.set(key, verdict);
        if (verdict.present) {
            devlog(`[rustls-detect] ${moduleName}: rustls marker found${verdict.version ? ` (rustls ${verdict.version})` : ""}; rustls hooks apply`);
        }
    }
    return verdict.present;
}

/**
 * Module names the existing name-based Linux rustls row already matches (its pattern is the
 * "rustls" substring regex): the excludePattern of the content-based row, so no module is
 * hooked by both (ssl_library_loader invokes every matching row).
 */
export const RUSTLS_LINUX_NAMED_MODULE = /rustls/;

/** Test hook: forget cached verdicts. */
export function resetRustlsModuleCache(): void {
    verdicts.clear();
}
