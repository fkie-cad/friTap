// agent/util/proc_maps.ts
//
// /proc/self/maps helpers for locating PE images that Frida does not list as
// modules. On Wine >= 9 (the "wow64" layout) PE DLLs/EXEs are mapped straight
// from their files but never appear in Process.enumerateModules(), so anything
// that wants to scan or hook e.g. libcef.dll must find the image here instead.

import { devlog } from "./log.js";

/** A PE image located via /proc/self/maps, shaped like the subset of Frida's
 *  `Module` the BoringSSL locators use (name/base/size/path/enumerateRanges). */
export interface ModuleLike {
    name: string;
    base: NativePointer;
    size: number;
    path: string;
    enumerateRanges(protection: PageProtection): RangeDetails[];
}

/** One header mapping (file offset 0) of a .dll/.exe, as parsed from maps text. */
export interface MapsPeEntry {
    base: string;
    path: string;
    name: string;
}

function tryGlobalExport(name: string): NativePointer | null {
    try { return Module.getGlobalExportByName(name); } catch (_e) { return null; }
}

/**
 * Read /proc/self/maps into a string via libc open/read/close. Bounded read:
 * /proc/self/maps for a Wine process is typically 200–500 KB; we cap the
 * returned buffer at 4 MB defensively.
 */
export function readProcSelfMaps(): string | null {
    try {
        const openPtr = tryGlobalExport("open");
        const readPtr = tryGlobalExport("read");
        const closePtr = tryGlobalExport("close");
        if (!openPtr || !readPtr || !closePtr) return null;

        const open = new NativeFunction(openPtr, "int", ["pointer", "int"]);
        const read = new NativeFunction(readPtr, "long", ["int", "pointer", "ulong"]);
        const close = new NativeFunction(closePtr, "int", ["int"]);

        const path = Memory.allocUtf8String("/proc/self/maps");
        const fd = open(path, 0 /* O_RDONLY */) as number;
        if (fd < 0) return null;

        const chunkSize = 65536;
        const buf = Memory.alloc(chunkSize);
        const chunks: string[] = [];
        let total = 0;
        const cap = 4 * 1024 * 1024;
        while (total < cap) {
            const n = (read(fd, buf, chunkSize) as any).valueOf() as number;
            if (n <= 0) break;
            const chunk = buf.readUtf8String(n);
            if (chunk === null) break;
            chunks.push(chunk);
            total += n;
        }
        close(fd);
        return chunks.join("");
    } catch (e) {
        devlog(`[maps] readProcSelfMaps error: ${e}`);
        return null;
    }
}

/**
 * The header mapping of every .dll/.exe in `maps` text, in address order. Pure
 * (strings only), so it is unit-testable without Frida.
 *
 *   7f00abc00000-7f00abd00000 r--p 00000000 00:1e 12345 /path/to/libcef.dll
 *
 * A PE image's first mapping (offset 0, readable) starts at its image base.
 */
export function parseMapsPeImages(maps: string): MapsPeEntry[] {
    const out: MapsPeEntry[] = [];
    const seen = new Set<string>();
    for (const line of maps.split("\n")) {
        const parts = line.trim().split(/\s+/);
        if (parts.length < 6) continue;
        const [range, perms, offset] = parts;
        if (!perms.startsWith("r")) continue;
        if (!/^0+$/.test(offset)) continue;
        const path = parts.slice(5).join(" ");
        if (!/\.(dll|exe)$/i.test(path)) continue;
        if (seen.has(path)) continue;
        seen.add(path);
        const name = path.split(/[\\/]/).pop() ?? path;
        out.push({ base: "0x" + range.split("-")[0], path, name });
    }
    return out;
}

/** SizeOfImage from the in-memory PE headers at `base`, or null if not a PE. */
export function peSizeOfImage(base: NativePointer): number | null {
    try {
        if (base.readU16() !== 0x5a4d) return null; // "MZ"
        const nt = base.add(base.add(0x3c).readU32());
        if (nt.readU32() !== 0x00004550) return null; // "PE\0\0"
        // OptionalHeader.SizeOfImage sits at +56 in both PE32 and PE32+.
        return nt.add(24 + 56).readU32();
    } catch (_e) {
        return null;
    }
}

/** Wrap a PE image at `base` as a ModuleLike; its ranges are the process ranges
 *  clipped to [base, base + SizeOfImage). */
export function peModuleLike(name: string, base: NativePointer, path: string): ModuleLike | null {
    const size = peSizeOfImage(base);
    if (size === null || size === 0) return null;
    const end = base.add(size);
    return {
        name, base, size, path,
        enumerateRanges(protection: PageProtection): RangeDetails[] {
            const out: RangeDetails[] = [];
            for (const r of Process.enumerateRanges(protection)) {
                const rEnd = r.base.add(r.size);
                if (rEnd.compare(base) <= 0 || r.base.compare(end) >= 0) continue;
                const lo = r.base.compare(base) < 0 ? base : r.base;
                const hi = rEnd.compare(end) > 0 ? end : rEnd;
                out.push({ ...r, base: lo, size: hi.sub(lo).toInt32() });
            }
            return out;
        },
    };
}

/** Every PE image mapped into this process (Wine), as ModuleLikes. */
export function listPeImages(): ModuleLike[] {
    const maps = readProcSelfMaps();
    if (!maps) return [];
    const out: ModuleLike[] = [];
    for (const e of parseMapsPeImages(maps)) {
        const m = peModuleLike(e.name, ptr(e.base), e.path);
        if (m) out.push(m);
    }
    return out;
}

/**
 * Resolve `moduleName` (case-insensitive basename) to a Module or, when Frida
 * does not list it (PE images on Wine >= 9), to a /proc/self/maps ModuleLike.
 */
export function findModuleOrPeImage(moduleName: string): Module | ModuleLike | null {
    try {
        const m = Process.findModuleByName(moduleName);
        if (m !== null) return m;
    } catch (_e) { /* fall through to maps */ }
    const maps = readProcSelfMaps();
    if (!maps) return null;
    const wanted = moduleName.toLowerCase();
    for (const e of parseMapsPeImages(maps)) {
        if (e.name.toLowerCase() === wanted) return peModuleLike(e.name, ptr(e.base), e.path);
    }
    return null;
}
