// agent/shared/macho_header.ts
//
// 64-bit little-endian Mach-O load commands of a loaded image: LC_UUID (the
// learned-offsets cache identity, like an ELF build id) and LC_SEGMENT_64
// sections (__unwind_info, __cstring), resolved to runtime addresses.

import { toHexString } from "../util/hex.js";
import { type CacheModule, type ModuleByteReader, memoizePerMapping, moduleMemoryReader } from "./module_mapping.js";

export const MH_MAGIC_64 = 0xfeedfacf;
const LC_SEGMENT_64 = 0x19;
const LC_UUID = 0x1b;
const MACH_HEADER_64_BYTES = 32;
const SEGMENT_COMMAND_64_BYTES = 72;
const SECTION_64_BYTES = 80;
const MAX_LOAD_COMMAND_BYTES = 1024 * 1024;
const UUID_BYTES = 16;

/** One section_64; `offset` is its runtime offset from the mach header (image base). */
export interface MachOSection { segname: string; sectname: string; offset: number; size: number; }

export interface MachOLoadCommands { uuid: string | null; sections: MachOSection[]; }

function fixedString(bytes: Uint8Array, at: number, length: number): string {
    let s = "";
    for (let i = 0; i < length && bytes[at + i] !== 0; i++) s += String.fromCharCode(bytes[at + i]);
    return s;
}

function u64(dv: DataView, at: number): number {
    const v = dv.getBigUint64(at, true);
    return v > BigInt(Number.MAX_SAFE_INTEGER) ? -1 : Number(v);
}

/** True when `read` starts with a 64-bit little-endian Mach-O header. */
export function isMachO64(read: ModuleByteReader): boolean {
    const magic = read(0, 4);
    return magic !== null && magic.length === 4 && new DataView(magic.buffer, magic.byteOffset, 4).getUint32(0, true) === MH_MAGIC_64;
}

/**
 * UUID and sections of the image behind `read`, or null when it is not a
 * readable Mach-O 64. Section offsets are relative to __TEXT's vmaddr, which
 * is where the mach header is mapped. Never throws.
 */
export function parseMachOLoadCommands(read: ModuleByteReader): MachOLoadCommands | null {
    try {
        if (!isMachO64(read)) return null;
        const header = read(0, MACH_HEADER_64_BYTES);
        if (header === null || header.length < MACH_HEADER_64_BYTES) return null;
        const hv = new DataView(header.buffer, header.byteOffset, header.byteLength);
        const ncmds = hv.getUint32(16, true), sizeofcmds = hv.getUint32(20, true);
        if (sizeofcmds === 0 || sizeofcmds > MAX_LOAD_COMMAND_BYTES) return null;
        const cmds = read(MACH_HEADER_64_BYTES, sizeofcmds);
        if (cmds === null || cmds.length < sizeofcmds) return null;
        return walkLoadCommands(cmds, ncmds);
    } catch (_e) {
        return null;
    }
}

function walkLoadCommands(cmds: Uint8Array, ncmds: number): MachOLoadCommands {
    const dv = new DataView(cmds.buffer, cmds.byteOffset, cmds.byteLength);
    const raw: { segname: string; sectname: string; addr: number; size: number }[] = [];
    let uuid: string | null = null, textVmaddr: number | null = null;
    for (let i = 0, at = 0; i < ncmds && at + 8 <= cmds.length; i++) {
        const cmd = dv.getUint32(at, true), cmdsize = dv.getUint32(at + 4, true);
        if (cmdsize < 8 || at + cmdsize > cmds.length) break;
        if (cmd === LC_UUID && cmdsize >= 8 + UUID_BYTES) uuid = toHexString(cmds.subarray(at + 8, at + 8 + UUID_BYTES));
        if (cmd === LC_SEGMENT_64 && cmdsize >= SEGMENT_COMMAND_64_BYTES) {
            if (fixedString(cmds, at + 8, 16) === "__TEXT") textVmaddr = u64(dv, at + 24);
            const nsects = dv.getUint32(at + 64, true);
            for (let s = 0; s < nsects; s++) {
                const sec = at + SEGMENT_COMMAND_64_BYTES + s * SECTION_64_BYTES;
                if (sec + SECTION_64_BYTES > at + cmdsize) break;
                raw.push({ sectname: fixedString(cmds, sec, 16), segname: fixedString(cmds, sec + 16, 16),
                           addr: u64(dv, sec + 32), size: u64(dv, sec + 40) });
            }
        }
        at += cmdsize;
    }
    const base = textVmaddr ?? 0;
    const sections = raw.filter((r) => r.addr >= base && r.size >= 0)
        .map((r) => ({ segname: r.segname, sectname: r.sectname, offset: r.addr - base, size: r.size }));
    return { uuid, sections };
}

/** Runtime [address, size) of one section of a loaded image. */
export interface SectionRange { base: NativePointer; size: number; }

type SectionModule = CacheModule & Partial<Pick<Module, "enumerateSections">>;

const sectionKey = (segname: string, sectname: string) => `${segname},${sectname}`;

/** One loaded Mach-O image: load commands parsed once, sections resolved on first use. */
class MachOImage {
    private sections: Map<string, SectionRange> | null = null;

    constructor(private readonly mod: SectionModule, private readonly commands: MachOLoadCommands) {}

    get uuid(): string | null { return this.commands.uuid; }

    section(segname: string, sectname: string): SectionRange | null {
        if (this.sections === null) this.sections = sectionsFromFrida(this.mod) ?? this.sectionsFromLoadCommands();
        return this.sections.get(sectionKey(segname, sectname)) ?? null;
    }

    private sectionsFromLoadCommands(): Map<string, SectionRange> {
        const map = new Map<string, SectionRange>();
        for (const s of this.commands.sections) {
            if (s.size > 0) map.set(sectionKey(s.segname, s.sectname), { base: this.mod.base.add(s.offset), size: s.size });
        }
        return map;
    }
}

/** Frida's sections keyed "SEG,sect", or null when Frida cannot enumerate them. */
function sectionsFromFrida(mod: SectionModule): Map<string, SectionRange> | null {
    try {
        if (typeof mod.enumerateSections !== "function") return null;
        const map = new Map<string, SectionRange>();
        for (const s of mod.enumerateSections()) {
            // Frida ids look like "<index>.<segment>.<section>".
            const segname = s.id.split(".")[1] ?? "";
            if (s.size > 0) map.set(sectionKey(segname, s.name), { base: s.address, size: s.size });
        }
        return map;
    } catch (_e) {
        return null;
    }
}

const imageByMapping = new Map<string, MachOImage | null>();

/** The Mach-O image of `mod`, parsed once per loaded mapping; null when it is not Mach-O 64. */
function machOImage(mod: SectionModule): MachOImage | null {
    return memoizePerMapping(imageByMapping, mod, () => {
        const commands = parseMachOLoadCommands(moduleMemoryReader(mod.base));
        return commands === null ? null : new MachOImage(mod, commands);
    });
}

/** LC_UUID of the Mach-O module as 32 lowercase hex chars, or null. */
export function moduleMachOUuid(mod: CacheModule): string | null {
    return machOImage(mod)?.uuid ?? null;
}

/** True when the module is a readable Mach-O 64 (unreadable reads as false). */
export function isMachOModule(mod: SectionModule): boolean {
    return machOImage(mod) !== null;
}

/**
 * Runtime range of segname,sectname in `mod`: Module.enumerateSections() where
 * Frida has it, else the image's own load commands.
 */
export function machOSectionRange(mod: SectionModule, segname: string, sectname: string): SectionRange | null {
    return machOImage(mod)?.section(segname, sectname) ?? null;
}
