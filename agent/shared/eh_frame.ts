// agent/shared/eh_frame.ts
//
// Function boundaries of a loaded ELF module from its in-memory .eh_frame_hdr
// binary-search table (PT_GNU_EH_FRAME). Stripped builds (Chrome's
// libmonochrome, Cronet) keep this table for C++ unwinding, so it bounds every
// function without symbols. Used by the anchor-based locators
// (tls/shared/boringssl_plaintext_locator.ts, quic/shared/quiche_frame_locator.ts),
// which share one table per module through ehFrameTableFor().

const PT_LOAD = 1;
const PT_GNU_EH_FRAME = 0x6474e550;
const DW_EH_PE_udata4 = 0x03;
const DW_EH_PE_datarel_sdata4 = 0x3b;

/** Index of the last sorted table entry whose start is <= addr, or -1. */
export function searchSortedStarts(count: number, startAt: (i: number) => number, addr: number): number {
    let lo = 0, hi = count - 1, found = -1;
    while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (startAt(mid) <= addr) { found = mid; lo = mid + 1; } else { hi = mid - 1; }
    }
    return found;
}

/** [start, end) of a function; end is null when its FDE is not decodable. */
export interface FunctionBounds { start: NativePointer; end: NativePointer | null; }

/** Function boundaries from a module's in-memory .eh_frame_hdr binary-search table. */
export class EhFrameFunctionTable {
    private constructor(private readonly hdr: NativePointer, private readonly count: number) {}

    static fromModule(mod: Module): EhFrameFunctionTable | null {
        try {
            const hdr = ehFrameHdrOf(mod.base);
            if (hdr === null) return null;
            const [version, countEnc, tableEnc] = [hdr.readU8(), hdr.add(2).readU8(), hdr.add(3).readU8()];
            if (version !== 1 || countEnc !== DW_EH_PE_udata4 || tableEnc !== DW_EH_PE_datarel_sdata4) return null;
            const count = hdr.add(8).readU32();
            return count > 0 ? new EhFrameFunctionTable(hdr, count) : null;
        } catch (_e) {
            return null;
        }
    }

    private entryStart(i: number): number {
        return this.hdr.add(12 + i * 8).readS32();        // relative to hdr (datarel)
    }

    /** Bounds of the function containing `addr`, or null when no FDE covers it. */
    bounds(addr: NativePointer): FunctionBounds | null {
        try {
            const rel = addr.sub(this.hdr).toInt32();
            const i = searchSortedStarts(this.count, (k) => this.entryStart(k), rel);
            if (i < 0) return null;
            const start = this.hdr.add(this.entryStart(i));
            const end = this.fdeEnd(i, start);
            if (end !== null && addr.compare(end) >= 0) return null;   // not covered: missing FDE
            return { start, end };
        } catch (_e) {
            return null;
        }
    }

    /** FDE: u32 length, s32 CIE pointer, pc_begin (pcrel sdata4), pc_range. */
    private fdeEnd(i: number, start: NativePointer): NativePointer | null {
        const fde = this.hdr.add(this.hdr.add(12 + i * 8 + 4).readS32());
        const pcBeginField = fde.add(8);
        if (fde.readU32() === 0xffffffff || !pcBeginField.add(pcBeginField.readS32()).equals(start)) return null;
        return start.add(fde.add(12).readU32());
    }
}

/** Address of the module's .eh_frame_hdr (64-bit ELF program headers), or null. */
function ehFrameHdrOf(base: NativePointer): NativePointer | null {
    if (base.readU32() !== 0x464c457f) return null;             // "\x7fELF"
    const phoff = base.add(0x20).readU64().toNumber();
    const phentsize = base.add(0x36).readU16();
    const phnum = base.add(0x38).readU16();
    let ehVaddr = -1, minLoad = Number.MAX_SAFE_INTEGER;
    for (let i = 0; i < phnum; i++) {
        const ph = base.add(phoff + i * phentsize);
        const type = ph.readU32();
        const vaddr = ph.add(0x10).readU64().toNumber();
        if (type === PT_LOAD) minLoad = Math.min(minLoad, vaddr);
        if (type === PT_GNU_EH_FRAME) ehVaddr = vaddr;
    }
    if (ehVaddr < 0 || minLoad === Number.MAX_SAFE_INTEGER) return null;
    return base.add(ehVaddr - (minLoad - (minLoad % 0x1000)));
}

const tablesByModule = new Map<string, EhFrameFunctionTable | null>();

/** The module's function table, built once per loaded module (name + base + size). */
export function ehFrameTableFor(mod: Module): EhFrameFunctionTable | null {
    const key = `${mod.name}@${mod.base}+${mod.size}`;
    if (!tablesByModule.has(key)) tablesByModule.set(key, EhFrameFunctionTable.fromModule(mod));
    return tablesByModule.get(key)!;
}
