// agent/util/darwin_vm_region.ts
//
// Single-address memory-region lookup for Darwin via mach_vm_region_recurse.
// Frida's Process.findRangeByAddress enumerates every range of the process
// (measured 42 ms per call on Chrome 157, ~2.5k regions), which starves a hot
// hook such as QUICHE's per-frame callbacks; one kernel call costs ~3 µs.
//
// Not plain mach_vm_region: it does not descend into submaps, so a dyld shared
// cache address answers the whole nested shared-region entry (GBs, with holes)
// and that entry's protection instead of the leaf mapping's.

/** A mapped region: [base, end) with its VM_PROT_* bits. */
export interface VmRegion { base: NativePointer; end: NativePointer; protection: number; }

export const VM_PROT_READ = 1;
export const VM_PROT_WRITE = 2;
export const VM_PROT_EXECUTE = 4;

// Short flavor (sizeof(vm_region_submap_short_info_64) / 4 = 48 / 4): the full
// one counts resident pages, measured 73 µs vs 4 µs on a 26 MB __DATA region.
const VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 = 12;
const SUBMAP_INFO_IS_SUBMAP_OFFSET = 32;
const KERN_SUCCESS = 0;
const KERN_INVALID_ADDRESS = 1;   // no region at or after the address
// The shared region nests one level; the cap only guards against a kernel loop.
const MAX_SUBMAP_DEPTH = 8;

type MachVmRegionRecurseFn = (task: number, address: NativePointer, size: NativePointer,
                              depth: NativePointer, info: NativePointer, count: NativePointer) => number;

interface Lookup { fn: MachVmRegionRecurseFn; task: number; address: NativePointer; size: NativePointer;
                   depth: NativePointer; info: NativePointer; count: NativePointer; }

/** One kernel answer at a given nesting depth. */
export interface RegionAnswer extends VmRegion { isSubmap: boolean; }

/**
 * mach_vm_region_recurse answers the region AT OR AFTER the address; true when
 * the answered [base, end) actually contains it.
 */
export function regionContains(address: NativePointer, base: NativePointer, end: NativePointer): boolean {
    return address.compare(base) >= 0 && address.compare(end) < 0;
}

/**
 * Descend through submaps to the leaf region containing `address`. `query(depth)`
 * is one kernel call: an answer, null for "nothing at or after", undefined on any
 * other failure. Returns the leaf, null when unmapped, undefined when the caller
 * must fall back (kernel failure or depth cap).
 */
export function resolveLeafRegion(address: NativePointer,
                                  query: (depth: number) => RegionAnswer | null | undefined): VmRegion | null | undefined {
    for (let depth = 0; depth <= MAX_SUBMAP_DEPTH; depth++) {
        const answer = query(depth);
        if (answer === undefined) return undefined;
        if (answer === null || !regionContains(address, answer.base, answer.end)) return null;
        if (!answer.isSubmap) return { base: answer.base, end: answer.end, protection: answer.protection };
    }
    return undefined;
}

let lookup: Lookup | null | undefined;

function initLookup(): Lookup | null {
    if (Process.platform !== "darwin") return null;
    try {
        const fnAddr = Module.findGlobalExportByName("mach_vm_region_recurse");
        const taskAddr = Module.findGlobalExportByName("mach_task_self_");
        if (fnAddr === null || taskAddr === null) return null;
        // exclusive: the scratch buffers below are shared, so keep the JS lock across the call.
        const fn = new NativeFunction(fnAddr, "int",
            ["uint", "pointer", "pointer", "pointer", "pointer", "pointer"],
            { scheduling: "exclusive" }) as unknown as MachVmRegionRecurseFn;
        return { fn, task: taskAddr.readU32(), address: Memory.alloc(8), size: Memory.alloc(8),
                 depth: Memory.alloc(4), info: Memory.alloc(VM_REGION_SUBMAP_SHORT_INFO_COUNT_64 * 4),
                 count: Memory.alloc(4) };
    } catch (_e) {
        return null;
    }
}

function queryAtDepth(l: Lookup, address: NativePointer, depth: number): RegionAnswer | null | undefined {
    l.address.writePointer(address);   // re-query the original address at each depth
    l.depth.writeU32(depth);
    l.count.writeU32(VM_REGION_SUBMAP_SHORT_INFO_COUNT_64);
    const kr = l.fn(l.task, l.address, l.size, l.depth, l.info, l.count);
    if (kr === KERN_INVALID_ADDRESS) return null;
    if (kr !== KERN_SUCCESS) return undefined;
    const base = l.address.readPointer();
    return { base, end: base.add(l.size.readU64()), protection: l.info.readS32(),
             isSubmap: l.info.add(SUBMAP_INFO_IS_SUBMAP_OFFSET).readU32() !== 0 };
}

/**
 * The leaf region containing `address`: a VmRegion, `null` when it is unmapped,
 * or `undefined` when the kernel lookup is unavailable or failed (not Darwin,
 * missing export, kernel error) so the caller falls back to
 * Process.findRangeByAddress.
 */
export function findDarwinRegion(address: NativePointer): VmRegion | null | undefined {
    if (lookup === undefined) lookup = initLookup();
    if (lookup === null) return undefined;
    const l = lookup;
    try {
        return resolveLeafRegion(address, (depth) => queryAtDepth(l, address, depth));
    } catch (_e) {
        return undefined;
    }
}
