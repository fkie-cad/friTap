// agent/shared/nss_layout_constants.ts
//
// Layout facts and acceptance rules shared by the three NSS keylog-writer
// backends (nss_keylog_backend_{arm64,x64,arm}.ts). Pure: unit-tested under Node.

import type { ModuleByteReader } from "./module_mapping.js";
import type { NssWriterDecode } from "./nss_keylog_locator.js";

/** The hex digit table the writer indexes to hex-encode client_random and the secret. */
export const NSS_HEX_TABLE = "0123456789abcdef";
/** Decode window when the function's end is unknown (the 3.132 writers are 292..420 bytes). */
export const WRITER_DECODE_CAP_BYTES = 2048;
/** Plausible `ss + imm` for sslSocket.ssl3.hs.client_random: [0x100, 0x2000]. */
export const CLIENT_RANDOM_OFF_MIN = 0x100;
export const CLIENT_RANDOM_OFF_MAX = 0x2000;

/**
 * True for an immediate the writer may add to `ss` to reach client_random:
 * inside [CLIENT_RANDOM_OFF_MIN, CLIENT_RANDOM_OFF_MAX] and `align`-aligned
 * (8 on 64-bit ABIs, 4 on arm32). Not the hook-time learner's wider check.
 */
export function isPlausibleWriterClientRandomOffset(imm: number, align: number): boolean {
    return imm >= CLIENT_RANDOM_OFF_MIN && imm <= CLIENT_RANDOM_OFF_MAX && imm % align === 0;
}

/** True when the bytes at `addr` read "0123456789abcdef" (matched by CONTENT: libnss3 has several copies). */
export function readsHexTable(read: ModuleByteReader, addr: number): boolean {
    const bytes = read(addr, NSS_HEX_TABLE.length);
    return bytes !== null && bytes.length === NSS_HEX_TABLE.length && String.fromCharCode(...bytes) === NSS_HEX_TABLE;
}

/** The decoders' acceptance rule: the hex table was referenced and exactly ONE distinct offset was seen. */
export function singleOffset(hexTableSeen: boolean, offsets: Set<number>): NssWriterDecode | null {
    if (!hexTableSeen || offsets.size !== 1) return null;
    return { clientRandomOff: [...offsets][0] };
}

/** Per label (index-aligned), each item resolved to a callee; unresolved items are dropped. */
export function calleesPerLabel<S>(perLabel: S[][], resolve: (item: S) => NativePointer | null): NativePointer[][] {
    return perLabel.map((items) => items
        .map((item) => resolve(item))
        .filter((p): p is NativePointer => p !== null));
}

/** Module offsets inside [0, mod.size) as addresses; anything outside the image is dropped. */
export function addressesInModule(mod: Pick<Module, "base" | "size">, offsets: number[]): NativePointer[] {
    return offsets.filter((off) => off >= 0 && off < mod.size).map((off) => mod.base.add(off));
}
