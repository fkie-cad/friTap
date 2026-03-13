// agent/tls/decoders/hex_utils.ts
//
// Shared hex-encoding utilities extracted from per-library duplicated code.

import { toHexString } from "../../shared/shared_functions.js";

/**
 * Read `length` bytes from a NativePointer and return an uppercase hex string.
 * Delegates to the pre-built lookup-table based toHexString for O(n) performance.
 */
export function readHexFromPointer(ptr: NativePointer, length: number): string {
    if (length <= 0) return "";
    return toHexString(ptr.readByteArray(length)).toUpperCase();
}

/**
 * Read a GnuTLS datum_t (pointer + uint length at pointer_size offset)
 * and return the data as an uppercase hex string.
 */
export function readGnuTlsDatum(datum: NativePointer): string {
    const len = datum.add(Process.pointerSize).readUInt();
    const p = datum.readPointer();
    return readHexFromPointer(p, len);
}
