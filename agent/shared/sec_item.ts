// agent/shared/sec_item.ts
//
// Guarded reader for an NSS SECItem { SECItemType type; unsigned char *data; unsigned int len; }:
// `data` at +pointerSize, `len` (u32) at +2*pointerSize. Every read is range-checked first,
// because a native fault inside a hook callback is not catchable by JS try/catch.

import { isReadable } from "../util/safe_memory.js";

/** The `data`/`len` pair of a SECItem whose bytes are readable. */
export interface SecItemView {
    data: NativePointer;
    len: number;
}

/**
 * `data`/`len` of the SECItem at `item`, or null when the pointer is NULL, the header or the
 * `len` bytes at `data` are unreadable, or `len` is 0. Never throws.
 */
export function readSecItemView(item: NativePointer): SecItemView | null {
    try {
        if (item.isNull() || !isReadable(item, Process.pointerSize * 2 + 4)) return null;
        const data = item.add(Process.pointerSize).readPointer();
        const len = item.add(Process.pointerSize * 2).readU32();
        if (len === 0 || data.isNull() || !isReadable(data, len)) return null;
        return { data, len };
    } catch (_e) {
        return null;
    }
}
