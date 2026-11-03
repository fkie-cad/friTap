// agent/shared/write_length.ts
//
// How many plaintext bytes a hooked TLS write call actually consumed.
//
// A write record must carry only the bytes the library accepted, never the requested
// length: with partial writes (SSL_MODE_ENABLE_PARTIAL_WRITE, mbedtls fragmenting, a
// non-blocking send) the app calls again with the REMAINING bytes, so emitting the full
// request each time duplicates plaintext in the capture.

/**
 * SSL_write-style call (returns the byte count, <= 0 on failure): min(requested, retval),
 * or 0 when the call failed.
 */
export function bytesWrittenFromRetval(requested: number, retval: number): number {
    if (!(retval > 0) || !(requested > 0)) return 0;
    return Math.min(requested, retval);
}

/**
 * SSL_write_ex-style call (returns 1 on success and stores the count in *written):
 * min(requested, *written), or 0 when the call failed. A NULL `written` pointer
 * (not allowed by the API, but tolerated) falls back to the requested length.
 */
export function bytesWrittenFromOutParam(requested: number, succeeded: number, written: NativePointer | null | undefined): number {
    if (!(succeeded > 0) || !(requested > 0)) return 0;
    if (!written || written.isNull()) return requested;
    // size_t on every supported target is little-endian; lengths fit in the low 32 bits.
    return Math.min(requested, written.readU32());
}
