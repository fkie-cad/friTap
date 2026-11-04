// agent/shared/write_length.ts
//
// How many plaintext bytes a hooked TLS write call actually consumed.
//
// A write record must carry only the bytes the library accepted, never the requested
// length: with partial writes (SSL_MODE_ENABLE_PARTIAL_WRITE, mbedtls fragmenting, a
// non-blocking send) the app calls again with the REMAINING bytes, so emitting the full
// request each time duplicates plaintext in the capture.

import { LruMap } from "./lru.js";

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

/** gnutls_record_send would-block returns: the record is already encrypted and buffered. */
export const GNUTLS_E_AGAIN = -28;
export const GNUTLS_E_INTERRUPTED = -52;
export const GNUTLS_SEND_RETRY_CODES: readonly number[] = [GNUTLS_E_AGAIN, GNUTLS_E_INTERRUPTED];

/** Upper bound of one buffered record copy (a TLS record carries at most 16 KiB plaintext). */
const MAX_PENDING_SEND_BYTES = 64 * 1024;
/** Sessions with a would-block send outstanding at the same time (LRU beyond that). */
const MAX_PENDING_SEND_SESSIONS = 64;

/**
 * Written plaintext of send calls whose library BUFFERS the record on a would-block return
 * and flushes it on a later call — gnutls_record_send: on GNUTLS_E_AGAIN/E_INTERRUPTED the
 * caller retries with the same arguments OR with data=NULL, size=0, and the successful
 * retry returns the byte count of the record buffered by the FIRST call. A bounded
 * per-session copy of that record's plaintext attributes the flush exactly once, whatever
 * the retry passes. Memory: at most 64 sessions x 64 KiB (JS heap, no native buffers).
 */
export class BufferedSendTracker {
    private readonly pending: LruMap<string, ArrayBuffer>;

    constructor(private readonly retryCodes: readonly number[] = GNUTLS_SEND_RETRY_CODES,
                maxSessions = MAX_PENDING_SEND_SESSIONS,
                private readonly maxPendingBytes = MAX_PENDING_SEND_BYTES) {
        this.pending = new LruMap(maxSessions);
    }

    /**
     * onLeave of send(session, buf, requested) -> retval: the plaintext this call actually
     * sent, or null (would-block, failure, nothing readable). Must run for EVERY call.
     */
    settle(session: string, buf: NativePointer | null, requested: number, retval: number): ArrayBuffer | null {
        if (retval > 0) return this.flush(session, buf, requested, retval);
        const pending = this.pending.get(session);
        if (this.retryCodes.indexOf(retval) < 0) {
            this.pending.delete(session); // hard error: the buffered record dies with the session
        } else if (!pending) {
            const copy = readWritten(buf, Math.min(requested, this.maxPendingBytes));
            if (copy) this.pending.set(session, copy);
        }
        return null;
    }

    /** A successful send: the buffered record it flushed, else its own written bytes. */
    private flush(session: string, buf: NativePointer | null, requested: number, retval: number): ArrayBuffer | null {
        // Fast path (no would-block outstanding anywhere): no map lookup / LRU reorder.
        const pending = this.pending.size > 0 ? this.pending.get(session) : undefined;
        if (!pending) return readWritten(buf, bytesWrittenFromRetval(requested, retval));
        this.pending.delete(session);
        // Normally the whole record was flushed: hand out the copy itself, no second copy.
        return retval >= pending.byteLength ? pending : pending.slice(0, retval);
    }

    /** Sessions with a buffered (not yet flushed) record. */
    get size(): number {
        return this.pending.size;
    }
}

/**
 * The plaintext a finished write(ctx, buf, requested) -> retval call actually sent, or null
 * when it sent nothing — the one "emit written bytes" rule of every write hook:
 *  - `buffered` (gnutls_record_send-style would-block buffering): settled per `session`
 *    by the tracker, so a flush is attributed exactly once (BufferedSendTracker);
 *  - otherwise min(requested, retval) bytes of `buf` (bytesWrittenFromRetval). Pass
 *    UNKNOWN_WRITE_LENGTH as `requested` when the call has no length argument and the
 *    return value alone is the count.
 * `session` is stringified only when `buffered` is given.
 */
export function writtenPayload(buf: NativePointer | null, requested: number, retval: number,
                               session?: NativePointer | string, buffered?: BufferedSendTracker): ArrayBuffer | null {
    if (buffered) return buffered.settle(String(session), buf, requested, retval);
    return readWritten(buf, bytesWrittenFromRetval(requested, retval));
}

/** `requested` of a write without a length argument: the return value is the count. */
export const UNKNOWN_WRITE_LENGTH = Number.POSITIVE_INFINITY;

function readWritten(buf: NativePointer | null, count: number): ArrayBuffer | null {
    if (!(count > 0) || !buf || buf.isNull()) return null;
    return buf.readByteArray(count);
}
