// agent/shared/matrixssl_plaintext.ts
//
// MatrixSSL plaintext capture, shared by agent/tls/definitions/matrixssl.ts and both
// matrix_SSL hooker classes (agent/tls/libs, agent/legacy/tls/libs).
//
// MatrixSSL API (matrixsslApi.h):
//   int32 matrixSslGetWritebuf(ssl_t *ssl, unsigned char **buf, uint32 reqLen);
//         -> bytes available in *buf, < 0 on error
//   int32 matrixSslEncodeWritebuf(ssl_t *ssl, uint32 len);
//         -> encodes the first `len` plaintext bytes the app put into *buf
//   int32 matrixSslReceivedData(ssl_t *ssl, uint32 bytes, unsigned char **ptbuf, uint32 *ptlen);
//   int32 matrixSslProcessedData(ssl_t *ssl, unsigned char **ptbuf, uint32 *ptlen);
//         -> MATRIXSSL_APP_DATA when *ptbuf / *ptlen hold decrypted application data
//            (ProcessedData returns the NEXT record already received, if any)

/** matrixSslReceivedData / matrixSslProcessedData status: *ptbuf holds app data. */
export const MATRIXSSL_APP_DATA = 4;

/** Decrypted app data from the (ptbuf, ptlen) out-params, or null if the call returned none. */
export function receivedPlaintext(status: number, ptbufOut: NativePointer, ptlenOut: NativePointer): ArrayBuffer | null {
    if (status !== MATRIXSSL_APP_DATA) return null;
    if (!ptbufOut || ptbufOut.isNull() || !ptlenOut || ptlenOut.isNull()) return null;
    const length = ptlenOut.readU32();
    if (length === 0) return null;
    const plaintext = ptbufOut.readPointer();
    if (plaintext.isNull()) return null;
    return plaintext.readByteArray(length);
}

/** Bytes matrixSslEncodeWritebuf(ssl, len) encodes from a buffer with `available` bytes. */
export function encodedLength(requested: number, available: number): number {
    if (!(requested > 0) || !(available > 0)) return 0;
    return Math.min(requested, available);
}

/** Emits one plaintext record for `ssl`; the caller builds the message metadata. */
export type MatrixSslEmit = (ssl: NativePointer, data: ArrayBuffer, functionName: string) => void;

function attachReceive(address: NativePointer | undefined, functionName: string, ptbufIndex: number, emit: MatrixSslEmit): void {
    if (!address || address.isNull()) return;
    Interceptor.attach(address, {
        onEnter(args: any) {
            this.ssl = args[0];
            this.ptbufOut = args[ptbufIndex];
            this.ptlenOut = args[ptbufIndex + 1];
        },
        onLeave(retval: any) {
            const data = receivedPlaintext(retval.toInt32(), this.ptbufOut, this.ptlenOut);
            if (data !== null) emit(this.ssl, data, functionName);
        },
    });
}

/** Read side: matrixSslReceivedData plus matrixSslProcessedData (later records of one read). */
export function hookMatrixSslReads(receivedData: NativePointer | undefined, processedData: NativePointer | undefined, emit: MatrixSslEmit): void {
    attachReceive(receivedData, "matrixSslReceivedData", 2, emit);
    attachReceive(processedData, "matrixSslProcessedData", 1, emit);
}

/**
 * Write side: matrixSslGetWritebuf hands out the buffer (via `unsigned char **`), the app
 * fills it, and matrixSslEncodeWritebuf(ssl, len) commits the first `len` bytes. Per-thread
 * state: both calls run back-to-back on the same thread per MatrixSSL's documented usage.
 */
export function hookMatrixSslWrites(getWritebuf: NativePointer | undefined, encodeWritebuf: NativePointer | undefined, emit: MatrixSslEmit): void {
    if (!getWritebuf || getWritebuf.isNull() || !encodeWritebuf || encodeWritebuf.isNull()) return;
    const pending = new Map<number, { buffer: NativePointer, available: number }>();
    Interceptor.attach(getWritebuf, {
        onEnter(args: any) {
            this.bufOut = args[1];
        },
        onLeave(retval: any) {
            const available = retval.toInt32();
            if (available <= 0 || !this.bufOut || this.bufOut.isNull()) return;
            const buffer = this.bufOut.readPointer();
            if (buffer.isNull()) return;
            pending.set(Process.getCurrentThreadId(), { buffer, available });
        },
    });
    Interceptor.attach(encodeWritebuf, {
        onEnter(args: any) {
            const tid = Process.getCurrentThreadId();
            const state = pending.get(tid);
            if (state === undefined) return;
            pending.delete(tid);
            const length = encodedLength(args[1].toUInt32(), state.available);
            if (length > 0) emit(args[0], state.buffer.readByteArray(length)!, "matrixSslEncodeWritebuf");
        },
    });
}
