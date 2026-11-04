// agent/shared/write_hooks.ts
//
// Interceptor wiring of the SSL_read/SSL_write-style plaintext hooks in the older hooker
// classes (agent/tls/libs + agent/legacy/tls/libs: wolfSSL_write, gnutls_record_send,
// NSS PR_Write, Cronet's SSL_read/SSL_write). onEnter only remembers the call's arguments;
// onLeave emits only the bytes the call actually transferred (write_length.ts) — never the
// requested length, which duplicates plaintext on a partial write or a would-block retry —
// and builds the record metadata only then, so failed / would-block calls cost nothing.

import { sendDatalog } from "./shared_structures.js";
import { BufferedSendTracker, writtenPayload } from "./write_length.js";

/** The (ctx, buf, len) arguments of one hooked call, captured at onEnter. */
export type PlaintextCallArgs = readonly [ctx: NativePointer, buf: NativePointer, len: NativePointer];

/**
 * Peer/session metadata of one record, or null when it cannot be attributed (no fd,
 * not a socket, loopback IPC...). Runs in onLeave: the ctx/fd is still valid there.
 */
export type PlaintextMessageBuilder = (args: PlaintextCallArgs) => { [key: string]: any } | null;

const CTX_ARG = 0;
const BUF_ARG = 1;
const LEN_ARG = 2;

function captureArgs(args: InvocationArguments): PlaintextCallArgs {
    return [args[CTX_ARG], args[BUF_ARG], args[LEN_ARG]];
}

/**
 * Hook write(ctx, buf, len) -> bytes written (<= 0 on failure / would-block) at `address`.
 * With `buffered`, a would-block call's plaintext is attributed to the later call that
 * flushes it, even when that call passes NULL/0 (gnutls_record_send).
 *
 * Integer widths: `len` is read UNSIGNED (low 32 bits; the arg is size_t or a C int whose
 * register upper half is undefined) because it is only ever an upper bound of the return
 * value. The return value is read SIGNED: it carries the error codes (-1, GNUTLS_E_AGAIN,
 * ...), and a negative return must never become a huge byte count. A negative int `len`
 * (e.g. PR_Write's PRInt32 amount) makes the call fail with a negative return, so nothing
 * is emitted either way.
 */
export function attachPlaintextWriteHook(address: NativePointer, buildMessage: PlaintextMessageBuilder,
                                         buffered?: BufferedSendTracker): InvocationListener {
    return Interceptor.attach(address, {
        onEnter(args: InvocationArguments) {
            this.call = captureArgs(args);
        },
        onLeave(retval: InvocationReturnValue) {
            const [ctx, buf, len] = this.call as PlaintextCallArgs;
            const payload = writtenPayload(buf, len.toUInt32(), retval.toInt32(), ctx, buffered);
            if (payload !== null) emitRecord(this.call, buildMessage, payload);
        },
    });
}

/**
 * Hook read(ctx, buf, len) -> bytes decrypted into buf (<= 0 on failure / would-block) at
 * `address`: emits exactly the returned byte count (signed 32-bit, see the write hook).
 */
export function attachPlaintextReadHook(address: NativePointer, buildMessage: PlaintextMessageBuilder): InvocationListener {
    return Interceptor.attach(address, {
        onEnter(args: InvocationArguments) {
            this.call = captureArgs(args);
        },
        onLeave(retval: InvocationReturnValue) {
            const count = retval.toInt32();
            if (count <= 0) return;
            emitRecord(this.call, buildMessage, this.call[BUF_ARG].readByteArray(count));
        },
    });
}

function emitRecord(call: PlaintextCallArgs, buildMessage: PlaintextMessageBuilder, payload: ArrayBuffer | null): void {
    if (payload === null) return;
    const message = buildMessage(call);
    if (message) sendDatalog(message, payload);
}
