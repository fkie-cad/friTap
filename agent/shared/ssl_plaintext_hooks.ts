// agent/shared/ssl_plaintext_hooks.ts
//
// The plaintext SSL_read / SSL_write / SSL_read_ex / SSL_write_ex hooks of the class-based
// OpenSSL/BoringSSL hookers. Shared by both copies of that class — agent/tls/libs/
// openssl_boringssl.ts (Linux, Windows, macOS, iOS) and agent/legacy/tls/libs/
// openssl_boringssl.ts (Android: libssl, Conscrypt) — so both get the same SSL-scoped,
// DEFERRED fd attribution (see shared/socket_fd_tracker.ts):
//   * an SSL object with a socket fd is attributed in onEnter, as always;
//   * an fd-less one (custom/memory BIO: curl connection filters, Conscrypt) opens an SSL
//     scope in onEnter (fdOrDeferred) and is attributed in onLeave via recoveredFd(ssl),
//     which is called on EVERY return path so the scope is always popped.

import { enable_default_fd } from "../fritap_agent.js";
import { devlog_error } from "../util/log.js";
import { sendDatalog } from "./shared_structures.js";
import { fdOrDeferred, recoveredFd, installSslScopeHooks } from "./socket_fd_tracker.js";
import { buildRecordMessage } from "./record_message.js";
import { bytesWrittenFromRetval, bytesWrittenFromOutParam } from "./write_length.js";

/** The hooker state the plaintext hooks read (an OpenSSL_BoringSSL instance). */
export interface SslPlaintextHost {
    moduleName: string;
    module_name: string;
    /** True when the library was hooked at startup (not via a later dlopen). */
    is_base_hook: boolean;
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    SSL_get_fd: any;
    SSL_get_session: any;
    SSL_SESSION_get_id: any;
    getSslSessionId(ssl: NativePointer): string | number;
}

/** Replacement plaintext pushed from the host (readmod / writemod messages). */
export interface PlaintextModifications {
    readonly readmod: ArrayBuffer | null;
    readonly writemod: ArrayBuffer | null;
}

export class SslPlaintextHooks {
    /**
     * @param useBioGetFd rebind SSL_get_fd to BIO_get_fd when falling back to the
     *                    init_addresses module (Apple's libboringssl only).
     */
    constructor(private readonly host: SslPlaintextHost,
                private readonly modifications: PlaintextModifications,
                private readonly useBioGetFd: boolean) { }

    /**
     * Peer/session metadata for one plaintext record, or null when it cannot be
     * attributed (no usable fd and no --enable_default_fd, or a non-IP socket).
     */
    buildMessage(fd: number, isRead: boolean, ssl: NativePointer, functionName: string): any | null {
        if (fd < 0 && !enable_default_fd) return null;
        const host = this.host;
        return buildRecordMessage(
            { fd, isRead, functionName, methodAddresses: host.addresses[host.module_name], enableDefaultFd: enable_default_fd },
            () => ({ ssl_session_id: host.getSslSessionId(ssl) }),
        );
    }

    /**
     * SSL_get_fd for the write hooks, or -1 if the call threw. On a throw outside the
     * base hook, rebinds the SSL helpers from the fallback (init_addresses) module.
     */
    writeSslFd(ssl: NativePointer, isBaseHook: boolean): number {
        try {
            return this.host.SSL_get_fd(ssl);
        } catch (error) {
            if (!isBaseHook) {
                this.rebindFromFallback();
            } else if (error instanceof Error) {
                devlog_error("Error: " + error.message);
                devlog_error("Stack: " + error.stack);
            } else {
                devlog_error("Unexpected error: " + error);
            }
            return -1;
        }
    }

    /**
     * Rebind the SSL helpers to the first base-hooked module's addresses. Never throws:
     * with no usable fallback the helpers stay as they are (this record falls back to
     * deferred attribution instead of being lost to an exception in onEnter).
     */
    private rebindFromFallback(): void {
        const host = this.host;
        const fallback = (globalThis as any).init_addresses ?? {};
        const firstKey = Object.keys(fallback)[0];
        const base = firstKey === undefined ? undefined : fallback[firstKey];
        const fdFunction = this.useBioGetFd ? "BIO_get_fd" : "SSL_get_fd";
        if (!base || !base[fdFunction] || !base["SSL_SESSION_get_id"] || !base["SSL_get_session"]) {
            devlog_error(`SSL_get_fd failed in ${host.moduleName} and no base-hook fallback is available`);
            return;
        }
        host.SSL_SESSION_get_id = new NativeFunction(base["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
        host.SSL_get_fd = new NativeFunction(base[fdFunction], "int", ["pointer"]);
        host.SSL_get_session = new NativeFunction(base["SSL_get_session"], "pointer", ["pointer"]);
    }

    /**
     * Scope SSL_do_handshake/SSL_connect/SSL_accept for fd-less SSL objects and forget an
     * SSL's fd on SSL_free. Idempotent per address.
     */
    installScopeHooks(): void {
        installSslScopeHooks(this.host.moduleName, (ssl: NativePointer) => {
            try { return this.host.SSL_get_fd(ssl) as number; } catch (e) { return -1; }
        });
    }

    /** SSL_read(ssl, buf, num) -> bytes read. */
    attachRead(address: NativePointer, functionName = "SSL_read"): void {
        const hooks = this;
        Interceptor.attach(address, {
            onEnter(args: any) {
                this.bufLen = args[2].toInt32();
                this.buf = args[1];
                const fd = fdOrDeferred(hooks.host.SSL_get_fd(args[0]), args[0]);
                if (fd === null) {
                    // No socket fd on the SSL object: attribute in onLeave, after this
                    // SSL_read did its own recv() (if any) on this thread.
                    this.deferredSsl = args[0];
                    return;
                }
                this.message = hooks.buildMessage(fd, true, args[0], functionName);
            },
            onLeave(retval: any) {
                // Deferred: always close the SSL scope, even for a failed call.
                const recovered = this.deferredSsl ? recoveredFd(this.deferredSsl) : -1;
                let length = retval.toInt32();
                if (length <= 0) return;
                if (this.deferredSsl) {
                    this.message = hooks.buildMessage(recovered, true, this.deferredSsl, functionName);
                }
                if (!this.message) return;
                const readmod = hooks.modifications.readmod;
                if (readmod !== null) {
                    this.buf.writeByteArray(new Uint8Array(this.bufLen)); // NULL out the buffer
                    this.buf.writeByteArray(readmod);
                    length = readmod.byteLength;
                }
                sendDatalog(this.message, this.buf.readByteArray(length));
            },
        });
    }

    /**
     * SSL_write(ssl, buf, num) -> bytes written. The record is emitted in onLeave with
     * min(num, retval) bytes, so a partial write never duplicates plaintext (the app
     * retries with the remainder). The caller owns `buf` for the whole synchronous call.
     */
    attachWrite(address: NativePointer, functionName = "SSL_write"): void {
        const hooks = this;
        Interceptor.attach(address, {
            onEnter(args: any) {
                if (!hooks.prepareWrite(this, args, functionName)) return;
                this.len = args[2].toInt32();
            },
            onLeave(retval: any) {
                hooks.emitWrite(this, bytesWrittenFromRetval(this.len, retval.toInt32()), functionName);
            },
        });
    }

    /** SSL_read_ex(ssl, buf, num, *readbytes) -> 1 on success. */
    attachReadEx(address: NativePointer, functionName = "SSL_read_ex"): void {
        const hooks = this;
        Interceptor.attach(address, {
            onEnter(args: any) {
                this.buf = args[1];
                this.readbytes_ptr = args[3];
                const fd = fdOrDeferred(hooks.host.SSL_get_fd(args[0]), args[0]);
                if (fd === null) {
                    this.deferredSsl = args[0]; // attribute in onLeave (see attachRead)
                    return;
                }
                this.message = hooks.buildMessage(fd, true, args[0], functionName);
            },
            onLeave(retval: any) {
                // Deferred: always close the SSL scope, even for a failed call.
                const recovered = this.deferredSsl ? recoveredFd(this.deferredSsl) : -1;
                // On failure *readbytes is not meaningful.
                if (retval.toInt32() <= 0) return;
                if (this.deferredSsl) {
                    this.message = hooks.buildMessage(recovered, true, this.deferredSsl, functionName);
                }
                if (!this.message) return;
                const actualBytes = this.readbytes_ptr.readULong();
                if (actualBytes <= 0) return;
                sendDatalog(this.message, this.buf.readByteArray(actualBytes));
            },
        });
    }

    /** SSL_write_ex(ssl, buf, num, *written) -> 1 on success; emits *written bytes in onLeave. */
    attachWriteEx(address: NativePointer, functionName = "SSL_write_ex"): void {
        const hooks = this;
        Interceptor.attach(address, {
            onEnter(args: any) {
                if (!hooks.prepareWrite(this, args, functionName)) return;
                this.len = args[2].toInt32();
                this.writtenPtr = args[3];
            },
            onLeave(retval: any) {
                const count = bytesWrittenFromOutParam(this.len, retval.toInt32(), this.writtenPtr);
                hooks.emitWrite(this, count, functionName);
            },
        });
    }

    /**
     * onEnter of a write hook: resolves the fd (or opens a deferred SSL scope), applies a
     * writemod replacement and remembers the buffer. Returns false when the record cannot
     * be attributed (nothing to emit in onLeave).
     */
    private prepareWrite(call: any, args: any, functionName: string): boolean {
        const ssl = args[0];
        const fd = fdOrDeferred(this.writeSslFd(ssl, this.host.is_base_hook), ssl);
        if (fd === null) {
            // No socket fd on the SSL object: attribute in onLeave, after this write sent
            // its record on this thread — so even a connection's first write is recovered.
            call.deferredSsl = ssl;
        } else {
            call.message = this.buildMessage(fd, false, ssl, functionName);
            if (call.message === null) return false;
        }
        const writemod = this.modifications.writemod;
        if (writemod !== null) {
            // Kept on the invocation context: a local would be collectable while the
            // library still reads it (and onLeave reads it again for the record).
            call.replacement = Memory.alloc(writemod.byteLength);
            call.replacement.writeByteArray(writemod);
            args[1] = call.replacement;
            args[2] = new NativePointer(writemod.byteLength);
        }
        call.buf = args[1];
        return true;
    }

    /** onLeave of a write hook: emits `count` bytes (0 = failed call, retried by the app). */
    private emitWrite(call: any, count: number, functionName: string): void {
        // Deferred: always close the SSL scope, even for a failed call.
        const recovered = call.deferredSsl ? recoveredFd(call.deferredSsl) : -1;
        if (count <= 0) return;
        const message = call.deferredSsl
            ? this.buildMessage(recovered, false, call.deferredSsl, functionName)
            : call.message;
        if (!message) return;
        sendDatalog(message, call.buf.readByteArray(count));
    }
}
