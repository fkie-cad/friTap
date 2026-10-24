// agent/shared/libressl_client_random.ts
//
// Shared per-thread client_random store for the LibreSSL *stripped-static* path,
// populated by parsing the plaintext ClientHello out of the outbound socket
// send(). See agent/shared/clienthello_random.ts for why this is necessary
// (client_random is not reachable from any LibreSSL KDF frame) and for the
// ClientHello byte layout. This is the Frida counterpart of the ws2_32!send
// resolver in agent_gdb/wine/gdb_script/gdb_wine_extract.py.
//
// The send() capture is only used on the stripped path (SSL_get_client_random
// unresolved). The dynamic path uses SSL_get_client_random on the SSL* tracked
// per thread by attachHandshakeTracker (also here).

import { extractClientRandomFromHandshake } from "./clienthello_random.js";
import { readHexFromPointer } from "../tls/decoders/hex_utils.js";
import { log, devlog, devlog_error } from "../util/log.js";

// threadId -> client_random hex. The ClientHello send() and the key-schedule run
// on the same thread during a synchronous handshake, so a per-thread key is the
// correct correlation (mirrors Schannel's clientRandomByThread in ncrypt_keylog.ts).
const _crByThread: Map<number, string> = new Map();

let _sendHookInstalled = false;

const _sslCrBuf = Memory.alloc(32);

// threadId -> SSL* of the handshake currently running on that thread, so the
// KDF hooks (which have no SSL* in frame) can ask SSL_get_client_random.
const _handshakeSslByThread: Map<number, NativePointer> = new Map();

/** SSL* of the handshake running on the current thread, if any. */
export function currentHandshakeSsl(): NativePointer | undefined {
    return _handshakeSslByThread.get(Process.getCurrentThreadId());
}

/**
 * Track args[0] (SSL*) for the duration of a handshake entry point. Restores the
 * previous value on leave so nested entry points (e.g. SSL_connect calling
 * SSL_do_handshake) don't clear the outer one.
 */
export function attachHandshakeTracker(addr: NativePointer): void {
    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            const tid = Process.getCurrentThreadId();
            this.prevSsl = _handshakeSslByThread.get(tid);
            _handshakeSslByThread.set(tid, args[0]);
        },
        onLeave: function (_retval: any) {
            const tid = Process.getCurrentThreadId();
            if (this.prevSsl) _handshakeSslByThread.set(tid, this.prevSsl);
            else _handshakeSslByThread.delete(tid);
        },
    });
}

/** client_random for the current thread's handshake, or null if not seen yet. */
export function getLibreSslClientRandom(): string | null {
    return _crByThread.get(Process.getCurrentThreadId()) ?? null;
}

/** client_random of `ssl` via the exported SSL_get_client_random (dynamic path). */
export function readSslClientRandom(
    SSL_get_client_random: NativeFunction<any, any> | null | undefined,
    ssl: NativePointer | undefined,
): string | null {
    if (!SSL_get_client_random || !ssl || ssl.isNull()) return null;
    try {
        const len = SSL_get_client_random(ssl, _sslCrBuf, 32) as number;
        if (len === 32) return readHexFromPointer(_sslCrBuf, 32);
    } catch (e) {
        devlog(`[LibreSSL] SSL_get_client_random error: ${e}`);
    }
    return null;
}

/**
 * client_random for a KDF call on the current thread: SSL_get_client_random on
 * the tracked SSL* (dynamic path), else the ClientHello send() capture.
 */
export function resolveLibreSslClientRandom(
    SSL_get_client_random: NativeFunction<any, any> | null | undefined,
    ssl: NativePointer | undefined,
): string | null {
    return readSslClientRandom(SSL_get_client_random, ssl) ?? getLibreSslClientRandom();
}

/**
 * Hook the outbound socket send() once and capture client_random from the first
 * ClientHello seen on each thread.
 *
 *   ssize_t send(int fd, const void *buf, size_t len, int flags)
 *
 * send() is resolved as a NAMED export (libc `send` on Linux and Wine's unix
 * side; WS2_32.dll!send on native Windows) via findGlobalExportByName — both are
 * native modules of the Frida host platform, so `args[1]`/`args[2]` read the
 * right ABI. (Under Wine the PE ws2_32.dll is not Frida-enumerated; the GDB
 * backend, which is the default for Wine, resolves the PE send itself.)
 */
export function installLibreSslClientRandomViaSend(): void {
    if (_sendHookInstalled) return;

    let sendAddr: NativePointer | null = null;
    try {
        sendAddr = Module.findGlobalExportByName("send");
    } catch (_) {
        sendAddr = null;
    }
    if (!sendAddr || sendAddr.isNull()) {
        devlog("[LibreSSL] send() not resolvable; client_random-via-send unavailable");
        return;
    }

    try {
        Interceptor.attach(sendAddr, {
            onEnter(args: any) {
                try {
                    const cr = extractClientRandomFromHandshake(args[1], args[2].toInt32());
                    if (cr) {
                        _crByThread.set(Process.getCurrentThreadId(), cr);
                        devlog(`[LibreSSL] client_random from send(): ${cr}`);
                    }
                } catch (_) { /* best effort */ }
            },
        });
    } catch (e) {
        devlog_error(`[LibreSSL] failed to hook send(): ${e}`);
        return;
    }

    _sendHookInstalled = true;
    log("[LibreSSL] client_random capture via send() installed (stripped-static path)");
}
