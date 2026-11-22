// agent/quic/shared/quic_ssl_binding.ts
//
// Binds a Google QUICHE connection to the TLS client_random of its handshake.
//
// BoringSSL derives the handshake secrets synchronously inside
// QuicConnection::OnCryptoFrame, on the connection's own thread. So while a
// thread is inside OnCryptoFrame, every SSL* secret event on that thread
// (ssl_log_secret entry, or a keylog line) belongs to that connection, and its
// client_random can be stamped on the connection's records.
//
// Pure logic: the Frida side injects the thread id, the client_random read and
// the tracker binding (see quiche_crypto_binding.ts).

import { normalizeClientRandom } from "../../shared/ssl_identity.js";

/** The connection a thread is processing a CRYPTO frame for. */
export interface CryptoFrameConnection {
    /** QuicConnection* as "0x..." (the tracker's native key). */
    connPtr: string;
    /** The tracker's connection key (with "#<generation>" on address reuse). */
    connKey: string;
}

export interface QuicSslBinderDeps {
    currentThreadId(): number;
    /** client_random of `ssl` (hex), "" when unknown. */
    readClientRandom(ssl: NativePointer, module: string): string;
    /** Attach `clientRandom` (normalised) to the connection; false when it is gone or re-keyed. */
    bind(connPtr: string, connKey: string, clientRandom: string): boolean;
}

export interface QuicSslBinder {
    /** Returns the thread's previous connection, to hand back to leaveCryptoFrame (re-entrancy). */
    enterCryptoFrame(conn: CryptoFrameConnection): CryptoFrameConnection | undefined;
    leaveCryptoFrame(previous?: CryptoFrameConnection): void;
    /** A keylog line carried `clientRandom` for some SSL* (keylog path). */
    onKeylogClientRandom(clientRandom: string): boolean;
    /** ssl_log_secret was entered for `ssl` (observe-only path, no keys). */
    onSslSecret(ssl: NativePointer, module: string): boolean;
}

export function createQuicSslBinder(deps: QuicSslBinderDeps): QuicSslBinder {
    const byThread = new Map<number, CryptoFrameConnection>();
    const current = () => byThread.size === 0 ? undefined : byThread.get(deps.currentThreadId());
    const bindCurrent = (conn: CryptoFrameConnection, rawClientRandom: string) => {
        const clientRandom = normalizeClientRandom(rawClientRandom);
        return clientRandom !== "" && deps.bind(conn.connPtr, conn.connKey, clientRandom);
    };
    return {
        enterCryptoFrame(conn) {
            const thread = deps.currentThreadId();
            const previous = byThread.get(thread);
            byThread.set(thread, conn);
            return previous;
        },
        leaveCryptoFrame(previous) {
            const thread = deps.currentThreadId();
            if (previous === undefined) byThread.delete(thread);
            else byThread.set(thread, previous);
        },
        onKeylogClientRandom(clientRandom) {
            const conn = current();
            return conn !== undefined && bindCurrent(conn, clientRandom);
        },
        onSslSecret(ssl, module) {
            // Checked before the read: most secrets (TCP TLS) are not inside a CRYPTO frame.
            const conn = current();
            if (conn === undefined || ssl.isNull()) return false;
            return bindCurrent(conn, deps.readClientRandom(ssl, module));
        },
    };
}

export interface QuicBindingGate {
    keylogEnabled: boolean;
    pairipSafe: boolean;
    arch: string;
}

/**
 * Observe-only ssl_log_secret hook: whenever the anchor scan is allowed (no
 * --pairip-safe) on arm64 (the STREAM-frame hooks themselves are arm64-only),
 * with or without -k: a -k run whose keylog tier never succeeds still binds.
 * Modules a keylog tier owns are skipped by the locator itself.
 */
export function wantsObserveOnlySslHook(gate: QuicBindingGate): boolean {
    return !gate.pairipSafe && gate.arch === "arm64";
}

/** OnCryptoFrame is worth hooking only when some path will report the handshake's secrets. */
export function wantsCryptoFrameBinding(gate: QuicBindingGate): boolean {
    return gate.keylogEnabled || wantsObserveOnlySslHook(gate);
}
