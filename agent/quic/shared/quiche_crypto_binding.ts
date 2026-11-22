// agent/quic/shared/quiche_crypto_binding.ts
//
// Frida side of quic_ssl_binding.ts: hooks QuicConnection::OnCryptoFrame (and,
// where located, TlsClientHandshaker::CryptoConnect, where a 0-RTT client logs
// its early secret before any CRYPTO frame) and feeds the binder from two SSL*
// sources:
//   - the keylog lines (sendKeylog -> keylog_ssl_observer listener), whenever a
//     keylog tier emits them;
//   - an observe-only ssl_log_secret entry hook (anchor locator) for modules no
//     keylog tier owns, which reads the client_random through ssl_identity and
//     emits no keys.

import { devlog, devlog_error, hookBreadcrumb, _isShuttingDownNow } from "../../util/log.js";
import { keylog_enabled, pairip_safe } from "../../fritap_agent.js";
import { addKeylogSslListener, KeylogSslObserver } from "../../shared/keylog_ssl_observer.js";
import { readSslClientRandom } from "../../shared/ssl_identity.js";
import { runAnchorLocatorObserveOnly } from "../../shared/boringssl_anchor_locator.js";
import { prefetchSslLayout } from "../../shared/ssl_layout_autolocate.js";
import { resetReadableCache } from "../../util/safe_memory.js";
import { quicConnectionTracker } from "./quic_connection_tracker.js";
import {
    QuicheLayoutState, handshakerConnection, resolveConnectionIdentity, resolveNewHandshakeIdentity,
} from "./quiche_records.js";
import { Address, toAddress } from "./quiche_layout.js";
import {
    CryptoFrameConnection, createQuicSslBinder, wantsCryptoFrameBinding, wantsObserveOnlySslHook,
} from "./quic_ssl_binding.js";

const CRYPTO_IN_LABEL = "QuicConnection_OnCryptoFrame";
const CRYPTO_CONNECT_LABEL = "TlsClientHandshaker_CryptoConnect";

const quicSslBinder = createQuicSslBinder({
    currentThreadId: () => Process.getCurrentThreadId(),
    readClientRandom: (ssl, module) => readSslClientRandom(ssl, module),
    bind: (connPtr, connKey, clientRandom) => quicConnectionTracker.bindClientRandom(connPtr, connKey, clientRandom),
});

// One shared instance: addKeylogSslListener dedups it across modules.
const bindKeylogClientRandom: KeylogSslObserver = (_ssl, clientRandom) => {
    quicSslBinder.onKeylogClientRandom(clientRandom);
};
const cryptoFrameHooked = new Set<string>();

function startObserveOnly(moduleName: string): void {
    prefetchSslLayout(moduleName, "hook-install");
    void runAnchorLocatorObserveOnly(moduleName, (ssl) => { quicSslBinder.onSslSecret(ssl, moduleName); })
        .then((hooked) => devlog(`[Google QUICHE] ${moduleName}: observe-only ssl_log_secret hook ` +
                                 (hooked ? "installed" : "not installed") + " (QUIC client_random binding)"));
}

/**
 * The connection's tracker identity, resolved the way the STREAM-frame hooks
 * resolve it: resolving here also starts a new generation for a reused
 * address before its first stream record, so the binding lands on the right key.
 * Null when this generation is already bound (post-handshake CRYPTO frames).
 */
function unboundCryptoFrameConnection(state: QuicheLayoutState, address: Address,
                                      resolve: ResolveIdentity): CryptoFrameConnection | null {
    const linked = resolve(state, address);
    // Without addresses (or after a self change) a reused pointer looks bound; its new handshake must rebind.
    if (linked.clientRandom && !linked.reuseUndetectable && !linked.selfChanged) return null;
    return { connPtr: "0x" + address.toString(16), connKey: linked.connKey };
}

/** Resolves a hooked function's `this` to its QuicConnection; null when not resolvable. */
type ConnectionOf = (self: NativePointer) => Address | null;
type ResolveIdentity = typeof resolveConnectionIdentity;

/** Enters the binder's per-thread connection scope for the duration of the hooked call. */
function connectionScopeListener(state: QuicheLayoutState, crumb: string, label: string,
                                 connectionOf: ConnectionOf,
                                 resolve: ResolveIdentity): ScriptInvocationListenerCallbacks {
    return {
        onEnter(args) {
            this.entered = false;
            if (_isShuttingDownNow()) return;
            hookBreadcrumb(crumb);
            try {
                resetReadableCache();
                const connection = connectionOf(args[0]);
                if (connection === null) return;
                const conn = unboundCryptoFrameConnection(state, connection, resolve);
                if (conn === null) return;
                // Saved, not cleared, on leave: OnCryptoFrame can nest on one thread.
                this.prev = quicSslBinder.enterCryptoFrame(conn);
                this.entered = true;
            } catch (e) {
                devlog_error(`[${label}] onEnter threw: ${e}`);
            }
        },
        onLeave() {
            if (this.entered) quicSslBinder.leaveCryptoFrame(this.prev);
        },
    };
}

function onCryptoFrameListener(state: QuicheLayoutState): ScriptInvocationListenerCallbacks {
    return connectionScopeListener(state, `QuicConnection::OnCryptoFrame (${state.moduleName})`, CRYPTO_IN_LABEL,
                                   toAddress, resolveConnectionIdentity);
}

// Before the session layout is learned the handshaker stays unresolved: that
// connection's 0-RTT records go unbound, its later CRYPTO frames still bind.
// Runs once per new connection, so it also splits a reused pointer off its old key.
function cryptoConnectListener(state: QuicheLayoutState): ScriptInvocationListenerCallbacks {
    return connectionScopeListener(state, `TlsClientHandshaker::CryptoConnect (${state.moduleName})`,
                                   CRYPTO_CONNECT_LABEL, (handshaker) => handshakerConnection(state, toAddress(handshaker)),
                                   resolveNewHandshakeIdentity);
}

/** Optional: without it 0-RTT early records just carry no client_random. */
function hookCryptoConnect(moduleName: string, state: QuicheLayoutState, cryptoConnect: NativePointer | null): void {
    if (cryptoConnect === null) return;
    try {
        Interceptor.attach(cryptoConnect, cryptoConnectListener(state));
        devlog(`[Google QUICHE] ${moduleName}: hooked TlsClientHandshaker::CryptoConnect (0-RTT client_random binding)`);
    } catch (e) {
        devlog_error(`[Google QUICHE] failed to hook TlsClientHandshaker::CryptoConnect in ${moduleName}: ${e}`);
    }
}

/**
 * Hook OnCryptoFrame of `moduleName` so its QUIC records carry the TLS
 * client_random. Skipped when nothing would report the handshake's SSL*
 * (no -k and the observe-only scan is not allowed).
 */
export function installQuicheCryptoBinding(moduleName: string, state: QuicheLayoutState,
                                           onCryptoFrame: NativePointer | null,
                                           cryptoConnect: NativePointer | null = null): boolean {
    const gate = { keylogEnabled: keylog_enabled, pairipSafe: pairip_safe, arch: Process.arch };
    if (onCryptoFrame === null || !wantsCryptoFrameBinding(gate)) return false;
    if (cryptoFrameHooked.has(moduleName)) return true;
    try {
        Interceptor.attach(onCryptoFrame, onCryptoFrameListener(state));
        cryptoFrameHooked.add(moduleName);
    } catch (e) {
        devlog_error(`[Google QUICHE] failed to hook QuicConnection::OnCryptoFrame in ${moduleName}: ${e}`);
        return false;
    }
    hookCryptoConnect(moduleName, state, cryptoConnect);
    // Both sources: keylog lines reach the listener whenever a tier emits them
    // (even without -k), and observe-only covers a module no tier owns. Binding
    // is idempotent per connection, so both firing for one handshake is harmless.
    addKeylogSslListener(bindKeylogClientRandom);
    if (wantsObserveOnlySslHook(gate)) startObserveOnly(moduleName);
    devlog(`[Google QUICHE] ${moduleName}: hooked QuicConnection::OnCryptoFrame (QUIC client_random binding)`);
    return true;
}
