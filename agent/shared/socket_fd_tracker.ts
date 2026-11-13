// agent/shared/socket_fd_tracker.ts
//
// Thread→stream-socket-fd correlation for fd-less peer recovery.
//
// Some TLS stacks (notably Android's Conscrypt, and any SSLEngine-style user that wraps
// the socket in an in-memory BIO) leave the SSL object WITHOUT a usable socket fd, so
// `SSL_get_fd(ssl)` returns -1. friTap then cannot resolve the peer IP/port the normal way
// (getpeername on the SSL's fd) and drops the plaintext.
//
// Recovery idea (no SSL fd needed): such stacks perform the raw socket I/O (recv/read of
// ciphertext, send/write of ciphertext) and the SSL_read/SSL_write of the SAME connection
// SYNCHRONOUSLY on the SAME thread during a request. So the stream-socket fd a thread most
// recently did I/O on IS that connection's fd. We maintain `threadId -> lastStreamFd`; a
// BoringSSL/OpenSSL read/write hook that sees fd<0 calls recoverSocketFd() and feeds the
// recovered fd into the existing getpeername path (getPortsAndAddresses) to obtain the REAL peer.
//
// LAZY / BIO-PRONE ONLY: the libc observer is NOT installed for every capture. The executor
// arms it (installSocketFdTracker()) the first time it actually observes SSL_get_fd()<0 — i.e.
// a BIO-based stack. Stacks that always expose a real fd never pay for the process-wide libc
// read()/write() hooks. COLD-START: the record that triggers arming cannot be recovered (no
// prior I/O was observed on its thread yet); recovery works from the next tracked I/O on that
// thread onward — typically a one-record gap at connection start.
//
// DEFERRED ATTRIBUTION (fdOrDeferred / recoveredFd): hooks that resolve the peer in onLeave instead of
// onEnter close that gap for stacks whose BIO does the socket I/O SYNCHRONOUSLY INSIDE the SSL
// call — curl >= 7.87's connection-filter BIO (macOS/Linux, genuine OpenSSL) send()s the
// record from within SSL_write and recv()s from within SSL_read. Arming in onEnter means that
// very send()/recv() is observed, so by onLeave the thread's last stream fd IS this record's
// connection — including the first SSL_write of a connection (the HTTP request / HTTP/2
// preface). It is also the more precise fd on a thread that multiplexes several connections.
// Memory-BIO stacks (Conscrypt) do no I/O inside the call, so onLeave sees the same mapping
// onEnter would have: deferring never makes recovery worse.
//
// STREAM-ONLY: only SOCK_STREAM (TCP) fds feed the mapping. A UDP fd a thread touched (e.g. a
// DNS/QUIC datagram) must never be recovered as the peer of a TCP SSL_read. Sockets we observe
// being created are typed from socket()'s args; pre-existing fds (created before we armed) are
// classified once, lazily, via getsockopt(SO_TYPE) and cached.
//
// SSL-SCOPED ATTRIBUTION (one thread, many connections): the thread's last stream fd is only
// right while a thread services ONE connection at a time. curl -Z (parallel transfers on one
// thread) and event-loop stacks interleave several SSL objects on one thread, so an SSL_read
// that returns data OpenSSL had already buffered (no socket I/O inside the call) would be
// attributed to whichever connection the thread touched last. The attribution is therefore
// scoped to the SSL object:
//   * onEnter of an fd-less SSL call (SSL_read/SSL_write/_ex, and the handshake functions via
//     installSslScopeHooks) pushes the SSL object onto a per-thread scope stack (fdOrDeferred);
//   * the libc I/O hooks note the stream fd they see in the innermost active scope;
//   * onLeave (recoveredFd) pops the scope and resolves, in order: the fd this very call did
//     I/O on (and caches it as sslToFd[ssl]); else the cached sslToFd[ssl] (a read served from
//     OpenSSL's buffer); else the thread's last stream fd (the old heuristic, e.g. a memory-BIO
//     stack whose first record precedes any scoped I/O).
// close(fd) drops every sslToFd entry naming fd (fd reuse), SSL_free drops the SSL's entry
// (pointer reuse), and the map is capped. With no scope active the I/O hooks pay one integer
// compare and allocate nothing.
//
// Remaining limitation: a memory-BIO stack (Conscrypt SSLEngine) does its socket I/O OUTSIDE
// the SSL call, so no scope ever sees it; such stacks still rely on the thread-last-fd heuristic.
//
// BACKENDS: the libc observer state lives in a SocketFdBackend: native (CModule; see
// native_socket_observer.ts for why), with these JS listeners as fallback. The SSL -> fd
// cache stays in JS for both; the native backend reports closed fds through a ring.

import { devlog } from "../util/log.js";
import { SslFdCache } from "./ssl_fd_cache.js";
// SDK-attribution dedup eviction (opt-in; inert when --attribute-sdk is off, the
// set is then always empty). Aliased: this module already exports its own fd-cache
// forgetSsl(NativePointer).
import { forgetSsl as forgetCallerStackSsl } from "./sdk_backtrace.js";
import { forgetSslIdentity } from "./ssl_identity.js";
import {
    nativeSocketObserver, fdCloseFunction, CLOSED_FD_CONSUMER, type ClosedFdDrain, MAX_SCOPE_DEPTH, SOCKET_IO_FUNCTIONS,
    SOCK_STREAM, SOL_SOCKET, SO_TYPE,
} from "./native_socket_observer.js";

export type { ClosedFdDrain };
export { MAX_SCOPE_DEPTH };

/** Where the libc observer state lives (see BACKENDS in the header). */
export interface SocketFdBackend {
    readonly name: "native" | "js";
    /** libc functions the backend attached listeners to (for the debug log). */
    readonly hookedFunctions: string[];
    enterScope(tid: number, ssl: NativePointer): void;
    /** Pop `ssl`'s scope (and stale frames above it); the fd it did I/O on, or -1. */
    leaveScope(tid: number, ssl: NativePointer): number;
    /** The stream fd thread `tid` most recently did I/O on, or -1. */
    recover(tid: number): number;
    /** Closed fds the JS SSL -> fd cache must forget (the JS backend forgets them inline). */
    drainClosedFds(): ClosedFdDrain;
}

// Known SOCK_STREAM sockets, and known non-stream fds (files, datagram sockets, non-sockets).
const streamFds = new Set<number>();
const nonStreamFds = new Set<number>();

// Most-recent STREAM-socket fd each thread did I/O on.
const threadToFd = new Map<number, number>();

let _installed = false;
let _backend: SocketFdBackend | null = null;

// Lazily-built getsockopt wrapper + scratch buffers, used to classify pre-existing fds.
let _getsockopt: NativeFunction<number, [number, number, number, NativePointer, NativePointer]> | null = null;
let _optvalBuf: NativePointer | null = null;
let _optlenBuf: NativePointer | null = null;

// Is `fd` a SOCK_STREAM socket? Cached. Unknown fds (created before we armed, or never seen via
// socket()) are probed once with getsockopt(SO_TYPE): a non-socket returns -1 (skip); a datagram
// socket returns SOCK_DGRAM (skip). Only TCP fds may feed the recovery mapping.
function classifyStream(fd: number): boolean {
    if (streamFds.has(fd)) return true;
    if (nonStreamFds.has(fd)) return false;
    if (_getsockopt && _optvalBuf && _optlenBuf) {
        try {
            _optlenBuf.writeU32(4);
            const ret = _getsockopt(fd, SOL_SOCKET, SO_TYPE, _optvalBuf, _optlenBuf) as number;
            if (ret === 0) {
                const sockType = _optvalBuf.readU32();
                if (sockType === SOCK_STREAM) {
                    streamFds.add(fd);
                    return true;
                }
                // Definitive answer: a real socket that is NOT a stream (datagram,
                // raw, …). Safe to cache as non-stream permanently.
                nonStreamFds.add(fd);
                return false;
            }
            // ret != 0 (e.g. EBADF on a since-closed fd): NOT definitive that this
            // is a non-stream socket — fall through WITHOUT caching so a later
            // probe (or socket()/connect() typing) can still classify a genuine
            // stream fd. Caching here would latch a stream fd out of recovery.
        } catch (e) { /* getsockopt threw — also non-definitive; do not cache */ }
        return false;
    }
    // getsockopt unavailable on this platform: we can never classify a
    // pre-existing fd. Don't poison the cache as "non-stream" (a real stream fd
    // would then be permanently un-recoverable); just report unknown-as-false.
    return false;
}

/** True once the libc socket-activity observer is armed (see installSocketFdTracker). */
export function isSocketFdTrackerInstalled(): boolean {
    return _installed;
}

/**
 * Install the libc socket-activity observer (idempotent, process-wide). Armed LAZILY by the
 * executor on the first SSL_get_fd()<0; only the first call attaches. Known fd-less modules
 * (statically linked Chromium BoringSSL) arm it EARLY at install, so their first records
 * already have socket activity to recover; `armedBy` names who armed it, for the debug log.
 */
export function installSocketFdTracker(armedBy = "lazily on first SSL_get_fd()<0"): void {
    if (_installed) return;
    _installed = true;

    const backend = _nativeBackendFactory() ?? createJsBackend();
    _backend = backend;
    devlog(`[socket-fd-tracker] armed ${armedBy} (thread->stream-socket-fd ` +
           "correlation for fd-less peer recovery; the triggering record may be unattributed); " +
           `backend=${backend.name}; hooked: ${backend.hookedFunctions.join(",") || "none"}.`);
}

/** Native backend on the shared CModule observer; null when it cannot serve the tracker. */
function createNativeBackend(): SocketFdBackend | null {
    const observer = nativeSocketObserver();
    if (observer === null || !observer.armSocketFdTracking()) return null;
    return {
        name: "native",
        get hookedFunctions() { return observer.hookedFunctions; },
        enterScope: (tid, ssl) => observer.enterScope(tid, ssl),
        leaveScope: (tid, ssl) => observer.leaveScope(tid, ssl),
        recover: (tid) => observer.recover(tid),
        drainClosedFds: () => observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker),
    };
}

type NativeBackendFactory = () => SocketFdBackend | null;
let _nativeBackendFactory: NativeBackendFactory = createNativeBackend;

/** Test-only: replace the native backend factory and forget any armed backend. */
export function resetSocketFdTrackerForTests(nativeFactory: NativeBackendFactory = createNativeBackend): void {
    _nativeBackendFactory = nativeFactory;
    _installed = false;
    _backend = null;
    streamFds.clear();
    nonStreamFds.clear();
    threadToFd.clear();
    threadScopes.clear();
    activeScopes = 0;
    sslToFd.clear();
    _lostClosedFdsLogged = false;
}

/** JS backend: the JS libc hooks plus the JS scope stacks. */
function createJsBackend(): SocketFdBackend {
    return {
        name: "js",
        hookedFunctions: installJsLibcHooks(),
        enterScope: (tid, ssl) => enterJsScope(tid, ssl),
        leaveScope: (tid, ssl) => leaveJsScope(tid, ssl.toString()),
        recover: (tid) => threadToFd.get(tid) ?? -1,
        drainClosedFds: () => [],            // its close() hook calls forgetFd() inline
    };
}

/** JS backend: attach JS listeners to the libc socket functions; returns the hooked names. */
function installJsLibcHooks(): string[] {
    const hooked: string[] = [];
    const getsockoptAddr = Module.findGlobalExportByName("getsockopt");
    if (getsockoptAddr) {
        _getsockopt = new NativeFunction(getsockoptAddr, "int", ["int", "int", "int", "pointer", "pointer"]);
        _optvalBuf = Memory.alloc(8);
        _optlenBuf = Memory.alloc(4);
    }

    const socketAddr = Module.findGlobalExportByName("socket");
    const connectAddr = Module.findGlobalExportByName("connect");
    const closeName = fdCloseFunction();
    const closeAddr = Module.findGlobalExportByName(closeName);

    if (socketAddr) {
        hooked.push("socket");
        Interceptor.attach(socketAddr, {
            onEnter(args) { (this as any).sockType = args[1].toInt32(); },
            onLeave(retval) {
                const fd = retval.toInt32();
                if (fd < 0) return;
                if (((this as any).sockType & 0x7f) === SOCK_STREAM) streamFds.add(fd);
                else nonStreamFds.add(fd);
            },
        });
    }
    if (connectAddr) {
        hooked.push("connect");
        Interceptor.attach(connectAddr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                // Bind the connection's fd to the connecting thread immediately, so the FIRST
                // app-data SSL_write (which may precede any recv/send on a reused thread) still
                // recovers the correct fd. Stream sockets only.
                if (fd >= 0 && classifyStream(fd)) {
                    threadToFd.set(Process.getCurrentThreadId(), fd);
                }
            },
        });
    }
    if (closeAddr) {
        hooked.push(closeName);
        Interceptor.attach(closeAddr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                const wasStream = streamFds.delete(fd);
                nonStreamFds.delete(fd);
                // Once close() returns the fd number to the kernel it can be reused for a brand-
                // new connection. A reused fd must not let ANY thread recover the stale one, so
                // sweep every thread mapping pointing at it — not just the closing thread's
                // (the fd may have been opened on a different thread). Gated to tracked stream-
                // socket closes so the common file/close path stays a pair of cheap Set deletes.
                if (wasStream) {
                    for (const [tid, mapped] of threadToFd) {
                        if (mapped === fd) threadToFd.delete(tid);
                    }
                    forgetFd(fd);
                }
            },
        });
    }

    // All socket I/O entry points: recv/send families AND generic read/write. Every one funnels
    // through classifyStream(), so the mapping only ever holds TCP fds regardless of which call
    // a given stack uses for its ciphertext I/O. (Files and datagram sockets classify once and
    // are then skipped cheaply via the nonStreamFds cache.)
    for (const name of SOCKET_IO_FUNCTIONS) {
        const addr = Module.findGlobalExportByName(name);
        if (!addr) continue;
        hooked.push(name);
        Interceptor.attach(addr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0 || !classifyStream(fd)) return;
                noteStreamIo(Process.getCurrentThreadId(), fd);
            },
        });
    }
    return hooked;
}

/**
 * Recover the stream-socket fd the current thread most recently did I/O on, or -1 if unknown.
 * Used by BoringSSL/OpenSSL read/write hooks when SSL_get_fd() returns -1.
 */
export function recoverSocketFd(): number {
    if (_backend === null) return -1;
    return _backend.recover(Process.getCurrentThreadId());
}

// ── SSL-scoped attribution (see the header) ──────────────────────────────────────────────

/** One fd-less SSL call in progress on a thread: its SSL object and the stream fd it did I/O on. */
interface SslScope { ssl: string; fd: number; }

/** Bound of the SSL -> fd cache. */
export const MAX_SSL_FD_ENTRIES = 1024;

const threadScopes = new Map<number, SslScope[]>();
/** Total frames on all stacks; the I/O hooks skip all scope work while it is 0. */
let activeScopes = 0;
/** SSL object (pointer string) -> stream fd an earlier scoped call of it did I/O on. */
const sslToFd = new SslFdCache(MAX_SSL_FD_ENTRIES);

/** libc I/O hook body: the thread's last stream fd, plus the innermost active SSL scope's fd. */
function noteStreamIo(tid: number, fd: number): void {
    threadToFd.set(tid, fd);
    if (activeScopes === 0) return;
    const stack = threadScopes.get(tid);
    if (stack !== undefined && stack.length > 0) stack[stack.length - 1].fd = fd;
}

function cacheSslFd(ssl: string, fd: number): void {
    sslToFd.set(ssl, fd);                    // LRU refresh + eviction, reverse index kept in sync
}

let _lostClosedFdsLogged = false;

/**
 * Apply the backend's closed fds to the SSL -> fd cache (native backend; the JS backend forgets
 * inline). Cheap when nothing was closed: the native drain compares two ring indices.
 */
function drainClosedFds(): void {
    if (_backend === null) return;
    const closed = _backend.drainClosedFds();
    if (closed === "lost") {
        sslToFd.clear();                     // some close() went unreported: no cached fd is safe
        if (!_lostClosedFdsLogged) {
            _lostClosedFdsLogged = true;
            devlog("[socket-fd-tracker] closed-fd ring overflowed; cleared the SSL->fd cache.");
        }
        return;
    }
    for (const fd of closed) forgetFd(fd);
}

/** close(fd): the number may be reused for a new connection, so no SSL may keep pointing at it. */
function forgetFd(fd: number): void {
    sslToFd.deleteFd(fd);                    // O(1) via the fd -> SSL reverse index
    if (activeScopes === 0) return;
    const stack = threadScopes.get(Process.getCurrentThreadId());
    if (stack === undefined) return;
    for (const scope of stack) {
        if (scope.fd === fd) scope.fd = -1;
    }
}

/**
 * The stream fd an earlier scoped call of `ssl` did I/O on, or -1 when unknown.
 * Read-only view of the SSL->fd recovery cache; used by the opt-in SDK-attribution
 * path (buildCallerStackJoin) to resolve a BIO-based connection's peer 5-tuple
 * from the SSL object when SSL_get_fd() returns -1. Empty (always -1) until a
 * scoped fd-less call has been observed, so it costs nothing on socket-based stacks.
 */
export function cachedSslFd(ssl: NativePointer): number {
    if (sslToFd.size === 0) return -1;
    drainClosedFds();
    return sslToFd.get(ssl.toString()) ?? -1;
}

/** SSL_free(ssl): the pointer may be reused by a new SSL object of another connection. */
export function forgetSsl(ssl: NativePointer): void {
    if (sslToFd.size === 0) return;
    sslToFd.deleteSsl(ssl.toString());
}

function enterSslScope(ssl: NativePointer): void {
    if (_backend === null) return;
    _backend.enterScope(Process.getCurrentThreadId(), ssl);
}

/**
 * Closes `ssl`'s scope on this thread and returns the stream fd the call did I/O on, caching it
 * for the SSL object; -1 when it did none (or no scope was open).
 */
function closeSslScope(ssl: NativePointer): number {
    if (_backend === null) return -1;
    drainClosedFds();
    const fd = _backend.leaveScope(Process.getCurrentThreadId(), ssl);
    if (fd >= 0) cacheSslFd(ssl.toString(), fd);
    return fd;
}

/** JS backend: push a scope frame for `ssl` on thread `tid`. */
function enterJsScope(tid: number, ssl: NativePointer): void {
    let stack = threadScopes.get(tid);
    if (stack === undefined) {
        stack = [];
        threadScopes.set(tid, stack);
    }
    if (stack.length >= MAX_SCOPE_DEPTH) {
        stack.shift();                       // a stale frame whose onLeave never ran
        activeScopes--;
    }
    stack.push({ ssl: ssl.toString(), fd: -1 });
    activeScopes++;
}

/**
 * JS backend: pops `ssl`'s scope (and any stale frames above it) off thread `tid`'s stack and
 * returns the stream fd the call did I/O on; -1 when it did none. closeSslScope caches it.
 */
function leaveJsScope(tid: number, ssl: string): number {
    const stack = threadScopes.get(tid);
    if (stack === undefined || !stack.some(scope => scope.ssl === ssl)) return -1;
    let scope: SslScope;
    do {
        scope = stack.pop()!;
        activeScopes--;
    } while (scope.ssl !== ssl);
    return scope.fd;
}

// One-time observability: a single devlog the first time deferred attribution recovers a peer,
// so a capture's debug log makes obvious that the recovered-fd path (not SSL_get_fd) produced it.
let _recoveryLogged = false;

/**
 * onEnter half of DEFERRED fd-less attribution (see the header). Returns `fd` unchanged when it
 * is usable (>= 0): attribute the record right away. For fd < 0 it arms the tracker (lazily,
 * idempotent), opens an attribution scope for `ssl` on this thread and returns null: the hook
 * MUST then call recoveredFd(ssl) in onLeave — on every return path, failed calls included, so
 * the scope is closed — and attribute the record with the fd it returns.
 */
export function fdOrDeferred(fd: number, ssl: NativePointer): number | null {
    if (fd >= 0) return fd;
    installSocketFdTracker();
    enterSslScope(ssl);
    return null;
}

/**
 * onLeave half of deferred attribution: closes `ssl`'s scope and returns the fd for its record —
 * the fd this call did I/O on, else the fd `ssl` last did I/O on, else the thread's last stream
 * fd, else -1.
 */
export function recoveredFd(ssl: NativePointer): number {
    let recovered = closeSslScope(ssl);
    if (recovered < 0) recovered = sslToFd.get(ssl.toString()) ?? recoverSocketFd();
    if (recovered >= 0 && !_recoveryLogged) {
        _recoveryLogged = true;
        devlog("[fd-recovery] SSL object exposed no socket fd (SSL_get_fd<0); recovered peer " +
               "via SSL-scoped socket-fd correlation — BIO-path active (e.g. curl connection " +
               "filters, Conscrypt SSLEngine).");
    }
    return recovered;
}

// Handshake entry points: scoping them caches the SSL's fd before its first SSL_read/SSL_write,
// so a first read served from data buffered during the handshake is attributed by the cache.
const HANDSHAKE_SYMBOLS = ["SSL_do_handshake", "SSL_connect", "SSL_accept"];
const _scopeHookedAddresses = new Set<string>();

function findModuleExport(moduleName: string, symbol: string): NativePointer | null {
    try {
        const module = Process.findModuleByName(moduleName);
        const address = module ? module.findExportByName(symbol) : null;
        return address && !address.isNull() ? address : null;
    } catch (e) {
        return null;
    }
}

/** Interceptor.attach once per address (definitions may request the same hooks twice). */
function attachOnce(address: NativePointer | null, callbacks: InvocationListenerCallbacks): void {
    if (address === null || _scopeHookedAddresses.has(address.toString())) return;
    _scopeHookedAddresses.add(address.toString());
    Interceptor.attach(address, callbacks);
}

/**
 * Scope the handshake functions of `moduleName` (when exported) for fd-less SSL objects, and
 * drop an SSL's cached fd on SSL_free. `getFd` is the library's SSL_get_fd (or -1 if unknown).
 * Idempotent per address.
 *
 * `extra.sslFree` is reserved for a located (non-exported) SSL_free on stripped builds; it is
 * accepted but not used yet (Chromium invalidation relies on generation + mismatch for now).
 */
export function installSslScopeHooks(
    moduleName: string,
    getFd: (ssl: NativePointer) => number,
    extra?: { sslFree?: NativePointer },
): void {
    for (const symbol of HANDSHAKE_SYMBOLS) {
        attachOnce(findModuleExport(moduleName, symbol), {
            onEnter(args) {
                const ssl = args[0];
                if (ssl.isNull() || fdOrDeferred(getFd(ssl), ssl) !== null) return;
                (this as any).scopedSsl = ssl;
            },
            onLeave() {
                const ssl = (this as any).scopedSsl;
                if (ssl) closeSslScope(ssl);
            },
        });
    }
    attachOnce(findModuleExport(moduleName, "SSL_free"), {
        onEnter(args) {
            forgetSsl(args[0]);
            forgetCallerStackSsl(args[0].toString());
            forgetSslIdentity(args[0]);
        },
    });
}
