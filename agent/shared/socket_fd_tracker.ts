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

import { devlog } from "../util/log.js";
import { SslFdCache } from "./ssl_fd_cache.js";

const SOCK_STREAM = 1; // portable across Linux/Android/macOS/iOS

// getsockopt(SO_TYPE) level/name differ per platform; SOCK_STREAM itself is portable.
const IS_DARWIN = Process.platform === "darwin";
const SOL_SOCKET = IS_DARWIN ? 0xffff : 1;
const SO_TYPE = IS_DARWIN ? 0x1008 : 3;

// Known SOCK_STREAM sockets, and known non-stream fds (files, datagram sockets, non-sockets).
const streamFds = new Set<number>();
const nonStreamFds = new Set<number>();

// Most-recent STREAM-socket fd each thread did I/O on.
const threadToFd = new Map<number, number>();

let _installed = false;

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

/**
 * Install the libc socket-activity observer (idempotent, process-wide). Armed LAZILY by the
 * executor on the first SSL_get_fd()<0; only the first call attaches.
 */
export function installSocketFdTracker(): void {
    if (_installed) return;
    _installed = true;

    const getsockoptAddr = Module.findGlobalExportByName("getsockopt");
    if (getsockoptAddr) {
        _getsockopt = new NativeFunction(getsockoptAddr, "int", ["int", "int", "int", "pointer", "pointer"]);
        _optvalBuf = Memory.alloc(8);
        _optlenBuf = Memory.alloc(4);
    }

    const socketAddr = Module.findGlobalExportByName("socket");
    const connectAddr = Module.findGlobalExportByName("connect");
    const closeAddr = Module.findGlobalExportByName("close");

    // All socket I/O entry points: recv/send families AND generic read/write. Every one funnels
    // through classifyStream(), so the mapping only ever holds TCP fds regardless of which call
    // a given stack uses for its ciphertext I/O. (Files and datagram sockets classify once and
    // are then skipped cheaply via the nonStreamFds cache.)
    const ioFns = ["recvfrom", "recv", "recvmsg", "sendto", "send", "sendmsg", "read", "write"];

    if (socketAddr) {
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

    for (const name of ioFns) {
        const addr = Module.findGlobalExportByName(name);
        if (!addr) continue;
        Interceptor.attach(addr, {
            onEnter(args) {
                const fd = args[0].toInt32();
                if (fd < 0 || !classifyStream(fd)) return;
                noteStreamIo(Process.getCurrentThreadId(), fd);
            },
        });
    }

    devlog("[socket-fd-tracker] armed lazily on first SSL_get_fd()<0 (thread->stream-socket-fd " +
           "correlation for fd-less peer recovery; the triggering record may be unattributed).");
}

/**
 * Recover the stream-socket fd the current thread most recently did I/O on, or -1 if unknown.
 * Used by BoringSSL/OpenSSL read/write hooks when SSL_get_fd() returns -1.
 */
export function recoverSocketFd(): number {
    const fd = threadToFd.get(Process.getCurrentThreadId());
    return fd === undefined ? -1 : fd;
}

// ── SSL-scoped attribution (see the header) ──────────────────────────────────────────────

/** One fd-less SSL call in progress on a thread: its SSL object and the stream fd it did I/O on. */
interface SslScope { ssl: string; fd: number; }

/** Bounds: a missed onLeave must not grow a stack forever; the cache must not grow unbounded. */
export const MAX_SCOPE_DEPTH = 16;
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

/** SSL_free(ssl): the pointer may be reused by a new SSL object of another connection. */
export function forgetSsl(ssl: NativePointer): void {
    if (sslToFd.size === 0) return;
    sslToFd.deleteSsl(ssl.toString());
}

function enterSslScope(ssl: NativePointer): void {
    const tid = Process.getCurrentThreadId();
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
 * Pops `ssl`'s scope (and any stale frames above it) off this thread's stack and returns the
 * stream fd the call did I/O on, caching it for the SSL object; -1 when it did none.
 */
function leaveSslScope(ssl: string): number {
    const stack = threadScopes.get(Process.getCurrentThreadId());
    if (stack === undefined || !stack.some(scope => scope.ssl === ssl)) return -1;
    let scope: SslScope;
    do {
        scope = stack.pop()!;
        activeScopes--;
    } while (scope.ssl !== ssl);
    if (scope.fd >= 0) cacheSslFd(ssl, scope.fd);
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
    const key = ssl.toString();
    let recovered = leaveSslScope(key);
    if (recovered < 0) recovered = sslToFd.get(key) ?? recoverSocketFd();
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
 */
export function installSslScopeHooks(moduleName: string, getFd: (ssl: NativePointer) => number): void {
    for (const symbol of HANDSHAKE_SYMBOLS) {
        attachOnce(findModuleExport(moduleName, symbol), {
            onEnter(args) {
                const ssl = args[0];
                if (ssl.isNull() || fdOrDeferred(getFd(ssl), ssl) !== null) return;
                (this as any).scopedSsl = ssl;
            },
            onLeave() {
                const ssl = (this as any).scopedSsl;
                if (ssl) leaveSslScope(ssl.toString());
            },
        });
    }
    attachOnce(findModuleExport(moduleName, "SSL_free"), {
        onEnter(args) { forgetSsl(args[0]); },
    });
}
