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
// STREAM-ONLY: only SOCK_STREAM (TCP) fds feed the mapping. A UDP fd a thread touched (e.g. a
// DNS/QUIC datagram) must never be recovered as the peer of a TCP SSL_read. Sockets we observe
// being created are typed from socket()'s args; pre-existing fds (created before we armed) are
// classified once, lazily, via getsockopt(SO_TYPE) and cached.
//
// Best-effort, with one KNOWN LIMITATION (documented, not fixed): the correlation assumes a
// thread services ONE connection at a time during a request. A single thread multiplexing many
// sockets via an NIO selector (some Netty/async stacks) breaks that assumption — `lastStreamFd`
// for the thread may belong to a different connection than the SSL_read/SSL_write being
// attributed, so the recovered peer could be wrong. This does NOT affect Conscrypt's blocking
// SSLSocket/SSLEngine (the stack this app uses), where each request runs synchronously on its
// own thread, and has not been observed in practice. Left as a documented caveat because a
// robust fix would require associating the BIO/SSL object with its fd at wrap time rather than
// inferring it from recent thread I/O.

import { devlog } from "../util/log.js";

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
            if (ret === 0 && _optvalBuf.readU32() === SOCK_STREAM) {
                streamFds.add(fd);
                return true;
            }
        } catch (e) { /* fall through: treat as non-stream */ }
    }
    nonStreamFds.add(fd);
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
                threadToFd.set(Process.getCurrentThreadId(), fd);
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
