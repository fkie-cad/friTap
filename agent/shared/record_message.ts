// agent/shared/record_message.ts
//
// The datalog message for one plaintext TLS record: peer addressing plus the SSL
// session fields. Shared by every SSL_read/SSL_write(_ex) hook (modern executors,
// the SSL_*_ex extra hooks and the legacy class-based OpenSSL/BoringSSL hooks).

import { getPortsAndAddresses } from "./shared_functions.js";
import { cachedSslFd, recoverSocketFd } from "./socket_fd_tracker.js";
import { CallerStackJoin } from "./shared_structures.js";

export type RecordFields = { [field: string]: string | number };

export interface RecordContext {
    /** Socket fd of the record's connection (SSL_get_fd, or recovered via the fd tracker). */
    fd: number;
    isRead: boolean;
    /** Hooked function name, reported as message.function. */
    functionName: string;
    methodAddresses: { [fn: string]: NativePointer };
    enableDefaultFd: boolean;
    /** Replaces getPortsAndAddresses for libraries with their own address logic. */
    resolvePeer?: () => RecordFields | null;
}

/**
 * Peer/session metadata for one plaintext record, or null when it cannot be
 * attributed (no usable fd and no --enable_default_fd, or a non-IP socket).
 * `sessionFields` is only evaluated for attributable records.
 */
export function buildRecordMessage(ctx: RecordContext, sessionFields: () => RecordFields): any | null {
    const message = ctx.resolvePeer
        ? ctx.resolvePeer()
        : getPortsAndAddresses(ctx.fd, ctx.isRead, ctx.methodAddresses, ctx.enableDefaultFd);
    if (message === null) return null;
    Object.assign(message, sessionFields());
    message["function"] = ctx.functionName;
    return message;
}

/**
 * Build the connection-join fields for an opt-in `caller_stack` SDK-attribution
 * message (agent/shared/sdk_backtrace.ts), shared by BOTH OpenSSL/BoringSSL hook
 * trees (the generic read/write executors and the class-based plaintext hooks).
 *
 * The 5-tuple is resolved the SAME way a datalog/record message resolves its
 * peer, so the emitted src/dst addr+port/ss_family are BYTE-FOR-BYTE what the
 * host stores on the flow — letting the host join a `caller_stack` to its flow
 * on the connection 5-tuple (stable at first write) instead of on the
 * `ssl_session_id`, which is still null (==0) at the first SSL_read/SSL_write.
 *
 * Everything is LAZY (`fdFn`, `sessionIdFn`, `resolvePeer` are invoked here, and
 * this function is only ever called from maybeCaptureCallerStack's first-capture
 * path): nothing is read for an already-seen connection or when --attribute-sdk
 * is off. `ssl_session_id` is kept best-effort (so an fd failure never loses it),
 * and a connection with no resolvable fd (BIO-based stacks at cold start) simply
 * emits no 5-tuple — that connection just won't attribute, which is acceptable.
 *
 * @param ssl             SSL object pointer (for the fd-tracker cache fallback).
 * @param fdFn            Lazy SSL_get_fd for this connection (may throw / return <0).
 * @param isRead          Orientation for getPortsAndAddresses (read vs write hook).
 * @param methodAddresses getpeername/getsockname/ntohs/ntohl for this module.
 * @param enableDefaultFd --enable_default_fd (loopback placeholder when fd<0).
 * @param sessionIdFn     Lazy best-effort ssl_session_id.
 * @param resolvePeer     Library-specific peer resolver (customAddressExtractor);
 *                        when set it replaces the getPortsAndAddresses path, so a
 *                        custom-addressing library's tuple still matches its flow.
 */
export function buildCallerStackJoin(
    ssl: NativePointer,
    fdFn: () => number,
    isRead: boolean,
    methodAddresses: { [fn: string]: NativePointer },
    enableDefaultFd: boolean,
    sessionIdFn: () => string | number,
    resolvePeer?: () => RecordFields | null,
): CallerStackJoin {
    const join: CallerStackJoin = {};
    try { join.ssl_session_id = sessionIdFn(); } catch (_e) { /* best-effort */ }

    let peer: RecordFields | null = null;
    if (resolvePeer) {
        try { peer = resolvePeer(); } catch (_e) { peer = null; }
    } else {
        // Resolve the fd the SAME way the datalog path's recoveredFd() does, so a
        // caller_stack's 5-tuple matches its flow's byte-for-byte on every stack:
        //   1. SSL_get_fd (socket-based stacks: the common case, valid at first write);
        //   2. the fd-tracker's SSL-scoped cache (curl BIO stacks that do I/O inside
        //      the SSL call, so an earlier scoped call cached sslToFd[ssl]);
        //   3. the thread's last stream-socket fd (recoverSocketFd) — the fallback a
        //      memory-BIO stack (Conscrypt SSLEngine) relies on, since it does its
        //      socket I/O OUTSIDE the SSL call so no scope ever caches its fd. The
        //      first app-data SSL_write runs synchronously on the connection's thread,
        //      whose last stream fd is that connection's (bound at connect()), so this
        //      recovers the same peer the datalog record does.
        let fd = -1;
        try { fd = fdFn(); } catch (_e) { fd = -1; }
        if (fd < 0) fd = cachedSslFd(ssl);
        if (fd < 0) fd = recoverSocketFd();
        if (fd >= 0 || enableDefaultFd) {
            try {
                peer = getPortsAndAddresses(fd, isRead, methodAddresses, enableDefaultFd);
            } catch (_e) {
                peer = null;
            }
        }
    }

    if (peer) {
        if (peer["src_addr"] !== undefined) join.src_addr = peer["src_addr"];
        if (peer["dst_addr"] !== undefined) join.dst_addr = peer["dst_addr"];
        if (peer["src_port"] !== undefined) join.src_port = peer["src_port"] as number;
        if (peer["dst_port"] !== undefined) join.dst_port = peer["dst_port"] as number;
        if (peer["ss_family"] !== undefined) join.ss_family = peer["ss_family"] as string;
    }
    return join;
}
