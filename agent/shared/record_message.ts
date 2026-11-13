// agent/shared/record_message.ts
//
// The datalog message for one plaintext TLS record: peer addressing plus the SSL
// session fields. Shared by every SSL_read/SSL_write(_ex) hook (modern executors,
// the SSL_*_ex extra hooks and the legacy class-based OpenSSL/BoringSSL hooks).

import { getPortsAndAddresses, isUnwantedFd } from "./shared_functions.js";
import { cachedSslFd, recoverSocketFd } from "./socket_fd_tracker.js";
import { CallerStackJoin } from "./shared_structures.js";
import { noteSslClientRandom, readSslClientRandom } from "./ssl_identity.js";
import { attribute_sdk } from "../fritap_agent.js";
import { offerCallerStackJoin } from "./sdk_backtrace.js";

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
    /**
     * Name of the hooked module that produced the record (e.g. "libwebviewchromium.so"),
     * reported as message.library. Without it the host falls back to the TLS library
     * announced LAST, which mislabels every flow of an earlier-announced module.
     */
    library?: string;
    /**
     * The record's SSL object. When set (and `clientRandom` is not), the record's
     * client_random is looked up through the shared per-SSL* identity
     * (ssl_identity.ts: cache -> the module's layout) for module `library`.
     */
    ssl?: NativePointer;
    /**
     * Library-specific client_random lookup (lower-case hex, "" when unknown).
     * Overrides the `ssl` lookup. Only evaluated for attributable records that
     * carry no client_random yet.
     */
    clientRandom?: () => string;
}

/**
 * Stamp the producing module's name onto a datalog message as `library`, so the host
 * attributes the flow to it instead of the last-announced TLS library. An empty or
 * missing name leaves the message untouched (no empty `library` key).
 */
export function stampRecordLibrary(message: { [key: string]: any }, library: string | undefined): void {
    if (library) message["library"] = library;
}

/**
 * Stamp the record's TLS client_random (the cross-source join key) onto a datalog
 * message. An empty value is skipped, and a non-empty `client_random` already on
 * the message (e.g. from an SSL_get_client_random session decoder) is never
 * overwritten.
 */
export function stampRecordClientRandom(message: { [key: string]: any }, clientRandom: string | undefined): void {
    if (!clientRandom || message["client_random"]) return;
    message["client_random"] = clientRandom;
}

/** The context's client_random: its own lookup, else the shared per-SSL* identity, else "". */
function lookupRecordClientRandom(ctx: RecordContext): string {
    try {
        if (ctx.clientRandom) return ctx.clientRandom();
        if (ctx.ssl) return readSslClientRandom(ctx.ssl, ctx.library ?? "");
    } catch (_e) {
        // best-effort: a record is never lost to a client_random lookup
    }
    return "";
}

/** True when the record has no socket fd to resolve a peer from (and no library-specific resolver). */
function hasNoSocketFd(ctx: RecordContext): boolean {
    return ctx.fd < 0 && !ctx.resolvePeer;
}

/** The fields every record carries besides its peer: function, library and client_random. */
function stampRecordIdentity(message: { [key: string]: any }, ctx: RecordContext): void {
    message["function"] = ctx.functionName;
    stampRecordLibrary(message, ctx.library);
    if (!message["client_random"]) stampRecordClientRandom(message, lookupRecordClientRandom(ctx));
}

/** SDK attribution (opt-in): a held caller_stack of this connection is sent with this record's own join keys. */
function offerRecordToCallerStack(message: { [key: string]: any }, ctx: RecordContext): void {
    if (attribute_sdk && ctx.ssl) offerCallerStackJoin(ctx.ssl, message);
}

/** The identity fields, then the opt-in SDK-attribution offer: the tail of every built record. */
function finishRecord(message: { [key: string]: any }, ctx: RecordContext): void {
    stampRecordIdentity(message, ctx);
    // SDK attribution (opt-in): a held caller_stack of this connection is sent with
    // this record's own client_random / 5-tuple (sdk_backtrace.ts).
    offerRecordToCallerStack(message, ctx);
}

/** `fn` evaluated at most once, however often the returned function is called. */
function once<T>(fn: () => T): () => T {
    let evaluated = false;
    let value: T;
    return () => {
        if (!evaluated) { value = fn(); evaluated = true; }
        return value;
    };
}

/**
 * Record message for a connection WITHOUT a socket fd (fd < 0: a memory/custom BIO whose
 * fd could not be recovered, e.g. statically linked Chromium BoringSSL), or null.
 *
 * The record is kept only when its TLS client_random is known: it then carries NO address
 * fields (no src/dst addr/port, no ss_family) and the host assigns one stable synthetic
 * tuple per client_random. Without a client_random it is dropped, as before. Records of
 * an fd that is merely unusable (AF_UNIX, other non-IP sockets) never come here.
 * Also preferred over the shared --enable_default_fd placeholder tuple, which merges every
 * fd-less connection into one stream. `sessionFields` is evaluated for fd-less records only.
 */
export function buildEndpointlessRecord(ctx: RecordContext, sessionFields: () => RecordFields): any | null {
    if (ctx.fd >= 0) return null;
    return buildRecordWithoutPeer(ctx, sessionFields);
}

/** The endpointless record (no address fields) when a client_random is known, else null. */
function buildRecordWithoutPeer(ctx: RecordContext, sessionFields: () => RecordFields): any | null {
    // The session fields are read first: they may carry the library's own
    // client_random decoder (SSL_get_client_random), which wins over the lookup.
    const message: { [key: string]: any } = { ...sessionFields() };
    stampRecordIdentity(message, ctx);
    if (!message["client_random"]) return null;
    offerRecordToCallerStack(message, ctx);
    return message;
}

/** The record's peer fields: the library's own resolver, else the socket fd's tuple; null when unresolved. */
function resolveRecordPeer(ctx: RecordContext): RecordFields | null {
    return ctx.resolvePeer
        ? ctx.resolvePeer()
        : getPortsAndAddresses(ctx.fd, ctx.isRead, ctx.methodAddresses, ctx.enableDefaultFd);
}

/** True when the record's fd is a non-IP socket (AF_UNIX etc.): never attributable, whatever its client_random. */
function isUnwantedRecordFd(ctx: RecordContext): boolean {
    return !ctx.resolvePeer && ctx.fd >= 0 && isUnwantedFd(ctx.fd);
}

/**
 * Peer/session metadata for one plaintext record, or null when it cannot be
 * attributed (a non-IP socket, or no resolvable peer with neither a known
 * client_random nor --enable_default_fd). A record without a resolvable peer --
 * no fd, a failed getsockname/getpeername, or a resolver returning null -- is
 * built endpointless (no address fields) when its client_random is known.
 * `sessionFields` is only evaluated for attributable records.
 */
export function buildRecordMessage(ctx: RecordContext, sessionFields: () => RecordFields): any | null {
    // Read once: an fd-less record without a client_random falls through to the
    // --enable_default_fd placeholder below, which needs the same fields.
    const sessionFieldsOnce = once(sessionFields);
    if (hasNoSocketFd(ctx)) {
        const endpointless = buildEndpointlessRecord(ctx, sessionFieldsOnce);
        if (endpointless !== null || !ctx.enableDefaultFd) return endpointless;
    }
    const message = resolveRecordPeer(ctx);
    if (message === null) {
        // A failed lookup is not an unwanted fd: keep the record if its client_random is known.
        return isUnwantedRecordFd(ctx) ? null : buildRecordWithoutPeer(ctx, sessionFieldsOnce);
    }
    Object.assign(message, sessionFieldsOnce());
    finishRecord(message, ctx);
    return message;
}

/**
 * The per-SSL lookups of a class-based hook that builds its own peer fields
 * (e.g. Cronet's statically linked BoringSSL), so its records get the same
 * fd-less handling, identity stamps and SDK-attribution offer as the shared paths.
 */
export interface SslRecordSource {
    /** The hooked module: message.library, and the module whose ssl_st layout is used. */
    library: string;
    methodAddresses: { [fn: string]: NativePointer };
    enableDefaultFd: boolean;
    /** The library's own client_random probe (hex, "" when unknown). A hit is noted for the SSL*. */
    probeClientRandom: (ssl: NativePointer) => string;
    /** The record's session fields (e.g. ssl_session_id). */
    sessionFields: (ssl: NativePointer) => RecordFields;
}

/**
 * client_random of `ssl` (lower-case hex, "" when unknown): the shared per-SSL* identity
 * cache -> the module's ssl_st layout -> the source's probe. A probe hit is noted (records
 * do not pass through sendKeylog, the other noter), so overlap learning anchors it and an
 * SSL* address reused for a new connection is detected.
 */
export function sslRecordClientRandom(source: SslRecordSource, ssl: NativePointer): string {
    return readSslClientRandom(ssl, source.library, (s) => probeAndNoteClientRandom(source, s));
}

function probeAndNoteClientRandom(source: SslRecordSource, ssl: NativePointer): string {
    const clientRandom = source.probeClientRandom(ssl);
    if (clientRandom) noteSslClientRandom(ssl, clientRandom, source.library);
    return clientRandom;
}

function sslRecordContext(source: SslRecordSource, ssl: NativePointer, functionName: string, isRead: boolean, fd: number): RecordContext {
    return {
        fd, isRead, functionName, methodAddresses: source.methodAddresses,
        enableDefaultFd: source.enableDefaultFd, library: source.library,
        ssl, clientRandom: () => sslRecordClientRandom(source, ssl),
    };
}

/** buildEndpointlessRecord for an fd-less SSL of `source`: no address fields, or null without a client_random. */
export function buildEndpointlessSslRecord(
    source: SslRecordSource, ssl: NativePointer, functionName: string, isRead: boolean,
): any | null {
    return buildEndpointlessRecord(sslRecordContext(source, ssl, functionName, isRead, -1), () => source.sessionFields(ssl));
}

/**
 * Finish an addressed record that `source`'s hook built itself: stamps function, library
 * and client_random (an existing client_random is kept) and offers it to a held caller_stack.
 */
export function finishSslRecord(
    message: { [key: string]: any }, source: SslRecordSource, ssl: NativePointer, functionName: string, isRead: boolean,
): void {
    finishRecord(message, sslRecordContext(source, ssl, functionName, isRead, -1));
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
