// agent/core/executors/read_write.ts
//
// Generic read/write hook executors that consume HookDefinition data.

import { HookDefinition, ResolvedFunctions } from "../hook_definition.js";
import { sendDatalog } from "../../shared/shared_structures.js";
import { pcap_enabled, attribute_sdk } from "../../fritap_agent.js";
import { hookBreadcrumb } from "../../util/log.js";
import { maybeCaptureCallerStack } from "../../shared/sdk_backtrace.js";
import { fdOrDeferred, recoveredFd } from "../../shared/socket_fd_tracker.js";
import { buildRecordMessage, buildCallerStackJoin } from "../../shared/record_message.js";
import { recoverTls13Secrets } from "../../shared/tls13_secret_recovery.js";
import { BufferedSendTracker, UNKNOWN_WRITE_LENGTH, writtenPayload } from "../../shared/write_length.js";
import { prefetchSslLayout } from "../../shared/ssl_layout_autolocate.js";

type RecordMessageBuilder = (sslCtx: NativePointer, fd: number) => any | null;

/**
 * onEnter: the SSL object's socket fd, or null when the record must be attributed in onLeave
 * instead (deferred fd-less recovery, see fdOrDeferred in socket_fd_tracker.ts).
 *
 * BIO-based TLS has no socket fd on the SSL object: Conscrypt's memory BIO, and curl >= 7.87's
 * connection-filter BIO on genuine OpenSSL (SSL_get_fd() == -1 for every curl connection).
 * fdOrDeferred arms the tracker LAZILY — only once SSL_get_fd()<0 was actually observed, so
 * fd-exposing stacks never pay for its process-wide libc I/O hooks. Resolving the peer in onLeave
 * then sees the socket I/O this very SSL call did (curl's BIO sends/receives inside it), so even
 * a connection's first record is attributed. customAddressExtractor libs keep their own address
 * logic and are never deferred. A deferred hook must call recoveredFd(sslCtx) on EVERY onLeave
 * (failed calls too): it closes the SSL-scoped attribution opened here.
 */
function sslFdOrDeferred(sslCtx: NativePointer, def: HookDefinition, resolvedFns: ResolvedFunctions): number | null {
    const fd = def.fdDecoder(sslCtx, resolvedFns);
    if (fd >= 0 || def.customAddressExtractor) return fd;
    return fdOrDeferred(fd, sslCtx);
}

/**
 * The per-hook record-message builder: everything but the SSL object and fd is fixed at install.
 * A deferred record whose fd stayed unrecovered (-1) but whose client_random is known is kept
 * without address fields (buildRecordMessage -> buildEndpointlessRecord).
 */
function recordMessageBuilder(
    def: HookDefinition,
    resolvedFns: ResolvedFunctions,
    methodAddresses: { [fn: string]: NativePointer },
    enableDefaultFd: boolean,
    isRead: boolean,
    label: string,
    moduleName: string,
): RecordMessageBuilder {
    const extractor = def.customAddressExtractor;
    return (sslCtx, fd) => buildRecordMessage(
        {
            fd, isRead, functionName: label, methodAddresses, enableDefaultFd, library: moduleName,
            // client_random fallback (shared per-SSL* identity) when the decoder below
            // is missing or returns "": stamped by buildRecordMessage, never overwrites.
            ssl: sslCtx,
            resolvePeer: extractor ? () => extractor(sslCtx, isRead, resolvedFns, enableDefaultFd) : undefined,
        },
        () => {
            const fields: { [field: string]: any } = { ssl_session_id: def.sessionIdDecoder(sslCtx, resolvedFns) };
            if (def.clientRandomDecoder) fields["client_random"] = def.clientRandomDecoder(sslCtx, resolvedFns);
            return fields;
        },
    );
}

export function installReadHook(
    def: HookDefinition,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
): void {
    if (!pcap_enabled) return;
    if (!def.readHook) return;
    const hook = def.readHook;
    const label = hook.functionLabel || "SSL_read";
    const methodAddresses = addresses[moduleName];
    // Built once at install time (label/moduleName are constant); the hot-path
    // onEnter just hands the precomputed string to the throttled hookBreadcrumb.
    const breadcrumb = `${label} (${moduleName})`;
    const buildMessage = recordMessageBuilder(def, resolvedFns, methodAddresses, enableDefaultFd, true, label, moduleName);

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    Interceptor.attach(hookAddr, {
        onEnter: function (args: any) {
            // Crash attribution: buildMessage walks SSL-struct pointers (fd/session
            // decoders) that can fault on a mis-resolved address; a native fault is
            // uncatchable, so record the hook first. Throttled in hookBreadcrumb.
            hookBreadcrumb(breadcrumb);
            const sslCtx = args[hook.args.sslCtxArgIndex];
            // SDK attribution (opt-in): one guarded boolean read when off.
            // Join on the connection 5-tuple (stable at first read), resolved
            // exactly as the datalog record's peer, so it matches the flow.
            if (attribute_sdk) maybeCaptureCallerStack(sslCtx, this.context, () => buildCallerStackJoin(
                sslCtx, () => def.fdDecoder(sslCtx, resolvedFns), true, methodAddresses, enableDefaultFd,
                () => def.sessionIdDecoder(sslCtx, resolvedFns),
                def.customAddressExtractor
                    ? () => def.customAddressExtractor!(sslCtx, true, resolvedFns, enableDefaultFd)
                    : undefined,
            ), { transportModule: moduleName });
            this.buf = args[hook.args.bufferArgIndex];
            const fd = sslFdOrDeferred(sslCtx, def, resolvedFns);
            if (fd === null) {
                this.deferredSsl = sslCtx;
                return;
            }
            const message = buildMessage(sslCtx, fd);
            if (message === null) return;
            this.message = message;
        },
        onLeave: function (retval: any) {
            // Deferred: always close the SSL scope, even for a failed call.
            const recovered = this.deferredSsl ? recoveredFd(this.deferredSsl) : -1;
            retval |= 0;
            if (retval <= 0) return;
            if (this.deferredSsl) {
                this.message = buildMessage(this.deferredSsl, recovered);
            }
            if (!this.message) return;
            sendDatalog(this.message, this.buf.readByteArray(retval));
        },
    });
    // Start the ssl_st layout lookup now so early records carry client_random (gated, once per module).
    prefetchSslLayout(moduleName);
}

export function installWriteHook(
    def: HookDefinition,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
): void {
    if (!pcap_enabled) return;
    if (!def.writeHook) return;
    const hook = def.writeHook;
    const label = hook.functionLabel || "SSL_write";
    const methodAddresses = addresses[moduleName];
    // Precomputed once (see installReadHook): keeps the hot-path onEnter allocation-free.
    const breadcrumb = `${label} (${moduleName})`;
    const buildMessage = recordMessageBuilder(def, resolvedFns, methodAddresses, enableDefaultFd, false, label, moduleName);

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    // Both layouts are emitted in onLeave: a "retval" layout reads retval bytes, an "arg"
    // layout min(length arg, retval) — never the requested length, which would duplicate
    // plaintext on a partial write (the app retries with the remainder). The caller owns
    // the buffer for the whole synchronous call, so the onEnter pointer is still valid.
    const lengthArgIndex = hook.args.bytesTransferred === "arg" ? hook.args.lengthArgIndex : undefined;
    // Would-block calls whose record a later (possibly NULL/0) call flushes: see WriteHookDef.
    const buffered = hook.bufferedRetryCodes && lengthArgIndex !== undefined
        ? new BufferedSendTracker(hook.bufferedRetryCodes) : undefined;
    Interceptor.attach(hookAddr, {
        onEnter: function (args: any) {
            hookBreadcrumb(breadcrumb);
            const sslCtx = args[hook.args.sslCtxArgIndex];
            // SDK attribution (opt-in): one guarded boolean read when off.
            // Join on the connection 5-tuple (stable at first write), resolved
            // exactly as the datalog record's peer, so it matches the flow.
            if (attribute_sdk) maybeCaptureCallerStack(sslCtx, this.context, () => buildCallerStackJoin(
                sslCtx, () => def.fdDecoder(sslCtx, resolvedFns), false, methodAddresses, enableDefaultFd,
                () => def.sessionIdDecoder(sslCtx, resolvedFns),
                def.customAddressExtractor
                    ? () => def.customAddressExtractor!(sslCtx, false, resolvedFns, enableDefaultFd)
                    : undefined,
            ), { transportModule: moduleName });
            // M2 spike (internally gated/one-shot): for an attached process
            // whose handshake we missed, recover TLS 1.3 traffic secrets from
            // the live ssl->s3 and emit them as keylog lines. No-op unless a
            // witnessed handshake on this module has taught us the offsets.
            recoverTls13Secrets(moduleName, sslCtx);
            this.buf = args[hook.args.bufferArgIndex];
            if (lengthArgIndex !== undefined) this.len = parseInt(args[lengthArgIndex]);
            if (buffered) this.sslCtx = sslCtx;
            const fd = sslFdOrDeferred(sslCtx, def, resolvedFns);
            if (fd === null) {
                // Attributed in onLeave, once this call has sent its record (see above).
                this.deferredSsl = sslCtx;
                return;
            }
            const message = buildMessage(sslCtx, fd);
            if (message === null) return;
            this.message = message;
        },
        onLeave: function (retval: any) {
            // Deferred: always close the SSL scope, even for a failed call
            // (e.g. SSL_ERROR_WANT_WRITE, retried by the app with the same buffer).
            const recovered = this.deferredSsl ? recoveredFd(this.deferredSsl) : -1;
            const returned = retval.toInt32();
            const requested = lengthArgIndex !== undefined ? this.len : UNKNOWN_WRITE_LENGTH;
            const payload = writtenPayload(this.buf, requested, returned, this.sslCtx, buffered);
            if (payload === null) return;
            if (this.deferredSsl) {
                this.message = buildMessage(this.deferredSsl, recovered);
            }
            if (!this.message) return;
            sendDatalog(this.message, payload);
        },
    });
}
