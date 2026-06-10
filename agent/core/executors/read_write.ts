// agent/core/executors/read_write.ts
//
// Generic read/write hook executors that consume HookDefinition data.

import { HookDefinition, ResolvedFunctions } from "../hook_definition.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { sendDatalog } from "../../shared/shared_structures.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { hookBreadcrumb, devlog } from "../../util/log.js";
import { installSocketFdTracker, recoverSocketFd } from "../../shared/socket_fd_tracker.js";

// One-time observability: emit a single devlog the first time fd-less peer recovery
// (the BIO-path, e.g. Conscrypt) is actually exercised, so a capture log makes it
// obvious the recovered-fd path — not SSL_get_fd — produced the peer addresses.
let _recoveryLogged = false;

function buildMessage(
    sslCtx: NativePointer,
    isRead: boolean,
    def: HookDefinition,
    resolvedFns: ResolvedFunctions,
    methodAddresses: { [fn: string]: NativePointer },
    enableDefaultFd: boolean,
    label: string,
): any | null {
    let fd = def.fdDecoder(sslCtx, resolvedFns);
    if (fd < 0) {
        // BIO-based TLS (e.g. Conscrypt): no socket fd on the SSL object. Arm the fd-less
        // recovery tracker LAZILY — only now that we've actually observed SSL_get_fd()<0, so
        // non-BIO stacks never pay for the process-wide libc I/O hooks the tracker installs.
        // Then recover the real peer via thread->socket-fd correlation. (customAddressExtractor
        // libs keep their own logic and are unaffected.)
        installSocketFdTracker();
        const recovered = recoverSocketFd();
        if (recovered >= 0) {
            fd = recovered;
            if (!_recoveryLogged) {
                _recoveryLogged = true;
                devlog("[fd-recovery] SSL object exposed no socket fd (SSL_get_fd<0); recovered peer " +
                       "via thread->socket-fd correlation — BIO-path active (e.g. Conscrypt SSLEngine).");
            }
        }
    }
    const message = def.customAddressExtractor
        ? def.customAddressExtractor(sslCtx, isRead, resolvedFns, enableDefaultFd)
        : getPortsAndAddresses(fd, isRead, methodAddresses, enableDefaultFd);
    if (message === null) return null;
    message["ssl_session_id"] = def.sessionIdDecoder(sslCtx, resolvedFns);
    if (def.clientRandomDecoder) {
        message["client_random"] = def.clientRandomDecoder(sslCtx, resolvedFns);
    }
    message["function"] = label;
    return message;
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

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    Interceptor.attach(hookAddr, {
        onEnter: function (args: any) {
            // Crash attribution: buildMessage walks SSL-struct pointers (fd/session
            // decoders) that can fault on a mis-resolved address; a native fault is
            // uncatchable, so record the hook first. Throttled in hookBreadcrumb.
            hookBreadcrumb(breadcrumb);
            const sslCtx = args[hook.args.sslCtxArgIndex];
            const message = buildMessage(sslCtx, true, def, resolvedFns, methodAddresses, enableDefaultFd, label);
            if (message === null) return;
            this.message = message;
            this.buf = args[hook.args.bufferArgIndex];
        },
        onLeave: function (retval: any) {
            retval |= 0;
            if (retval <= 0) return;
            if (!this.message) return;
            sendDatalog(this.message, this.buf.readByteArray(retval));
        },
    });
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

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    if (hook.args.bytesTransferred === "retval") {
        // Retval-based write: capture buffer in onEnter, read retval bytes in onLeave
        Interceptor.attach(hookAddr, {
            onEnter: function (args: any) {
                hookBreadcrumb(breadcrumb);
                const sslCtx = args[hook.args.sslCtxArgIndex];
                const message = buildMessage(sslCtx, false, def, resolvedFns, methodAddresses, enableDefaultFd, label);
                if (message === null) return;
                this.message = message;
                this.buf = args[hook.args.bufferArgIndex];
            },
            onLeave: function (retval: any) {
                retval |= 0;
                if (retval <= 0) return;
                if (!this.message) return;
                sendDatalog(this.message, this.buf.readByteArray(retval));
            },
        });
    } else {
        // Arg-based write: read length from args in onEnter
        Interceptor.attach(hookAddr, {
            onEnter: function (args: any) {
                hookBreadcrumb(breadcrumb);
                const sslCtx = args[hook.args.sslCtxArgIndex];
                const message = buildMessage(sslCtx, false, def, resolvedFns, methodAddresses, enableDefaultFd, label);
                if (message === null) return;
                const buf = args[hook.args.bufferArgIndex];
                const len = parseInt(args[hook.args.lengthArgIndex!]);
                sendDatalog(message, buf.readByteArray(len));
            },
            onLeave: function (_retval: any) {
            },
        });
    }
}
