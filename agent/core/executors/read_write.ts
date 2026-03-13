// agent/core/executors/read_write.ts
//
// Generic read/write hook executors that consume HookDefinition data.

import { HookDefinition, ResolvedFunctions } from "../hook_definition.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { sendDatalog } from "../../shared/shared_structures.js";

function buildMessage(
    sslCtx: NativePointer,
    isRead: boolean,
    def: HookDefinition,
    resolvedFns: ResolvedFunctions,
    methodAddresses: { [fn: string]: NativePointer },
    enableDefaultFd: boolean,
    label: string,
): any | null {
    const fd = def.fdDecoder(sslCtx, resolvedFns);
    const message = def.customAddressExtractor
        ? def.customAddressExtractor(sslCtx, isRead, resolvedFns, enableDefaultFd)
        : getPortsAndAddresses(fd, isRead, methodAddresses, enableDefaultFd);
    if (message === null) return null;
    message["ssl_session_id"] = def.sessionIdDecoder(sslCtx, resolvedFns);
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
    if (!def.readHook) return;
    const hook = def.readHook;
    const label = hook.functionLabel || "SSL_read";
    const methodAddresses = addresses[moduleName];

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    Interceptor.attach(hookAddr, {
        onEnter: function (args: any) {
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
    if (!def.writeHook) return;
    const hook = def.writeHook;
    const label = hook.functionLabel || "SSL_write";
    const methodAddresses = addresses[moduleName];

    const hookAddr = addresses[moduleName][hook.symbol];
    if (!hookAddr || hookAddr.isNull()) return;

    if (hook.args.bytesTransferred === "retval") {
        // Retval-based write: capture buffer in onEnter, read retval bytes in onLeave
        Interceptor.attach(hookAddr, {
            onEnter: function (args: any) {
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
