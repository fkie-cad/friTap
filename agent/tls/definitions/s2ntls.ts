// agent/tls/definitions/s2ntls.ts
//
// Data-driven s2n-tls hook definition.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { devlog } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";

const keylog_callback = new NativeCallback(
    function (ctxPtr: NativePointer, conn: NativePointer, logline: NativePointer, len: NativePointer) {
        devlog("invoking keylog_callback from s2ntls");
        sendKeylog(logline.readCString(len.toInt32()));
        return 1;
    },
    "int",
    ["pointer", "pointer", "pointer", "pointer"],
);

// Pre-allocated buffer for fd output (reused across calls)
const _fdPtr = Memory.alloc(Process.pointerSize);

function s2nFdDecoder(conn: NativePointer, fns: ResolvedFunctions): number {
    fns["s2n_connection_get_read_fd"](conn, _fdPtr);
    return _fdPtr.readInt();
}

function s2nSessionIdDecoder(_conn: NativePointer, _fns: ResolvedFunctions): string {
    return "0";
}

export function createS2nTlsDefinition(): HookDefinition {
    return {
        libraryId: "s2n",
        offsetKey: "s2n",
        functions: {
            librarySymbols: [
                "s2n_send",
                "s2n_recv",
                "s2n_connection_get_read_fd",
                "s2n_connection_get_write_fd",
                "s2n_config_set_key_log_cb",
                "s2n_config_new",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            { symbol: "s2n_connection_get_read_fd", retType: "int", argTypes: ["pointer", "pointer"] },
            { symbol: "s2n_connection_get_write_fd", retType: "int", argTypes: ["pointer", "pointer"] },
            { symbol: "s2n_config_set_key_log_cb", retType: "int", argTypes: ["pointer", "pointer", "pointer"] },
        ],
        fdDecoder: s2nFdDecoder,
        sessionIdDecoder: s2nSessionIdDecoder,
        readHook: {
            symbol: "s2n_recv",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "s2n_recv",
        },
        writeHook: {
            symbol: "s2n_send",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "s2n_send",
        },
        keylog: {
            kind: "custom",
            install: (addresses, moduleName, resolvedFns, _enableDefaultFd) => {
                // Auto-inject keylog callback on new configs
                const configNewAddr = addresses[moduleName]?.["s2n_config_new"];
                if (configNewAddr && !configNewAddr.isNull()) {
                    Interceptor.attach(configNewAddr, {
                        onLeave: function (retval: any) {
                            resolvedFns["s2n_config_set_key_log_cb"](retval, keylog_callback, ptr("0"));
                        },
                    });
                }

                // Intercept user-set callbacks
                const setKeyLogCbAddr = addresses[moduleName]?.["s2n_config_set_key_log_cb"];
                if (setKeyLogCbAddr && !setKeyLogCbAddr.isNull()) {
                    Interceptor.attach(setKeyLogCbAddr, {
                        onEnter: function (args: any) {
                            const userCallback = args[1];
                            Interceptor.attach(userCallback, {
                                onEnter: function (args: any) {
                                    const logline = args[2];
                                    const len = args[3];
                                    sendKeylog(logline.readCString(len.toInt32()));
                                },
                            });
                        },
                    });
                }
            },
        },
    };
}
