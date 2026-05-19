// agent/tls/definitions/rustls.ts
//
// Data-driven Rustls hook definition for symbol-resolvable rustls-ffi builds.
// Pattern-only stripped variants (librustls_android_*_ex.so etc.) continue to
// route through the legacy executor — see rustls_linux.ts / rustls_android.ts.

import {
    HookDefinition,
    ResolvedFunctions,
} from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { devlog, devlog_error } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";

// rustls-ffi rustls_keylog_callback typedef:
//   void(const u8 *label, size_t label_len, const u8 *cr, size_t cr_len,
//        const u8 *secret, size_t secret_len)
// Lazy: only allocate the NativeCallback trampoline if a rustls module is
// actually present and the keylog install runs. Sessions without rustls
// skip the cost entirely.
let rustlsKeylogCb: NativeCallback<"void", ["pointer", "size_t", "pointer", "size_t", "pointer", "size_t"]> | null = null;

function getRustlsKeylogCb(): typeof rustlsKeylogCb {
    if (rustlsKeylogCb !== null) return rustlsKeylogCb;
    rustlsKeylogCb = new NativeCallback(
        function (
            label: NativePointer, labelLen: UInt64,
            clientRandom: NativePointer, crLen: UInt64,
            secret: NativePointer, secretLen: UInt64,
        ): void {
            try {
                const labelStr = labelLen.toNumber() === 0
                    ? "CLIENT_RANDOM"
                    : (label.readUtf8String(labelLen.toNumber()) ?? "CLIENT_RANDOM");
                const crHex = toHexString(clientRandom.readByteArray(crLen.toNumber()));
                const secretHex = toHexString(secret.readByteArray(secretLen.toNumber()));
                sendKeylog(`${labelStr} ${crHex} ${secretHex}`);
            } catch (e) {
                devlog_error(`[rustls keylog cb] ${e}`);
            }
        },
        "void",
        ["pointer", "size_t", "pointer", "size_t", "pointer", "size_t"],
    );
    return rustlsKeylogCb;
}

// rustls-ffi exposes no SSL_get_fd / session ID accessors. Returning -1 / ""
// follows the s2ntls precedent — getPortsAndAddresses respects
// enable_default_fd to synthesize 5-tuple metadata.
function rustlsFdDecoder(_conn: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}
function rustlsSessionIdDecoder(_conn: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

function attachUserKeylogShadow(addr: NativePointer): void {
    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            this.userCallback = args[1];
        },
        onLeave: function (retval: any) {
            // 7000 == RUSTLS_RESULT_OK in older rustls-ffi versions; 0 in newer.
            // Accept either as "the user actually replaced our callback".
            const status = retval.toInt32();
            if (status !== 7000 && status !== 0) return;
            if (this.userCallback.isNull()) return;
            try {
                Interceptor.attach(this.userCallback, {
                    onEnter(args: any) {
                        try {
                            const labelPtr = args[0];
                            const labelLen = args[1].toInt32();
                            const cr = args[2];
                            const crLen = args[3].toInt32();
                            const secret = args[4];
                            const secretLen = args[5].toInt32();
                            if (cr.isNull() || crLen !== 32) return;
                            if (secret.isNull() || secretLen <= 0 || secretLen > 48) return;
                            const labelStr = labelPtr.readUtf8String(labelLen);
                            const crHex = toHexString(cr.readByteArray(crLen));
                            const secretHex = toHexString(secret.readByteArray(secretLen));
                            sendKeylog(`${labelStr} ${crHex} ${secretHex}`);
                        } catch (e) {
                            devlog_error(`[rustls user-cb shadow] ${e}`);
                        }
                    },
                });
            } catch (e) {
                devlog_error(`[rustls user-cb attach] ${e}`);
            }
        },
    });
}

export function createRustlsDefinition(): HookDefinition {
    return {
        libraryId: "rustls",
        offsetKey: "rustls",
        functions: {
            librarySymbols: [
                "rustls_connection_read_tls",
                "rustls_connection_write_tls",
                "rustls_client_config_builder_new",
                "rustls_client_config_builder_new_custom",
                "rustls_client_config_builder_set_key_log",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            {
                symbol: "rustls_client_config_builder_set_key_log",
                retType: "uint32",
                argTypes: ["pointer", "pointer", "pointer"],
            },
        ],
        fdDecoder: rustlsFdDecoder,
        sessionIdDecoder: rustlsSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        // No readHook / writeHook — rustls_connection_*_tls carry CIPHERTEXT
        // (raw TLS records), not plaintext, so the generic plaintext executor
        // would emit garbage. Legacy also marks these "TBD".
        keylog: {
            kind: "custom",
            install: (addresses, modName, resolvedFns, _enableDefaultFd) => {
                const lib = addresses[modName] || {};
                const setKeyLogFn = resolvedFns["rustls_client_config_builder_set_key_log"];
                if (!setKeyLogFn) {
                    devlog("[rustls] set_key_log unresolved; cannot install builder hook");
                    return false;
                }
                let installed = false;

                // Inject our keylog callback on every config builder creation.
                const builderNewAddr = lib["rustls_client_config_builder_new"];
                if (builderNewAddr && !builderNewAddr.isNull()) {
                    Interceptor.attach(builderNewAddr, {
                        onLeave(retval: NativePointer) {
                            if (retval.isNull()) return;
                            setKeyLogFn(retval, getRustlsKeylogCb(), ptr("0"));
                        },
                    });
                    installed = true;
                }
                const customNewAddr = lib["rustls_client_config_builder_new_custom"];
                if (customNewAddr && !customNewAddr.isNull()) {
                    Interceptor.attach(customNewAddr, {
                        onLeave(retval: NativePointer) {
                            if (retval.isNull()) return;
                            setKeyLogFn(retval, getRustlsKeylogCb(), ptr("0"));
                        },
                    });
                    installed = true;
                }

                // Shadow any user-installed callback so we still extract keys.
                const setKeyLogAddr = lib["rustls_client_config_builder_set_key_log"];
                if (setKeyLogAddr && !setKeyLogAddr.isNull()) {
                    attachUserKeylogShadow(setKeyLogAddr);
                    installed = true;
                }
                return installed;
            },
        },
        libraryType: "rustls",
    };
}
