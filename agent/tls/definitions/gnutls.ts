// agent/tls/definitions/gnutls.ts
//
// Data-driven GnuTLS hook definition.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { log, devlog_error } from "../../util/log.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { enable_default_fd } from "../../fritap_agent.js";
import { STANDARD_SOCKET_SYMBOLS, DUMMY_SESSION_ID_GNUTLS } from "./shared_constants.js";

// Pre-allocated buffers for keylog callback (fixed size, reused across calls)
const _serverRandomPtr = Memory.alloc(Process.pointerSize + 4);
const _clientRandomPtr = Memory.alloc(Process.pointerSize + 4);

// Pre-allocated buffer for gnuTlsSessionIdDecoder (fixed 4 bytes for length)
const _sessionIdLenPtr = Memory.alloc(4);

function gnuTlsSessionIdDecoder(session: NativePointer, fns: ResolvedFunctions): string {
    let err = fns["gnutls_session_get_id"](session, NULL, _sessionIdLenPtr);
    if (err != 0) {
        if (enable_default_fd) {
            log("using dummy SessionID: " + DUMMY_SESSION_ID_GNUTLS);
            return DUMMY_SESSION_ID_GNUTLS;
        }
        return "";
    }
    const len = _sessionIdLenPtr.readU32();
    const p = Memory.alloc(len);
    err = fns["gnutls_session_get_id"](session, p, _sessionIdLenPtr);
    if (err != 0) {
        if (enable_default_fd) {
            log("using dummy SessionID: " + DUMMY_SESSION_ID_GNUTLS);
            return DUMMY_SESSION_ID_GNUTLS;
        }
        return "";
    }
    return readHexFromPointer(p, len);
}

export function createGnuTlsDefinition(): HookDefinition {
    // Per-call mutable ref — populated by loader via onNativeFunctionsResolved
    let _fns: ResolvedFunctions = {};

    // Per-call NativeCallback — captures local _fns by closure
    const keylog_callback = new NativeCallback(
        function (session: NativePointer, label: NativePointer, secret: NativePointer) {
            const secretLen = secret.add(Process.pointerSize).readUInt();
            const secretPtr = secret.readPointer();
            const secretStr = readHexFromPointer(secretPtr, secretLen);

            if (typeof this !== "undefined") {
                _fns["gnutls_session_get_random"](session, _clientRandomPtr, _serverRandomPtr);
            } else {
                devlog_error("[-] Error while installing keylog callback");
            }

            const clientRandomLen = 32;
            const clientRandomP = _clientRandomPtr.readPointer();
            const clientRandomStr = readHexFromPointer(clientRandomP, clientRandomLen);

            sendKeylog(label.readCString() + " " + clientRandomStr + " " + secretStr);
            return 0;
        },
        "int",
        ["pointer", "pointer", "pointer"],
    );

    return {
        libraryId: "gnutls",
        offsetKey: "gnutls",
        functions: {
            librarySymbols: [
                "gnutls_record_recv",
                "gnutls_record_send",
                "gnutls_session_set_keylog_function",
                "gnutls_transport_get_int",
                "gnutls_session_get_id",
                "gnutls_init",
                "gnutls_handshake",
                "gnutls_session_get_keylog_function",
                "gnutls_session_get_random",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            { symbol: "gnutls_transport_get_int", retType: "int", argTypes: ["pointer"] },
            { symbol: "gnutls_session_get_id", retType: "int", argTypes: ["pointer", "pointer", "pointer"] },
            { symbol: "gnutls_session_set_keylog_function", retType: "void", argTypes: ["pointer", "pointer"] },
            { symbol: "gnutls_session_get_random", retType: "pointer", argTypes: ["pointer", "pointer", "pointer"] },
        ],
        fdDecoder: (sslCtx, fns) => fns["gnutls_transport_get_int"](sslCtx) as number,
        sessionIdDecoder: gnuTlsSessionIdDecoder,
        readHook: {
            symbol: "gnutls_record_recv",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "gnutls_record_recv",
        },
        writeHook: {
            symbol: "gnutls_record_send",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "gnutls_record_send",
        },
        keylog: {
            kind: "callback_on_init",
            initSymbol: "gnutls_init",
            callbackInstaller: (session, fns) => {
                fns["gnutls_session_set_keylog_function"](session, keylog_callback);
            },
        },
        onNativeFunctionsResolved: (fns) => {
            _fns = fns;
        },
    };
}
