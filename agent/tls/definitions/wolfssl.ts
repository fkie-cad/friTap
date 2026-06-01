// agent/tls/definitions/wolfssl.ts
//
// Data-driven WolfSSL hook definition.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { log, devlog } from "../../util/log.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { enable_default_fd } from "../../fritap_agent.js";
import { STANDARD_SOCKET_SYMBOLS, DUMMY_SESSION_ID_WOLFSSL } from "./shared_constants.js";
import { createLifecycleHook, createBufferedClientRandomDecoder } from "./shared_factories.js";

function wolfSslSessionIdDecoder(ssl: NativePointer, fns: ResolvedFunctions): string {
    const session = fns["wolfSSL_get_session"](ssl) as NativePointer;
    if (session.isNull()) {
        if (enable_default_fd) {
            log("using dummy SessionID: " + DUMMY_SESSION_ID_WOLFSSL);
            return DUMMY_SESSION_ID_WOLFSSL;
        }
        log("Session is null");
        return "";
    }
    const p = session.add(8);
    const len = 32;
    return readHexFromPointer(p, len);
}

/**
 * Read one buffered key field via a WolfSSL getter that follows the
 * `int get(ctx, out, outlen)` shape: call with (lengthCtx, NULL, 0) to query
 * the size, then with (readCtx, buffer, len) to fill it. Returns the formatted
 * "LABEL: <hex>\n" line, or "" when the getter is unavailable or yields nothing.
 *
 * `fn` may be undefined when the target WolfSSL build does not export the
 * symbol (e.g. compiled without OPENSSL_EXTRA) — in that case we skip the field
 * instead of crashing with "is not a function".
 */
function extractBufferedKey(
    fn: ((...a: any[]) => any) | undefined,
    lengthCtx: NativePointer,
    readCtx: NativePointer,
    label: string,
): string {
    if (!fn) {
        devlog(`[wolfssl] ${label} extraction function unavailable; skipping`);
        return "";
    }
    const len = fn(lengthCtx, NULL, 0) as number;
    if (len <= 0) return "";
    const buffer = Memory.alloc(len);
    fn(readCtx, buffer, len);
    return `${label}: ${toHexString(buffer.readByteArray(len))}\n`;
}

// Emit the wolfSSL_KeepArrays advisory only once per process to avoid spamming
// the (per-connect) extraction path.
let keepArraysNoticeLogged = false;

function logKeepArraysNotice(): void {
    if (keepArraysNoticeLogged) return;
    keepArraysNoticeLogged = true;
    devlog(
        "[wolfssl] note: client/server random and master secret are only retained " +
        "if wolfSSL_KeepArrays() was called before the handshake. Without it, wolfSSL " +
        "frees these arrays after the handshake and the extracted values may be zeroed.",
    );
}

function wolfSslExtractKeys(ssl: NativePointer, fns: ResolvedFunctions): void {
    try {
        logKeepArraysNotice();
        const getSession = fns["wolfSSL_get_session"];
        if (!getSession) {
            devlog("[wolfssl] wolfSSL_get_session unavailable; cannot extract keys");
            return;
        }
        const session = getSession(ssl) as NativePointer;
        if (session.isNull()) {
            devlog("[wolfssl] session is null; cannot extract keys");
            return;
        }

        // Preserve existing call semantics: client/server random length is
        // queried with the session pointer but read from the ssl pointer; the
        // master key uses the session pointer for both.
        let keysString = "";
        keysString += extractBufferedKey(fns["wolfSSL_get_client_random"], session, ssl, "CLIENT_RANDOM");
        keysString += extractBufferedKey(fns["wolfSSL_get_server_random"], session, ssl, "SERVER_RANDOM");
        keysString += extractBufferedKey(fns["wolfSSL_SESSION_get_master_key"], session, session, "MASTER_KEY");

        if (keysString.length === 0) {
            devlog("[wolfssl] no key material extracted (export functions unavailable)");
            return;
        }

        devlog("invoking keylog dump from wolfSSL");
        sendKeylog(keysString);
    } catch (e) {
        devlog(`[wolfssl] key extraction failed: ${e}`);
    }
}

const wolfSslClientRandomDecoder = createBufferedClientRandomDecoder("wolfSSL_get_client_random");

function wolfSslFdDecoder(sslCtx: NativePointer, fns: ResolvedFunctions): number {
    return fns["wolfSSL_get_fd"](sslCtx) as number;
}

export function createWolfSslDefinition(): HookDefinition {
    return {
        libraryId: "wolfssl",
        offsetKey: "wolfssl",
        functions: {
            librarySymbols: [
                "wolfSSL_read",
                "wolfSSL_write",
                "wolfSSL_get_fd",
                "wolfSSL_get_session",
                "wolfSSL_connect",
                "wolfSSL_KeepArrays",
                "wolfSSL_SESSION_get_master_key",
                "wolfSSL_get_client_random",
                "wolfSSL_get_server_random",
                "wolfSSL_free",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [
            { symbol: "wolfSSL_get_fd", retType: "int", argTypes: ["pointer"] },
            { symbol: "wolfSSL_get_session", retType: "pointer", argTypes: ["pointer"] },
            { symbol: "wolfSSL_get_client_random", retType: "int", argTypes: ["pointer", "pointer", "int"] },
            { symbol: "wolfSSL_get_server_random", retType: "int", argTypes: ["pointer", "pointer", "int"] },
            { symbol: "wolfSSL_SESSION_get_master_key", retType: "int", argTypes: ["pointer", "pointer", "int"] },
        ],
        fdDecoder: wolfSslFdDecoder,
        sessionIdDecoder: wolfSslSessionIdDecoder,
        clientRandomDecoder: wolfSslClientRandomDecoder,
        readHook: {
            symbol: "wolfSSL_read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "wolfSSL_read",
        },
        writeHook: {
            symbol: "wolfSSL_write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "wolfSSL_write",
        },
        keylog: {
            kind: "manual_on_connect",
            connectSymbol: "wolfSSL_connect",
            extractKeys: wolfSslExtractKeys,
        },
        extraHooks: [
            createLifecycleHook("wolfSSL_free", wolfSslFdDecoder, wolfSslSessionIdDecoder, wolfSslClientRandomDecoder),
        ],
    };
}
