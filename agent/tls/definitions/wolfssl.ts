// agent/tls/definitions/wolfssl.ts
//
// Data-driven WolfSSL hook definition.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { toHexString } from "../../shared/shared_functions.js";
import { log } from "../../util/log.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { enable_default_fd } from "../../fritap_agent.js";
import { STANDARD_SOCKET_SYMBOLS, DUMMY_SESSION_ID_WOLFSSL } from "./shared_constants.js";

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

function wolfSslExtractKeys(ssl: NativePointer, fns: ResolvedFunctions): void {
    const session = fns["wolfSSL_get_session"](ssl) as NativePointer;
    let keysString = "";

    const requiredClientRandomLength = fns["wolfSSL_get_client_random"](session, NULL, 0) as number;
    const clientBuffer = Memory.alloc(requiredClientRandomLength);
    fns["wolfSSL_get_client_random"](ssl, clientBuffer, requiredClientRandomLength);
    const clientBytes = clientBuffer.readByteArray(requiredClientRandomLength);
    keysString = `${keysString}CLIENT_RANDOM: ${toHexString(clientBytes)}\n`;

    const requiredServerRandomLength = fns["wolfSSL_get_server_random"](session, NULL, 0) as number;
    const serverBuffer = Memory.alloc(requiredServerRandomLength);
    fns["wolfSSL_get_server_random"](ssl, serverBuffer, requiredServerRandomLength);
    const serverBytes = serverBuffer.readByteArray(requiredServerRandomLength);
    keysString = `${keysString}SERVER_RANDOM: ${toHexString(serverBytes)}\n`;

    const requiredMasterKeyLength = fns["wolfSSL_SESSION_get_master_key"](session, NULL, 0) as number;
    const masterBuffer = Memory.alloc(requiredMasterKeyLength);
    fns["wolfSSL_SESSION_get_master_key"](session, masterBuffer, requiredMasterKeyLength);
    const masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength);
    keysString = `${keysString}MASTER_KEY: ${toHexString(masterBytes)}\n`;

    sendKeylog(keysString);
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
        fdDecoder: (sslCtx, fns) => fns["wolfSSL_get_fd"](sslCtx) as number,
        sessionIdDecoder: wolfSslSessionIdDecoder,
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
    };
}
