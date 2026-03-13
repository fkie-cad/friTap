// agent/tls/definitions/nss.ts
//
// Data-driven NSS hook definition.
// NSS uses multiple libraries (nspr, libnss, libssl) and PRNetAddr for addressing.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";

export function createNssDefinition(): HookDefinition {
    return {
        libraryId: "nss",
        offsetKey: "nss",
        functions: {
            librarySymbols: [
                "PR_Write",
                "PR_Read",
                "PR_FileDesc2NativeHandle",
                "PR_GetPeerName",
                "PR_GetSockName",
                "PR_GetNameForIdentity",
                "PR_GetDescType",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
            auxiliaryLibraries: [
                { pattern: "*libnss*", symbols: ["PK11_ExtractKeyValue", "PK11_GetKeyData"] },
                { pattern: "*libssl*.so", symbols: ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"] },
            ],
        },
        nativeFunctions: [
            { symbol: "PR_GetPeerName", retType: "int", argTypes: ["pointer", "pointer"] },
            { symbol: "PR_GetSockName", retType: "int", argTypes: ["pointer", "pointer"] },
            { symbol: "PR_FileDesc2NativeHandle", retType: "int", argTypes: ["pointer"] },
            { symbol: "SSL_GetSessionID", retType: "pointer", argTypes: ["pointer"] },
        ],
        fdDecoder: (sslCtx, fns) => {
            if (!fns["PR_FileDesc2NativeHandle"]) return 0;
            return fns["PR_FileDesc2NativeHandle"](sslCtx) as number;
        },
        sessionIdDecoder: (sslCtx, fns) => {
            if (!fns["SSL_GetSessionID"]) return "0";
            const secItem = fns["SSL_GetSessionID"](sslCtx) as NativePointer;
            if (secItem.isNull()) return "0";
            // SECItem struct: { SECItemType type (4 bytes + padding); unsigned char *data; unsigned int len; }
            // On 64-bit: type at offset 0 (4 bytes + 4 padding), data pointer at offset 8, len at offset 16
            // On 32-bit: type at offset 0 (4 bytes), data pointer at offset 4, len at offset 8
            // Process.pointerSize gives the correct offset for both cases due to alignment
            const dataPtr = secItem.add(Process.pointerSize).readPointer();
            const len = secItem.add(Process.pointerSize + Process.pointerSize).readU32();
            if (len === 0 || dataPtr.isNull()) return "0";
            return readHexFromPointer(dataPtr, len);
        },
        readHook: {
            symbol: "PR_Read",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" },
            functionLabel: "PR_Read",
        },
        writeHook: {
            symbol: "PR_Write",
            args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" },
            functionLabel: "PR_Write",
        },
        keylog: { kind: "none" },
    };
}
