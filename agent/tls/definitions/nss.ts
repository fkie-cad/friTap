// agent/tls/definitions/nss.ts
//
// Data-driven NSS hook definition.
// NSS uses multiple libraries (nspr, libnss, libssl) and PRNetAddr for addressing.

import { HookDefinition, ClientRandomDecoder, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { NSS } from "../libs/nss.js";
import { installNssKeyExtraction } from "../libs/nss_install.js";
import { nssWindowsAuxiliaryLibraries, nssWindowsLibrarySymbols } from "../libs/nss_windows_libraries.js";

/** Delegates to ``NSS.extractClientRandom()`` which caches results. */
function createNssClientRandomDecoder(): ClientRandomDecoder {
    return (fd: NativePointer, _fns: ResolvedFunctions): string =>
        NSS.extractClientRandom(fd);
}

/**
 * Custom keylog installer for NSS. Delegates all tier logic (keylog-writer hook,
 * SSL_SecretCallback API, old-NSS offset table) to the shared installer, which
 * scopes itself to the module owning SSL_ImportFD. Resolves false if nothing was installed.
 */
export function installNssKeylog(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    _resolvedFns: ResolvedFunctions,
    _enableDefaultFd: boolean,
): Promise<boolean> {
    const modAddrs = addresses[moduleName];
    if (!modAddrs) return Promise.resolve(false);
    return installNssKeyExtraction(moduleName, modAddrs);
}

// macOS variant: Firefox bundles all NSS/NSPR/SSL symbols into a single libnss3.dylib,
// so SSL_* symbols must be looked up in *libnss* rather than a separate *libssl*.so
export function createNssMacosDefinition(): HookDefinition {
    const base = createNssDefinition();
    return {
        ...base,
        functions: {
            ...base.functions,
            auxiliaryLibraries: [
                { pattern: "*libnss*", symbols: ["PK11_ExtractKeyValue", "PK11_GetKeyData", "SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI", "NSSSSL_GetVersion"] },
            ],
        },
    };
}

// Windows variant: the Linux aux globs (*libnss*, *libssl*.so) never match a DLL. A folded
// nss3.dll (Firefox/Thunderbird) resolves everything in the hooked module; an unfolded
// (lib)nspr4.dll resolves SSL_* from (lib)ssl3.dll and PK11_* from (lib)nss3.dll.
export function createNssWindowsDefinition(moduleName: string): HookDefinition {
    const base = createNssDefinition();
    return {
        ...base,
        functions: {
            ...base.functions,
            librarySymbols: nssWindowsLibrarySymbols(moduleName),
            auxiliaryLibraries: nssWindowsAuxiliaryLibraries(moduleName),
        },
    };
}

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
                { pattern: "*libnss*", symbols: ["PK11_ExtractKeyValue", "PK11_GetKeyData", "NSSSSL_GetVersion"] },
                { pattern: "*libssl*.so", symbols: ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI"] },
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
        clientRandomDecoder: createNssClientRandomDecoder(),
        keylog: { kind: "custom", install: installNssKeylog },
    };
}
