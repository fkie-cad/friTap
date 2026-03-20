// agent/tls/definitions/nss.ts
//
// Data-driven NSS hook definition.
// NSS uses multiple libraries (nspr, libnss, libssl) and PRNetAddr for addressing.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";
import { NSS } from "../libs/nss.js";
import { devlog } from "../../util/log.js";

/**
 * Custom keylog installer for NSS.
 * Sets up:
 * 1. Version-dependent struct offsets
 * 2. SSL_SecretCallback via experimental API (TLS 1.3)
 * 3. SSL_ImportFD hook for per-connection secret callback registration
 * 4. SSL_HandshakeCallback interception for TLS 1.2 key extraction
 * 5. SSL_SecretCallback interceptor for Firefox override detection
 */
function installNssKeylog(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    _resolvedFns: ResolvedFunctions,
    _enableDefaultFd: boolean,
): void {
    const modAddrs = addresses[moduleName];
    if (!modAddrs) return;

    // Initialize version-dependent offsets + experimental API
    NSS.detectVersionOffsets();
    NSS.resolveExperimentalAPI();

    // Set up NativeFunctions needed by the NSS class
    if (modAddrs["PR_GetDescType"]) {
        NSS.getDescType = new NativeFunction(modAddrs["PR_GetDescType"], "int", ["pointer"]);
    }
    if (modAddrs["PR_GetNameForIdentity"]) {
        NSS.PR_GetNameForIdentity = new NativeFunction(modAddrs["PR_GetNameForIdentity"], "pointer", ["pointer"]);
    }
    if (modAddrs["SSL_HandshakeCallback"]) {
        NSS.get_SSL_Callback = new NativeFunction(modAddrs["SSL_HandshakeCallback"], "int", ["pointer", "pointer", "pointer"]);
    }
    if (modAddrs["PK11_ExtractKeyValue"]) {
        NSS.PK11_ExtractKeyValue = new NativeFunction(modAddrs["PK11_ExtractKeyValue"], "int", ["pointer"]);
    }
    if (modAddrs["PK11_GetKeyData"]) {
        NSS.PK11_GetKeyData = new NativeFunction(modAddrs["PK11_GetKeyData"], "pointer", ["pointer"]);
    }

    // Hook SSL_ImportFD to register callbacks on each new SSL connection
    const sslImportFdAddr = modAddrs["SSL_ImportFD"];
    if (sslImportFdAddr && !sslImportFdAddr.isNull()) {
        Interceptor.attach(sslImportFdAddr, {
            onEnter(args: any) {
                this.fd = args[1];
            },
            onLeave(retval: any) {
                if (retval.isNull()) {
                    devlog("[-] SSL_ImportFD error: unknown null");
                    return;
                }

                var retValue = NSS.get_SSL_Callback(retval, NSS.keylog_callback, NULL);
                NSS.register_secret_callback(retval);

                if (retValue < 0) {
                    devlog("Callback Error");
                } else {
                    devlog("[*] NSS keylog callback successfully installed");
                }
            }
        });
    }

    // Hook SSL_HandshakeCallback to intercept app's callback for TLS 1.2 key extraction
    const sslHandshakeCbAddr = modAddrs["SSL_HandshakeCallback"];
    if (sslHandshakeCbAddr && !sslHandshakeCbAddr.isNull()) {
        Interceptor.attach(sslHandshakeCbAddr, {
            onEnter(args: any) {
                this.originalCallback = args[1];
                Interceptor.attach(ptr(this.originalCallback), {
                    onEnter(args: any) {
                        var sslSocketFD = args[0];
                        devlog("[*] NSS keylog callback successfully installed via applications callback function");
                        NSS.ssl_RecordKeyLog(sslSocketFD);
                    },
                });
            },
        });
    }

    // Install SSL_SecretCallback interceptor for Firefox override detection
    NSS.installSecretCallbackInterceptor();

    devlog("[*] NSS modern keylog hooks installed");
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
                { pattern: "*libnss*", symbols: ["PK11_ExtractKeyValue", "PK11_GetKeyData", "SSL_ImportFD", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI", "NSSSSL_GetVersion"] },
            ],
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
        keylog: { kind: "custom", install: installNssKeylog },
    };
}
