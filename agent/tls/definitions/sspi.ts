// SSPI (secur32/sspicli) hook definition. Covers two responsibilities:
//   1. Plaintext capture via EncryptMessage / DecryptMessage. SecBufferDesc
//      traversal does not fit the generic single-symbol executor, so the
//      work lives inside keylog.kind == "custom".
//   2. ncrypt.dll keylog (TLS 1.2 + 1.3), gated by --experimental because
//      the struct offsets are Windows-version sensitive. Shares the
//      implementation in ../decoders/ncrypt_keylog.ts with LSASS.

import {
    HookDefinition,
    ResolvedFunctions,
} from "../../core/hook_definition.js";
import { sendDatalog } from "../../shared/shared_structures.js";
import { devlog, log } from "../../util/log.js";
import { pcap_enabled, experimental } from "../../fritap_agent.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";
import { installNcryptKeylogHooks } from "../decoders/ncrypt_keylog.js";

// SecBuffer: ULONG + ULONG + PVOID — 16 on 64-bit, 12 on 32-bit.
// Legacy hardcoded 16 (silently broken on Win32).
const SECBUFFER_STRIDE = Process.pointerSize === 8 ? 16 : 12;
const SECBUFFER_TYPE_DATA = 1;

interface CapturedSecBuffer {
    size: number;
    type: number;
    bufferPointer: NativePointer;
}

function parseSecBufferDesc(pMessage: NativePointer): CapturedSecBuffer[] {
    const cBuffers = pMessage.add(4).readU32();
    const pBuffers = pMessage.add(8).readPointer();
    const out: CapturedSecBuffer[] = [];
    for (let i = 0; i < cBuffers; i++) {
        const sb = pBuffers.add(i * SECBUFFER_STRIDE);
        out.push({
            size: sb.add(0).readU32(),
            type: sb.add(4).readU32(),
            bufferPointer: sb.add(8).readPointer(),
        });
    }
    return out;
}

// SSPI gives no socket context; emit stable loopback sentinel. Port pair
// flips per direction so downstream pcap writers distinguish streams.
function makeSspiMessage(
    functionLabel: string,
    isRead: boolean,
): { [key: string]: string | number } {
    return {
        ss_family: "AF_INET",
        src_addr: "127.0.0.1",
        dst_addr: "127.0.0.1",
        src_port: isRead ? 444 : 443,
        dst_port: isRead ? 443 : 444,
        function: functionLabel,
        ssl_session_id: 10,
    };
}

function emitSecBufferData(
    buffers: CapturedSecBuffer[],
    functionLabel: string,
    isRead: boolean,
): void {
    for (const sb of buffers) {
        if (sb.type !== SECBUFFER_TYPE_DATA) continue;
        if (sb.size === 0 || sb.bufferPointer.isNull()) continue;
        try {
            const bytes = sb.bufferPointer.readByteArray(sb.size);
            const message = makeSspiMessage(functionLabel, isRead);
            sendDatalog(message, bytes);
        } catch (e) {
            devlog(`[sspi] SecBuffer read error in ${functionLabel}: ${e}`);
        }
    }
}

function installSspiPlaintextHooks(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
): void {
    if (!pcap_enabled) return;

    const decryptAddr = addresses[moduleName]?.["DecryptMessage"];
    if (decryptAddr && !decryptAddr.isNull()) {
        Interceptor.attach(decryptAddr, {
            onEnter(args) {
                (this as any).pMessage = args[1];
            },
            onLeave() {
                try {
                    const buffers = parseSecBufferDesc((this as any).pMessage);
                    emitSecBufferData(buffers, "DecryptMessage", true);
                } catch (e) {
                    devlog(`[sspi] DecryptMessage onLeave error: ${e}`);
                }
            },
        });
    } else {
        devlog("[sspi] DecryptMessage unresolved – read plaintext capture disabled");
    }

    const encryptAddr = addresses[moduleName]?.["EncryptMessage"];
    if (encryptAddr && !encryptAddr.isNull()) {
        Interceptor.attach(encryptAddr, {
            onEnter(args) {
                // SSPI replaces SECBUFFER_DATA with ciphertext at onLeave —
                // plaintext must be captured at onEnter.
                try {
                    const buffers = parseSecBufferDesc(args[2]);
                    emitSecBufferData(buffers, "EncryptMessage", false);
                } catch (e) {
                    devlog(`[sspi] EncryptMessage onEnter error: ${e}`);
                }
            },
        });
    } else {
        devlog("[sspi] EncryptMessage unresolved – write plaintext capture disabled");
    }
}

function sspiFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}
function sspiSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

const NCRYPT_SYMBOLS = [
    "SslHashHandshake",
    "SslGenerateMasterKey",
    "SslImportMasterKey",
    "SslGenerateSessionKeys",
    "SslExpandTrafficKeys",
    "SslExpandExporterMasterKey",
];

export function createSspiDefinition(): HookDefinition {
    const auxiliaryLibraries = experimental
        ? [{ pattern: "*ncrypt*.dll", symbols: NCRYPT_SYMBOLS }]
        : undefined;

    if (experimental) {
        log("ncrypt.dll was loaded & will be hooked on Windows!");
    }

    return {
        libraryId: "sspi",
        offsetKey: "sspi",
        functions: {
            librarySymbols: ["EncryptMessage", "DecryptMessage"],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
            auxiliaryLibraries,
        },
        nativeFunctions: [],
        fdDecoder: sspiFdDecoder,
        sessionIdDecoder: sspiSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        keylog: {
            kind: "custom",
            install: (addresses, moduleName, _resolvedFns, _enableDefaultFd) => {
                installSspiPlaintextHooks(addresses, moduleName);
                if (!experimental) {
                    devlog("[sspi] --experimental not set; skipping ncrypt keylog hooks");
                    return true;
                }
                const ncryptInstalled = installNcryptKeylogHooks(addresses, moduleName, {
                    logPrefix: "[sspi]",
                    includeHkdfAlias: false,
                });
                if (!ncryptInstalled) {
                    devlog("[sspi] ncrypt.dll symbols unresolved – keylog disabled");
                }
                return true;
            },
        },
        libraryType: "sspi",
    };
}
