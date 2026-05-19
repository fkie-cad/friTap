// LSASS (ncrypt.dll) hook definition. Runs in a separate Frida session
// attached to lsass.exe via load_windows_lsass_agent. Keylog-only — no
// plaintext capture (legacy intentionally stubs the read/write hooks).

import {
    HookDefinition,
    ResolvedFunctions,
} from "../../core/hook_definition.js";
import { devlog } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";
import { installNcryptKeylogHooks } from "../decoders/ncrypt_keylog.js";

function lsassFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}
function lsassSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

export function createLsassDefinition(): HookDefinition {
    return {
        libraryId: "lsass",
        offsetKey: "lsass",
        functions: {
            librarySymbols: [
                "SslHashHandshake",
                "SslGenerateMasterKey",
                "SslImportMasterKey",
                "SslGenerateSessionKeys",
                "SslExpandTrafficKeys",
                "SslExpandExporterMasterKey",
                "SslGenerateSessionKeysHkdf",
            ],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        fdDecoder: lsassFdDecoder,
        sessionIdDecoder: lsassSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        keylog: {
            kind: "custom",
            install: (addresses, moduleName, _resolvedFns, _enableDefaultFd) => {
                const installed = installNcryptKeylogHooks(addresses, moduleName, {
                    logPrefix: "[lsass]",
                    includeHkdfAlias: true,
                });
                if (!installed) {
                    devlog("[lsass] no ncrypt symbols resolved – keylog disabled");
                }
                return installed;
            },
        },
        libraryType: "lsass",
    };
}
