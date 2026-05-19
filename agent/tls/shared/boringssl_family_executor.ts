// Shared executor for embedded-BoringSSL forks (Cronet variants, Flutter,
// Mono BTLS). All these families statically link BoringSSL with stripped
// symbols and bypass SSL_new from the host code, so the modern path needs
// the same recipe at every callsite:
//   - createOpenSslDefinition + optional read/write skip
//   - libraryType = "boringssl" → routes via the three-tier hook chain
//   - keylogPriority = "symbol-first" → tier 1 (callback) installs but
//     never fires on these forks; symbol/pattern tiers carry the keylog
//   - family marker drives tier 3c bundled pattern lookup

import { executeFromDefinition } from "../../core/loader.js";
import {
    createOpenSslDefinition,
    createBoringSSLKeylogApproach,
} from "../definitions/openssl.js";
import { detectBoringSSLFamily } from "../../shared/boringssl_family_detect.js";

export interface BoringSSLFamilyOptions {
    skipReadWriteHooks?: boolean;
    includeExSymbols?: boolean;
}

export function executeBoringSSLFamily(
    moduleName: string,
    socketLibrary: string,
    isBaseHook: boolean,
    enableDefaultFd: boolean,
    options: BoringSSLFamilyOptions = {},
): void {
    const def = createOpenSslDefinition({
        includeExSymbols: options.includeExSymbols ?? false,
        skipReadWriteHooks: options.skipReadWriteHooks ?? false,
    });

    def.libraryType = "boringssl";
    def.keylog = createBoringSSLKeylogApproach();
    def.keylogPriority = "symbol-first";
    def.family = detectBoringSSLFamily(moduleName);

    executeFromDefinition(def, moduleName, socketLibrary, isBaseHook, enableDefaultFd);
}
