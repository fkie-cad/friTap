// agent/legacy/tls/platforms/linux/libressl_linux.ts
//
// Legacy (class-based) LibreSSL executor for Linux. Reuses the platform-neutral
// LibreSSL class (defined in the macOS legacy file) bound to Linux's
// socket_library (libc). enableDeepSymbolResolution helps the KDF symbols
// resolve inside a statically linked ELF host.

import { LibreSSL_MacOS } from "../macos/libressl_macos.js";
import { socket_library } from "../../../../platforms/linux.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";

export function libressl_execute(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(LibreSSL_MacOS, moduleName, socket_library, is_base_hook);
}
