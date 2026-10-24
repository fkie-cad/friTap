// agent/legacy/tls/platforms/windows/libressl_windows.ts
//
// Legacy (class-based) LibreSSL executor for Windows (and Wine PE). Reuses the
// platform-neutral LibreSSL class (defined in the macOS legacy file) bound to
// the Windows socket_library (WS2_32.dll). enableDeepSymbolResolution helps the
// internal KDF symbols resolve from a PE symbol table where present; a stripped
// static host falls back to the bundled byte patterns.

import { LibreSSL_MacOS } from "../macos/libressl_macos.js";
import { socket_library } from "../../../../platforms/windows.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";

export function libressl_execute(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(LibreSSL_MacOS, moduleName, socket_library, is_base_hook);
}
