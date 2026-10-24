// agent/tls/platforms/windows/libressl_windows.ts
//
// Modern (definition-based) LibreSSL executor for Windows (and Wine PE).
//
// LibreSSL on Windows ships as libssl-NN.dll (and can be statically linked into
// an .exe such as curl-for-win's curl.exe). The definition is platform-neutral;
// this binds it onto the Windows socket_library (WS2_32.dll).
// enableDeepSymbolResolution lets the internal KDF symbols resolve from a PE
// symbol table where present; when stripped, the definition falls back to the
// bundled byte patterns (agent/shared/libressl_kdf.ts).

import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLibreSslDefinition } from "../../definitions/libressl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function libressl_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    executeFromDefinition(createLibreSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
