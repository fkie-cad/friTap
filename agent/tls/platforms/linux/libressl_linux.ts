// agent/tls/platforms/linux/libressl_linux.ts
//
// Modern (definition-based) LibreSSL executor for Linux.
//
// LibreSSL on Linux ships as libssl.so(.NN). The definition is platform-neutral;
// this is a thin re-bind onto Linux's socket_library (libc). enableDeepSymbolResolution
// lets the KDF symbols resolve from the symbol table of a statically linked ELF
// host; when even that is absent the definition falls back to byte patterns.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLibreSslDefinition } from "../../definitions/libressl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function libressl_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    executeFromDefinition(createLibreSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
