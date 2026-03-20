// agent/tls/platforms/macos/libressl_macos.ts
//
// Modern (definition-based) LibreSSL executor for macOS.

import { socket_library } from "../../../platforms/macos.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLibreSslDefinition } from "../../definitions/libressl.js";

export function libressl_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createLibreSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
