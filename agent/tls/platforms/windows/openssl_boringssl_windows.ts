
import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition } from "../../definitions/openssl.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // Windows: SSL_CTX_set_keylog_callback not exported by default.
    // v2 definition handles read/write hooks only; keylog stays as { kind: "none" }.
    executeFromDefinition(createOpenSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}

export function ssl_python_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createOpenSslDefinition({ includeExSymbols: true }), moduleName, socket_library, is_base_hook, enable_default_fd);
}
