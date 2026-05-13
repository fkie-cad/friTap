
import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition } from "../../definitions/openssl.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // Windows: SSL_CTX_set_keylog_callback is not exported by default on most
    // BoringSSL-flavoured DLLs, so the v2 definition leaves keylog at
    // { kind: "none" } for read/write-only coverage. Tagging libraryType:
    // "boringssl" lets the loader auto-install the bssl::ssl_log_secret
    // symbol hook — for genuine OpenSSL DLLs this is a harmless symbol-table
    // walk that finds nothing and falls through; for BoringSSL forks it is
    // the only working keylog path on Windows.
    const def = createOpenSslDefinition();
    def.libraryType = "boringssl";
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

export function ssl_python_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createOpenSslDefinition({ includeExSymbols: true }), moduleName, socket_library, is_base_hook, enable_default_fd);
}
