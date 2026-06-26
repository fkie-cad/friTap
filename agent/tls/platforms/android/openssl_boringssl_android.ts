import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach, createSslReadWriteExHooks } from "../../definitions/openssl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    const def = createOpenSslDefinition({ includeExSymbols: true });

    // Use shared BoringSSL keylog callback installation
    def.keylog = createBoringSSLKeylogApproach();

    // Add SSL_read_ex / SSL_write_ex as extra hooks
    def.extraHooks = createSslReadWriteExHooks();

    // Tag as BoringSSL so the loader auto-installs the bssl::ssl_log_secret
    // symbol fallback when SSL_CTX_set_keylog_callback can't be resolved.
    def.libraryType = "boringssl";

    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

// libhttpengine.so statically links BoringSSL and exports the standard SSL_*
// surface, but may keep those symbols in .symtab rather than .dynsym. Opting the
// module into deep symbol resolution lets readAddresses fall back to
// enumerateSymbols(), so the stealthy SSL_CTX_set_keylog_callback (heap-write)
// keylog path resolves and installs — preferred over the bssl::ssl_log_secret
// code patch. The full callback → symbol → pattern chain is inherited unchanged
// from boring_execute_modern (def.libraryType = "boringssl").
export function httpengine_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    boring_execute_modern(moduleName, is_base_hook);
}
