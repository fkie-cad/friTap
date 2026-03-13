import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach, createSslReadWriteExHooks } from "../../definitions/openssl.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    const def = createOpenSslDefinition({ includeExSymbols: true });

    // Use shared BoringSSL keylog callback installation
    def.keylog = createBoringSSLKeylogApproach();

    // Add SSL_read_ex / SSL_write_ex as extra hooks
    def.extraHooks = createSslReadWriteExHooks();

    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
