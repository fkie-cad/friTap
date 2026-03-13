
import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition } from "../../definitions/openssl.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // iOS uses struct-offset keylog via SSL_CTX_set_info_callback; v2 definition
    // only resolves addresses and stores init_addresses. Actual iOS keylog stays in v1 path.
    executeFromDefinition(createOpenSslDefinition({ skipReadWriteHooks: true }), moduleName, socket_library, is_base_hook, enable_default_fd);
}
