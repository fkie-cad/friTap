import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createMbedTlsDefinition } from "../../definitions/mbedtls.js";

export function mbedTLS_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createMbedTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
