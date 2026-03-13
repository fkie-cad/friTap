import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createS2nTlsDefinition } from "../../definitions/s2ntls.js";

export function s2ntls_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createS2nTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
