
import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createNssDefinition } from "../../definitions/nss.js";

export function nss_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createNssDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
