import { socket_library } from "../../../platforms/macos.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createNeqoDefinition } from "../../definitions/neqo.js";

export function neqo_execute(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createNeqoDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
