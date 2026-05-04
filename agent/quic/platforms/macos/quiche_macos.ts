import { socket_library } from "../../../platforms/macos.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createQuicheDefinition } from "../../definitions/quiche.js";

export function quiche_execute(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createQuicheDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
