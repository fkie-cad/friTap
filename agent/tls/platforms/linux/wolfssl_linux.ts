import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createWolfSslDefinition } from "../../definitions/wolfssl.js";

export function wolfssl_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createWolfSslDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
