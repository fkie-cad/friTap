
import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGnuTlsDefinition } from "../../definitions/gnutls.js";

export function gnutls_execute_modern(moduleName: string, is_base_hook: boolean) {
    executeFromDefinition(createGnuTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd);
}
