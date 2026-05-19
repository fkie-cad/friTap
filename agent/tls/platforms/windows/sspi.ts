import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createSspiDefinition } from "../../definitions/sspi.js";

export { sspi_execute, SSPI_Windows } from "../../../legacy/tls/platforms/windows/sspi.js";

export function sspi_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(
        createSspiDefinition(),
        moduleName,
        socket_library,
        is_base_hook,
        enable_default_fd,
    );
}
