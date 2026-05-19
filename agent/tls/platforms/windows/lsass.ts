import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createLsassDefinition } from "../../definitions/lsass.js";

export { lsass_execute, LSASS_Windows } from "../../../legacy/tls/platforms/windows/lsass.js";

export function lsass_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeFromDefinition(
        createLsassDefinition(),
        moduleName,
        socket_library,
        is_base_hook,
        enable_default_fd,
    );
}
