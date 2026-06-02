// Windows Cronet — preserves the legacy exclusion list for backup/test variants.

import { socket_library } from "../../../platforms/windows.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { cronetExecuteModern } from "../../shared/cronet_modern.js";
import { devlog_debug } from "../../../util/log.js";

export { cronet_execute } from "../../../legacy/tls/platforms/windows/cronet_windows.js";

const EXCLUDED_MODULE_SUFFIXES = ["_backup.dll", "_old.dll"];
const EXCLUDED_MODULE_PREFIXES = ["test_"];

export function cronet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    const lower = moduleName.toLowerCase();
    if (EXCLUDED_MODULE_SUFFIXES.some((s) => lower.endsWith(s)) ||
        EXCLUDED_MODULE_PREFIXES.some((p) => lower.startsWith(p))) {
        devlog_debug(`Skipping module ${moduleName} due to excluded suffix/prefix.`);
        return;
    }
    cronetExecuteModern(moduleName, socket_library as string, is_base_hook, enable_default_fd);
}
