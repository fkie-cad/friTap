import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { cronetExecuteModern } from "../../shared/cronet_modern.js";

export { cronet_execute } from "../../../legacy/tls/platforms/linux/cronet_linux.js";

export function cronet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    cronetExecuteModern(moduleName, socket_library as string, is_base_hook, enable_default_fd);
}
