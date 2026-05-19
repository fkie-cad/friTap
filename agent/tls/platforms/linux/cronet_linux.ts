import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeBoringSSLFamily } from "../../shared/boringssl_family_executor.js";

export { cronet_execute } from "../../../legacy/tls/platforms/linux/cronet_linux.js";

export function cronet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeBoringSSLFamily(moduleName, socket_library, is_base_hook, enable_default_fd);
}
