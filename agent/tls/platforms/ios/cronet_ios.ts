// iOS Cronet — keylog-only (legacy iOS Cronet never installed plaintext hooks).

import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeBoringSSLFamily } from "../../shared/boringssl_family_executor.js";

export { cronet_execute } from "../../../legacy/tls/platforms/ios/cronet_ios.js";

export function cronet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeBoringSSLFamily(moduleName, socket_library, is_base_hook, enable_default_fd, {
        skipReadWriteHooks: true,
    });
}
