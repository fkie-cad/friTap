// Modern entry point for Flutter.framework / FlutterEngine on iOS.
// skipReadWriteHooks because Apple's static linker strips SSL_read/SSL_write
// too aggressively to install reliably — keylog-only matches legacy iOS.

import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeBoringSSLFamily } from "../../shared/boringssl_family_executor.js";

export { flutter_execute } from "../../../legacy/tls/platforms/ios/flutter_ios.js";

export function flutter_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeBoringSSLFamily(moduleName, socket_library, is_base_hook, enable_default_fd, {
        skipReadWriteHooks: true,
    });
}
