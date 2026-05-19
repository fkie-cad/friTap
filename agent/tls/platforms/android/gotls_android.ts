// Modern Go crypto/tls executor for Android. Same shape as Linux —
// see ./linux/gotls_linux.ts for the architectural rationale.

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGoTlsDefinition } from "../../definitions/gotls.js";
import { gotls_execute as gotls_execute_legacy } from "../../../legacy/tls/platforms/android/gotls_android.js";

export { gotls_execute } from "../../../legacy/tls/platforms/android/gotls_android.js";

export function gotls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    try {
        executeFromDefinition(
            createGoTlsDefinition(),
            moduleName,
            socket_library,
            is_base_hook,
            enable_default_fd,
        );
    } catch (e) {
        gotls_execute_legacy(moduleName, is_base_hook);
    }
}
