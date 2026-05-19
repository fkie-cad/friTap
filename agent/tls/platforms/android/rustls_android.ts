// Modern Rustls executor for Android. Same shape as Linux: symbolic
// rustls-ffi → modern definition; stripped → legacy pattern path
// (which handles librustls_android_13.so / _ex.so variants).

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createRustlsDefinition } from "../../definitions/rustls.js";
import { hasMoreThanFiveExports } from "../../../legacy/shared/shared_functions_legacy.js";
import { rustls_execute as rustls_execute_legacy } from "../../../legacy/tls/platforms/android/rustls_android.js";

export { rustls_execute } from "../../../legacy/tls/platforms/android/rustls_android.js";

export function rustls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    if (hasMoreThanFiveExports(moduleName)) {
        executeFromDefinition(
            createRustlsDefinition(),
            moduleName,
            socket_library,
            is_base_hook,
            enable_default_fd,
        );
    } else {
        rustls_execute_legacy(moduleName, is_base_hook);
    }
}
