// Modern Rustls executor for Linux. When rustls-ffi symbols are present we
// route through the HookDefinition pipeline. Stripped builds (no exports)
// fall back to the legacy pattern-based path which already handles
// derive_logged_secrets / derive_secrets pattern scans.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createRustlsDefinition } from "../../definitions/rustls.js";
import { hasMoreThanFiveExports } from "../../../legacy/shared/shared_functions_legacy.js";
import { rustls_execute as rustls_execute_legacy } from "../../../legacy/tls/platforms/linux/rustls_linux.js";

export { rustls_execute } from "../../../legacy/tls/platforms/linux/rustls_linux.js";

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
        // Stripped binary — modern definition can't resolve symbols. Defer to
        // legacy pattern path which already has the TLS 1.2 PRF + TLS 1.3
        // derive_logged_secrets patterns wired.
        rustls_execute_legacy(moduleName, is_base_hook);
    }
}
