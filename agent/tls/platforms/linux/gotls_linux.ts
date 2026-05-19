// Modern Go crypto/tls executor for Linux.
//
// Go is the one TLS library whose symbol names (e.g.
// "crypto/tls.(*Config).writeKeyLog") and ABI (register-based parameter
// passing) defeat the standard HookDefinition pipeline. The modern path
// uses the data-driven definition with a custom .symbolResolver and a
// register-aware keylog hook; stripped binaries with no enumerable Go
// symbols fall back to the legacy pattern-based path.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGoTlsDefinition } from "../../definitions/gotls.js";
import { gotls_execute as gotls_execute_legacy } from "../../../legacy/tls/platforms/linux/gotls_linux.js";

export { gotls_execute } from "../../../legacy/tls/platforms/linux/gotls_linux.js";

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
        // Modern definition couldn't establish hooks (e.g. symbol cascade
        // returned nothing for a stripped binary) — fall back to the
        // legacy pattern-based path which carries the Go writeKeyLog
        // byte-pattern fallbacks.
        gotls_execute_legacy(moduleName, is_base_hook);
    }
}
