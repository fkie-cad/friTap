// Modern Go crypto/tls executor for MacOS. Same shape as Linux — see
// ../linux/gotls_linux.ts for the rationale. Go links crypto/tls into the image itself
// (usually the main executable), so the platform row finds it by content
// (shared/go_binary_detection.ts), not by name. The legacy executor (default, no --modern)
// is agent/legacy/tls/platforms/macos/gotls_macos.ts.
//
// Go's ABIInternal is OS-independent: the amd64/arm64 register assignment (go_abi.ts) and
// the writeKeyLog entry patterns (go_keylog_hook.ts) hold on MacOS as on Linux.

import { socket_library } from "../../../platforms/macos.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGoTlsDefinition } from "../../definitions/gotls.js";
import { gotls_execute_class_based } from "../../libs/gotls.js";
import { devlog } from "../../../util/log.js";

export function gotls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    // executeFromDefinition is async: a failure is a rejected promise, not a throw.
    const fallBack = (e: unknown) => {
        devlog(`[gotls] modern definition failed on ${moduleName} (${e}); using the class-based GoTLS executor`);
        gotls_execute_class_based(moduleName, socket_library, is_base_hook);
    };
    try {
        executeFromDefinition(createGoTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd)
            .catch(fallBack);
    } catch (e) {
        fallBack(e);
    }
}
