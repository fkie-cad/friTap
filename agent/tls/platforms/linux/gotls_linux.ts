// Modern Go crypto/tls executor for Linux.
//
// Go is the one TLS library whose symbol names (e.g.
// "crypto/tls.(*Config).writeKeyLog") and ABI (register-based parameter
// passing) defeat the standard HookDefinition pipeline. The modern path
// uses the data-driven definition with a custom .symbolResolver and a
// register-aware keylog hook (stripped binaries: writeKeyLog byte patterns).
// If the definition pipeline fails, the modern class-based GoTLS executor
// (../../libs/gotls.ts) takes over. The legacy executor (default, no --modern)
// is agent/legacy/tls/platforms/linux/gotls_linux.ts.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGoTlsDefinition } from "../../definitions/gotls.js";
import { gotls_execute_class_based } from "../../libs/gotls.js";
import { GO_WRITE_KEYLOG_PATTERNS, GoKeyLogArchPatterns } from "../../shared/go_keylog_hook.js";
import { devlog } from "../../../util/log.js";

/**
 * writeKeyLog entry patterns for the class-based fallback: x64/arm64 shared with the definition;
 * the x86/arm32 entries are C-style prologues, unverified against Go binaries.
 */
const GO_LINUX_KEYLOG_PATTERNS: GoKeyLogArchPatterns = {
    ...GO_WRITE_KEYLOG_PATTERNS,
    "x86": { primary: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60", fallback: "" },
    "arm": { primary: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0", fallback: "" },
};

export function gotls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    // executeFromDefinition is async: a failure is a rejected promise, not a throw.
    const fallBack = (e: unknown) => {
        devlog(`[gotls] modern definition failed on ${moduleName} (${e}); using the class-based GoTLS executor`);
        gotls_execute_class_based(moduleName, socket_library, is_base_hook, GO_LINUX_KEYLOG_PATTERNS);
    };
    try {
        executeFromDefinition(createGoTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd)
            .catch(fallBack);
    } catch (e) {
        fallBack(e);
    }
}
