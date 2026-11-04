// Modern Go crypto/tls executor for Android. Same shape as Linux —
// see ../linux/gotls_linux.ts for the architectural rationale. The legacy
// executor (default, no --modern) is agent/legacy/tls/platforms/android/gotls_android.ts.

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createGoTlsDefinition } from "../../definitions/gotls.js";
import { gotls_execute_class_based } from "../../libs/gotls.js";
import { GO_WRITE_KEYLOG_PATTERNS, GoKeyLogArchPatterns } from "../../shared/go_keylog_hook.js";
import { devlog } from "../../../util/log.js";

/** As on Linux; the arm32 entries differ (unverified against Go binaries). */
const GO_ANDROID_KEYLOG_PATTERNS: GoKeyLogArchPatterns = {
    ...GO_WRITE_KEYLOG_PATTERNS,
    "x86": { primary: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60", fallback: "" },
    "arm": {
        primary: "08 10 9A E5 01 00 5D E1 63 00 00 9A 5C E0 2D E5 60 20 9D E5 AC 30 92 E5",
        fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0",
    },
};

export function gotls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    const fallBack = (e: unknown) => {
        devlog(`[gotls] modern definition failed on ${moduleName} (${e}); using the class-based GoTLS executor`);
        gotls_execute_class_based(moduleName, socket_library, is_base_hook, GO_ANDROID_KEYLOG_PATTERNS);
    };
    try {
        executeFromDefinition(createGoTlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd)
            .catch(fallBack);
    } catch (e) {
        fallBack(e);
    }
}
