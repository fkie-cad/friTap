// Legacy (default, no --modern) Go crypto/tls executor for MacOS: the shared desktop executor
// (../../libs/gotls_native.ts) with the MacOS socket library. The platform row finds Go images
// by content (shared/go_binary_detection.ts). The modern executor (--modern) is
// agent/tls/platforms/macos/gotls_macos.ts.

import { socket_library } from "../../../../platforms/macos.js";
import { gotls_execute_native } from "../../libs/gotls_native.js";

export function gotls_execute(moduleName: string, is_base_hook: boolean): void {
    gotls_execute_native(moduleName, socket_library, is_base_hook);
}
