// Modern entry point for the Flutter Engine on Android (libflutter.so).
// Flutter statically links BoringSSL with stripped symbols — same shape as
// Cronet, routed through the three-tier chain via executeBoringSSLFamily.

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeBoringSSLFamily } from "../../shared/boringssl_family_executor.js";

export { flutter_execute } from "../../../legacy/tls/platforms/android/flutter_android.js";

export function flutter_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeBoringSSLFamily(moduleName, socket_library, is_base_hook, enable_default_fd);
}
