// Modern entry point for libmono-btls-shared.so — BoringSSL statically
// embedded in Mono / Xamarin / .NET MAUI Android apps.

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeBoringSSLFamily } from "../../shared/boringssl_family_executor.js";

export { mono_btls_execute } from "../../../legacy/tls/platforms/android/mono_btls_android.js";

export function mono_btls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    executeBoringSSLFamily(moduleName, socket_library, is_base_hook, enable_default_fd);
}
