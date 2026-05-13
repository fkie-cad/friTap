import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import {
    createOpenSslDefinition,
    createBoringSSLKeylogApproach,
} from "../../definitions/openssl.js";

/**
 * Modern (definition-based) entry point for Cronet and Cronet-derived
 * libraries (libwarp_mobile, libsignal_jni, libringrtc_rffi, monochrome,
 * libquiche, etc.).
 *
 * Mirrors boring_execute_modern but is wired into Cronet registry entries so
 * that `use_modern = true` actually routes Cronet through the modern stack
 * instead of always falling back to the legacy cronet_execute. Tags the
 * definition as libraryType: "boringssl" so the loader routes through the
 * three-tier hook chain (agent/shared/boringssl_hook_chain.ts). Sets
 * keylogPriority="symbol-first" because Cronet-derived libs bypass SSL_new
 * internally — the SSL_CTX_set_keylog_callback path would install cleanly
 * but never fire at runtime on these modules.
 *
 * Late-load note: targets like libwarp_mobile.so are loaded after process
 * startup (often only when the user enables the VPN). No per-lib linker hook
 * is needed here — agent/shared/shared_functions.ts:hookDynamicLoader already
 * intercepts dlopen / android_dlopen_ext via the registry in
 * agent/platforms/android.ts and dispatches this executor on load.
 */
export function cronet_execute_modern(moduleName: string, is_base_hook: boolean) {
    const def = createOpenSslDefinition({ includeExSymbols: false });

    def.keylog = createBoringSSLKeylogApproach();
    def.libraryType = "boringssl";
    def.keylogPriority = "symbol-first";  // Cronet variants bypass SSL_new internally

    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
