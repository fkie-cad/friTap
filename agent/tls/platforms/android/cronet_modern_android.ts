import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { cronetExecuteModern } from "../../shared/cronet_modern.js";

// Modern (definition-based) entry point for Cronet and Cronet-derived
// libraries (libwarp_mobile, libsignal_jni, libringrtc_rffi, monochrome,
// libquiche, etc.). Routes through the three-tier BoringSSL chain so
// stripped Cronet monoliths still get keylog via bundled patterns.
//
// Late-load note: agent/shared/shared_functions.ts:hookDynamicLoader picks
// up dlopen / android_dlopen_ext events and dispatches this executor when
// modules matching the registry patterns appear.
export function cronet_execute_modern(moduleName: string, is_base_hook: boolean): void {
    cronetExecuteModern(moduleName, socket_library as string, is_base_hook, enable_default_fd);
}
