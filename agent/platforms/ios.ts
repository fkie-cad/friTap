import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader } from "../shared/shared_functions.js";
import { Platform, PLATFORM_DARWIN } from "../shared/shared_structures.js";
import { boring_execute } from "../legacy/tls/platforms/ios/openssl_boringssl_ios.js";
import { boring_execute_modern } from "../tls/platforms/ios/openssl_boringssl_ios.js";
import { cronet_execute } from "../legacy/tls/platforms/ios/cronet_ios.js";
import { flutter_execute } from "../tls/platforms/ios/flutter_ios.js"


var plattform_name: Platform = PLATFORM_DARWIN;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "iOS", is_base_hook, selected_protocol)
}



export function load_ios_hooking_agent() {
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "BoringSSL", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*flutter.*\.dylib/, hookFn: flutter_execute, library: "Flutter BoringSSL", libraryType: "boringssl" },
    ]);

    hook_iOS_SSL_Libs(hookRegistry, true);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader({
        platform: plattform_name,
        platformLabel: "iOS",
        loaderLibrary: /libSystem.B.dylib/,
        functionName: "dlopen",
    }, hookRegistry, moduleNames, false, selected_protocol);
}