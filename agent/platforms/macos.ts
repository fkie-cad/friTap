import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader } from "../shared/shared_functions.js";
import { Platform, PLATFORM_DARWIN } from "../shared/shared_structures.js";
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/macos/openssl_boringssl_macos.js";
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/macos/openssl_boringssl_macos.js";
import { cronet_execute } from "../legacy/tls/platforms/macos/cronet_macos.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";


var plattform_name: Platform = PLATFORM_DARWIN;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "MacOS", is_base_hook, selected_protocol)
}



export function load_macos_hooking_agent() {
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "BoringSSL", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        // SSH libraries
        { platform: plattform_name, pattern: /.*libssh2?\.dylib/, hookFn: ssh_detect_execute, library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*sshd/, hookFn: ssh_detect_execute, library: "OpenSSH", protocol: "ssh" },
    ]);

    hook_macOS_SSL_Libs(hookRegistry, true); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader({
        platform: plattform_name,
        platformLabel: "MacOS",
        loaderLibrary: /libSystem.B.dylib/,
        functionName: "dlopen",
    }, hookRegistry, moduleNames, false, selected_protocol);
}