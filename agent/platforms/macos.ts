import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks } from "../shared/shared_functions.js";
import { Platform, PLATFORM_DARWIN } from "../shared/shared_structures.js";
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/macos/openssl_boringssl_macos.js";
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/macos/openssl_boringssl_macos.js";
import { libressl_execute } from "../legacy/tls/platforms/macos/libressl_macos.js";
import { libressl_execute_modern } from "../tls/platforms/macos/libressl_macos.js";
import { cronet_execute } from "../legacy/tls/platforms/macos/cronet_macos.js";
import { nss_execute } from "../legacy/tls/platforms/macos/nss_macos.js";
import { nss_execute_modern } from "../tls/platforms/macos/nss_macos.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { nss_hpke_execute_macos } from "../ohttp/platforms/macos/nss_hpke_macos.js";
import { quiche_execute } from "../quic/platforms/macos/quiche_macos.js";
import { google_quiche_execute } from "../quic/platforms/macos/google_quiche_macos.js";
import { neqo_execute } from "../quic/platforms/macos/neqo_macos.js";


var plattform_name: Platform = PLATFORM_DARWIN;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "MacOS", is_base_hook, selected_protocol)
}



export function load_macos_hooking_agent() {
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "BoringSSL", libraryType: "boringssl" },
        // LibreSSL (macOS system SSL at /usr/lib/libssl.*.dylib) — must be before generic OpenSSL
        { platform: plattform_name, pattern: /libssl\.\d+\.dylib/, hookFn: (use_modern ? libressl_execute_modern : libressl_execute), library: "LibreSSL", pathFilter: "/usr/lib/", priority: 150, libraryType: "libressl" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*libssl.*\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", excludePattern: /^libssl\.\d+\.dylib$/, libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libnss[0-9]*\.dylib/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss" },
        // SSH libraries
        { platform: plattform_name, pattern: /.*libssh2?\.dylib/, hookFn: ssh_detect_execute, library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*sshd/, hookFn: ssh_detect_execute, library: "OpenSSH", protocol: "ssh" },
        // OHTTP (NSS HPKE) hooks
        { platform: plattform_name, pattern: /.*libnss[0-9]*\.dylib/, hookFn: nss_hpke_execute_macos, library: "NSS HPKE (OHTTP)", protocol: "ohttp", libraryType: "nss_hpke" },
        // QUIC (Cloudflare QUICHE) hooks
        { platform: plattform_name, pattern: /.*libquiche\.dylib/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche" },
        { platform: plattform_name, pattern: /Google Chrome Framework/, hookFn: google_quiche_execute, library: "Google QUICHE (Chrome)", libraryType: "google_quiche" },
        // Neqo (Firefox HTTP/3) — module is "XUL" at /Applications/Firefox.app/Contents/MacOS/XUL
        { platform: plattform_name, pattern: /^XUL$/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo" },
    ]);

    hook_macOS_SSL_Libs(hookRegistry, true); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    const macosLoaderConfig = {
        platform: plattform_name,
        platformLabel: "MacOS",
        loaderLibrary: /libSystem.B.dylib/,
        functionName: "dlopen",
    };
    installOhttpHooks(plattform_name, hookRegistry, moduleNames, "MacOS", macosLoaderConfig);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader(macosLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
}