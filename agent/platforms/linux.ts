import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader } from "../shared/shared_functions.js";
import { Platform, PLATFORM_LINUX } from "../shared/shared_structures.js";
// Modern (definition-based) executors
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/linux/openssl_boringssl_linux.js";
import { gnutls_execute_modern } from "../tls/platforms/linux/gnutls_linux.js";
import { wolfssl_execute_modern } from "../tls/platforms/linux/wolfssl_linux.js";
import { nss_execute_modern } from "../tls/platforms/linux/nss_linux.js";
import { mbedTLS_execute_modern } from "../tls/platforms/linux/mbedTLS_linux.js";
import { s2ntls_execute_modern } from "../tls/platforms/linux/s2ntls_linux.js";
// Legacy (class-based) executors
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/linux/openssl_boringssl_linux.js";
import { gnutls_execute } from "../legacy/tls/platforms/linux/gnutls_linux.js";
import { wolfssl_execute } from "../legacy/tls/platforms/linux/wolfssl_linux.js";
import { nss_execute } from "../legacy/tls/platforms/linux/nss_linux.js";
import { mbedTLS_execute } from "../legacy/tls/platforms/linux/mbedTLS_linux.js";
import { s2ntls_execute } from "../legacy/tls/platforms/linux/s2ntls_linux.js";
import { cronet_execute } from "../legacy/tls/platforms/linux/cronet_linux.js";
// V1-only (re-exported from legacy)
import { matrixSSL_execute } from "../tls/platforms/linux/matrixssl_linux.js";
import { rustls_execute } from "../tls/platforms/linux/rustls_linux.js";
import { gotls_execute } from "../tls/platforms/linux/gotls_linux.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";

var plattform_name: Platform = PLATFORM_LINUX;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Linux", is_base_hook, selected_protocol)
}


export function load_linux_hooking_agent() {
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*libssl.*\.so/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, excludePattern: /_(libpki|libcrypto)\.so$/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl" },
        { platform: plattform_name, pattern: /.*libnspr[0-9]?\.so/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls" },
        { platform: plattform_name, pattern: /libssl_s.a/, hookFn: matrixSSL_execute, library: "MatrixSSL", libraryType: "matrixssl" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: (use_modern ? s2ntls_execute_modern : s2ntls_execute), library: "s2n-tls", libraryType: "s2ntls" },
        { platform: plattform_name, pattern: /.*rustls.*/, hookFn: rustls_execute, library: "Rustls", libraryType: "rustls" },
        { platform: plattform_name, pattern: /.*\.go.so$/, hookFn: gotls_execute, library: "Go TLS", libraryType: "gotls" },
        { platform: plattform_name, pattern: /.*go[0-9.]+$/, hookFn: gotls_execute, library: "Go TLS", libraryType: "gotls" },
        // IPSec libraries (detection stubs — key extraction in Phase 3.8)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: ipsec_detect_execute, library: "strongSwan (charon)", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: ipsec_detect_execute, library: "strongSwan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libipsec\.so/, hookFn: ipsec_detect_execute, library: "strongSwan (IPSec)", protocol: "ipsec" },
        // SSH libraries (detection stubs — key extraction in Phase 3.8)
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: ssh_detect_execute, library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*sshd/, hookFn: ssh_detect_execute, library: "OpenSSH", protocol: "ssh" },
    ]);

    hook_Linux_SSL_Libs(hookRegistry, true);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader({
        platform: plattform_name,
        platformLabel: "Linux",
        loaderLibrary: /.*libdl.*\.so/,
        functionName: "dlopen",
        extractModulePath: true,
    }, hookRegistry, moduleNames, false, selected_protocol);
}