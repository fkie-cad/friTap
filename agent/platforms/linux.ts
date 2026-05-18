import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks } from "../shared/shared_functions.js";
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
import { nss_hpke_execute_linux } from "../ohttp/platforms/linux/nss_hpke_linux.js";
// QUIC
import { quiche_execute } from "../quic/platforms/linux/quiche_linux.js";
import { google_quiche_execute } from "../quic/platforms/linux/google_quiche_linux.js";
import { neqo_execute } from "../quic/platforms/linux/neqo_linux.js";

var plattform_name: Platform = PLATFORM_LINUX;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Linux", is_base_hook, selected_protocol)
}


export function load_linux_hooking_agent() {
    hookRegistry.registerAll([
        // TLS libraries (TLS protocol family — also covers QUIC and OHTTP below)
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libssl.*\.so/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, excludePattern: /_(libpki|libcrypto)\.so$/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libnspr[0-9]?\.so/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss", protocol: "tls" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls", protocol: "tls" },
        { platform: plattform_name, pattern: /libssl_s.a/, hookFn: matrixSSL_execute, library: "MatrixSSL", libraryType: "matrixssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: (use_modern ? s2ntls_execute_modern : s2ntls_execute), library: "s2n-tls", libraryType: "s2ntls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*rustls.*/, hookFn: rustls_execute, library: "Rustls", libraryType: "rustls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*\.go.so$/, hookFn: gotls_execute, library: "Go TLS", libraryType: "gotls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*go[0-9.]+$/, hookFn: gotls_execute, library: "Go TLS", libraryType: "gotls", protocol: "tls" },
        // IPSec libraries (detection stubs — key extraction in the future)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: ipsec_detect_execute, library: "strongSwan (charon)", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: ipsec_detect_execute, library: "strongSwan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libipsec\.so/, hookFn: ipsec_detect_execute, library: "strongSwan (IPSec)", protocol: "ipsec" },
        // SSH binaries / libraries
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: ssh_detect_execute, library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /^(\/.+\/)?(ssh|sshd|sshd-session|scp|sftp-server)$/, hookFn: ssh_detect_execute, library: "OpenSSH", protocol: "ssh" },
        // OHTTP (NSS HPKE) — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libnss3?\.so/, hookFn: nss_hpke_execute_linux, library: "NSS HPKE (OHTTP)", protocol: "tls", libraryType: "nss_hpke" },
        // QUIC libraries — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libquiche\.so/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libcronet.*\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Cronet)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libxul\.so/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls" },
    ]);

    hook_Linux_SSL_Libs(hookRegistry, true);
    const linuxLoaderConfig = {
        platform: plattform_name,
        platformLabel: "Linux",
        loaderLibrary: /.*libdl.*\.so/,
        functionName: "dlopen",
        extractModulePath: true,
    };
    installOhttpHooks(plattform_name, hookRegistry, moduleNames, "Linux", linuxLoaderConfig);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader(linuxLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
}