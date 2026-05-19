import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks } from "../shared/shared_functions.js";
import { Platform, PLATFORM_WINDOWS } from "../shared/shared_structures.js";
import { sspi_execute } from "../legacy/tls/platforms/windows/sspi.js";
import { sspi_execute_modern } from "../tls/platforms/windows/sspi.js";
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/windows/openssl_boringssl_windows.js";
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/windows/openssl_boringssl_windows.js";
import { gnutls_execute } from "../legacy/tls/platforms/windows/gnutls_windows.js";
import { gnutls_execute_modern } from "../tls/platforms/windows/gnutls_windows.js";
import { mbedTLS_execute } from "../legacy/tls/platforms/windows/mbedTLS_windows.js";
import { mbedTLS_execute_modern } from "../tls/platforms/windows/mbedTLS_windows.js";
import { nss_execute } from "../legacy/tls/platforms/windows/nss_windows.js";
import { nss_execute_modern } from "../tls/platforms/windows/nss_windows.js";
import { wolfssl_execute } from "../legacy/tls/platforms/windows/wolfssl_windows.js";
import { wolfssl_execute_modern } from "../tls/platforms/windows/wolfssl_windows.js";
import { matrixSSL_execute } from "../legacy/tls/platforms/windows/matrixssl_windows.js";
import { matrixSSL_execute_modern } from "../tls/platforms/windows/matrixssl_windows.js";
import { cronet_execute } from "../legacy/tls/platforms/windows/cronet_windows.js";
import { cronet_execute_modern } from "../tls/platforms/windows/cronet_windows.js";
import { lsass_execute } from "../legacy/tls/platforms/windows/lsass.js";
import { lsass_execute_modern } from "../tls/platforms/windows/lsass.js";
import { nss_hpke_execute_windows } from "../ohttp/platforms/windows/nss_hpke_windows.js";
import { quiche_execute } from "../quic/platforms/windows/quiche_windows.js";
import { google_quiche_execute } from "../quic/platforms/windows/google_quiche_windows.js";
import { neqo_execute } from "../quic/platforms/windows/neqo_windows.js";


var plattform_name: Platform = PLATFORM_WINDOWS;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "WS2_32.dll";

function hook_Windows_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Windows", is_base_hook, selected_protocol)
}

export function load_windows_hooking_agent() {
    hookRegistry.registerAll([
        // TLS libraries (TLS protocol family — also covers QUIC and OHTTP below)
        { platform: plattform_name, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /^.*libssl.*\.dll$/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /^.*(wolfssl|WOLFSSL).*\.dll$/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl", protocol: "tls" },
        { platform: plattform_name, pattern: /^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls", protocol: "tls" },
        { platform: plattform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss", protocol: "tls" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: (use_modern ? sspi_execute_modern : sspi_execute), library: "SSPI", libraryType: "sspi", protocol: "tls" },
        { platform: plattform_name, pattern: /mbedTLS\.dll/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls", protocol: "tls" },
        { platform: plattform_name, pattern: /^.*(cronet|CRONET).*\.dll/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /matrixSSL\.dll/, hookFn: (use_modern ? matrixSSL_execute_modern : matrixSSL_execute), library: "MatrixSSL", libraryType: "matrixssl", protocol: "tls" },
        // OHTTP (NSS HPKE) — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/, hookFn: nss_hpke_execute_windows, library: "NSS HPKE (OHTTP)", protocol: "tls", libraryType: "nss_hpke" },
        // QUIC libraries — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*quiche\.dll/i, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /chrome\.dll/i, hookFn: google_quiche_execute, library: "Google QUICHE (Chrome)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*xul\.dll/i, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls" },
    ]);

    hook_Windows_SSL_Libs(hookRegistry, true);
    const windowsLoaderConfig = {
        platform: plattform_name,
        platformLabel: "Windows",
        resolveViaApi: "exports:KERNELBASE.dll!*LoadLibraryExW",
        functionName: "LoadLibraryExW",
        moduleFromRetval: true,
    };
    installOhttpHooks(plattform_name, hookRegistry, moduleNames, "Windows", windowsLoaderConfig);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader({
        ...windowsLoaderConfig,
        onMatchExtra: () => {
            log("\n[*] Remember to hook the default SSL provider for the Windows API you have to hook lsass.exe\n");
        },
    }, hookRegistry, moduleNames, false, selected_protocol);
}

export function load_windows_lsass_agent() {
    devlog("Loading Windows LSASS agent...");
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /ncrypt*\.dll/, hookFn: (use_modern ? lsass_execute_modern : lsass_execute), library: "LSASS NCrypt" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: (use_modern ? sspi_execute_modern : sspi_execute), library: "SSPI" },
    ]);

    hook_Windows_SSL_Libs(hookRegistry, true);
    hookDynamicLoader({
        platform: plattform_name,
        platformLabel: "Windows",
        resolveViaApi: "exports:KERNELBASE.dll!*LoadLibraryExW",
        functionName: "LoadLibraryExW",
        moduleFromRetval: true,
        onMatchExtra: () => {
            log("\n[*] Remember to hook the default SSL provider for the Windows API you have to hook lsass.exe\n");
        },
    }, hookRegistry, moduleNames, false, selected_protocol);

}