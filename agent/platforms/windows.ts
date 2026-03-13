import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader } from "../shared/shared_functions.js";
import { Platform, PLATFORM_WINDOWS } from "../shared/shared_structures.js";
import { sspi_execute } from "../legacy/tls/platforms/windows/sspi.js";
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
import { cronet_execute } from "../legacy/tls/platforms/windows/cronet_windows.js";
import { lsass_execute } from "../legacy/tls/platforms/windows/lsass.js";


var plattform_name: Platform = PLATFORM_WINDOWS;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "WS2_32.dll";

function hook_Windows_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Windows", is_base_hook, selected_protocol)
}

export function load_windows_hooking_agent() {
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /^.*libssl.*\.dll$/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl" },
        { platform: plattform_name, pattern: /^.*(wolfssl|WOLFSSL).*\.dll$/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl" },
        { platform: plattform_name, pattern: /^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls" },
        { platform: plattform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: sspi_execute, library: "SSPI", libraryType: "sspi" },
        { platform: plattform_name, pattern: /mbedTLS\.dll/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls" },
        { platform: plattform_name, pattern: /^.*(cronet|CRONET).*\.dll/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /matrixSSL\.dll/, hookFn: matrixSSL_execute, library: "MatrixSSL", libraryType: "matrixssl" },
    ]);

    hook_Windows_SSL_Libs(hookRegistry, true);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
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

export function load_windows_lsass_agent() {
    devlog("Loading Windows LSASS agent...");
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /ncrypt*\.dll/, hookFn: lsass_execute, library: "LSASS NCrypt" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: sspi_execute, library: "SSPI" },
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