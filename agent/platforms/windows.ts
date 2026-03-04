import { hookRegistry } from "../shared/registry.js";
import { selected_protocol } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader_v2, invokeHookingFunction } from "../shared/shared_functions.js";
import { sspi_execute } from "../tls/platforms/windows/sspi.js";
import { boring_execute, ssl_python_execute } from "../tls/platforms/windows/openssl_boringssl_windows.js";
import { gnutls_execute } from "../tls/platforms/windows/gnutls_windows.js";
import { mbedTLS_execute } from "../tls/platforms/windows/mbedTLS_windows.js";
import { nss_execute } from "../tls/platforms/windows/nss_windows.js";
import { wolfssl_execute } from "../tls/platforms/windows/wolfssl_windows.js";
import { matrixSSL_execute } from "../tls/platforms/windows/matrixssl_windows.js";
import { cronet_execute } from "../tls/platforms/windows/cronet_windows.js";
import { lsass_execute } from "../tls/platforms/windows/lsass.js";


var plattform_name = "windows";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "WS2_32.dll";

function hook_Windows_Dynamic_Loader(hookRegistry: any, is_base_hook: boolean): void {
    try {

        const resolver: ApiResolver = new ApiResolver('module')
        var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW")

        if (loadLibraryExW.length == 0) return log("[-] Missing windows dynamic loader!")


        Interceptor.attach(loadLibraryExW[0].address, {
            onLeave(retval: NativePointer) {

                let map = new ModuleMap();
                let moduleName = map.findName(retval)
                if (moduleName === null) return

                const matches = hookRegistry.findAllMatches(plattform_name, moduleName, undefined, selected_protocol);
                for (let match of matches) {
                    log(`${moduleName} was loaded & will be hooked on Windows!`)
                    try {
                        match.hookFn(moduleName, is_base_hook)
                    } catch (error_msg) {
                        devlog(`Windows dynamic loader error: ${error_msg}`)
                    }
                    log("\n[*] Remember to hook the default SSL provider for the Windows API you have to hook lsass.exe\n");
                }
            }
        })
        log("[*] Windows dynamic loader hooked.")
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}

function hook_Windows_SSL_Libs(hookRegistry: any, is_base_hook: boolean) {
    ssl_library_loader_v2(plattform_name, hookRegistry, moduleNames, "Windows", is_base_hook, selected_protocol)
}

export function load_windows_hooking_agent() {
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, invokeHookingFunction(boring_execute)],
    //     [/^.*libssl.*\.dll$/, invokeHookingFunction(ssl_python_execute), "python"], // Python-specific OpenSSL
    //     [/^.*(wolfssl|WOLFSSL).*\.dll$/, invokeHookingFunction(wolfssl_execute)],
    //     [/^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/, invokeHookingFunction(gnutls_execute)],
    //     [/^(nspr|NSPR)[0-9]*\.dll/, invokeHookingFunction(nss_execute)],
    //     [/(sspicli|SSPICLI|SspiCli)\.dll$/, invokeHookingFunction(sspi_execute)],
    //     [/mbedTLS\.dll/, invokeHookingFunction(mbedTLS_execute)],
    //     [/^.*(cronet|CRONET).*\.dll/, invokeHookingFunction(cronet_execute)],
    //     ["/matrixSSL\.dll", invokeHookingFunction(matrixSSL_execute)]
    // ]
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /^.*libssl.*\.dll$/, hookFn: invokeHookingFunction(ssl_python_execute), library: "Python OpenSSL", pathFilter: "python" },
        { platform: plattform_name, pattern: /^.*(wolfssl|WOLFSSL).*\.dll$/, hookFn: invokeHookingFunction(wolfssl_execute), library: "WolfSSL" },
        { platform: plattform_name, pattern: /^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/, hookFn: invokeHookingFunction(gnutls_execute), library: "GnuTLS" },
        { platform: plattform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/, hookFn: invokeHookingFunction(nss_execute), library: "NSS" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: invokeHookingFunction(sspi_execute), library: "SSPI" },
        { platform: plattform_name, pattern: /mbedTLS\.dll/, hookFn: invokeHookingFunction(mbedTLS_execute), library: "mbedTLS" },
        { platform: plattform_name, pattern: /^.*(cronet|CRONET).*\.dll/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet" },
        { platform: plattform_name, pattern: /matrixSSL\.dll/, hookFn: invokeHookingFunction(matrixSSL_execute), library: "MatrixSSL" },
    ]);

    hook_Windows_SSL_Libs(hookRegistry, true);
    hook_Windows_Dynamic_Loader(hookRegistry, false);
}

export function load_windows_lsass_agent() {
    devlog("Loading Windows LSASS agent...");
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/ncrypt*\.dll/, invokeHookingFunction(lsass_execute)],
    //     [/(sspicli|SSPICLI|SspiCli)\.dll$/, invokeHookingFunction(sspi_execute)]
    // ]
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /ncrypt*\.dll/, hookFn: invokeHookingFunction(lsass_execute), library: "LSASS NCrypt" },
        { platform: plattform_name, pattern: /(sspicli|SSPICLI|SspiCli)\.dll$/, hookFn: invokeHookingFunction(sspi_execute), library: "SSPI" },
    ]);

    hook_Windows_SSL_Libs(hookRegistry, true);
    hook_Windows_Dynamic_Loader(hookRegistry, false);

}