import { hookRegistry } from "../shared/registry.js";
import { selected_protocol } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader_v2, invokeHookingFunction } from "../shared/shared_functions.js";
import { gnutls_execute } from "../tls/platforms/linux/gnutls_linux.js";
import { wolfssl_execute } from "../tls/platforms/linux/wolfssl_linux.js";
import { nss_execute } from "../tls/platforms/linux/nss_linux.js";
import { mbedTLS_execute } from "../tls/platforms/linux/mbedTLS_linux.js";
import { boring_execute, ssl_python_execute } from "../tls/platforms/linux/openssl_boringssl_linux.js";
import { matrixSSL_execute } from "../tls/platforms/linux/matrixssl_linux.js";
import { s2ntls_execute } from "../tls/platforms/linux/s2ntls_linux.js";
import { cronet_execute } from "../tls/platforms/linux/cronet_linux.js";
import { rustls_execute } from "../tls/platforms/linux/rustls_linux.js";
import { gotls_execute } from "../tls/platforms/linux/gotls_linux.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";

var plattform_name = "linux";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_Dynamic_Loader(hookRegistry: any, is_base_hook: boolean): void {
    try {
        const regex_libdl = /.*libdl.*\.so/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Linux Dynamic loader not found!"
        }

        var dlopen = "dlopen"

        Interceptor.attach(Process.getModuleByName(libdl).getExportByName(dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString()
            },
            onLeave: function (retval: any) {
                if (this.moduleName != undefined) {
                    // Get module path for filtering
                    let modulePath: string | undefined;
                    try {
                        const mod = Process.getModuleByName(this.moduleName);
                        modulePath = mod.path;
                    } catch (_) {
                        // Module not yet loaded, continue without path
                    }

                    const matches = hookRegistry.findAllMatches(plattform_name, this.moduleName, modulePath, selected_protocol);
                    for (let match of matches) {
                        log(`${this.moduleName} was loaded & will be hooked on Linux!`)
                        try {
                            match.hookFn(this.moduleName, is_base_hook)
                        } catch (error_msg) {
                            devlog(`Linux dynamic loader error: ${error_msg}`)
                        }
                    }
                }
            }


        })

        log(`[*] Linux dynamic loader hooked.`)
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}

function hook_Linux_SSL_Libs(hookRegistry: any, is_base_hook: boolean) {
    ssl_library_loader_v2(plattform_name, hookRegistry, moduleNames, "Linux", is_base_hook, selected_protocol)
}


export function load_linux_hooking_agent() {
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/.*libssl_sb.so/, invokeHookingFunction(boring_execute)],
    //     [/.*libssl\.so/, invokeHookingFunction(boring_execute)],
    //     [/.*libssl.*\.so/, invokeHookingFunction(ssl_python_execute), "python"], // Python-specific OpenSSL
    //     [/.*cronet.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*libgnutls\.so/, invokeHookingFunction(gnutls_execute)],
    //     [/.*libwolfssl\.so/, invokeHookingFunction(wolfssl_execute)],
    //     [/.*libnspr[0-9]?\.so/, invokeHookingFunction(nss_execute)],
    //     [/libmbedtls\.so.*/, invokeHookingFunction(mbedTLS_execute)],
    //     [/libssl_s.a/, invokeHookingFunction(matrixSSL_execute)],
    //     [/.*libs2n.so/, invokeHookingFunction(s2ntls_execute)],
    //     [/.*rustls.*/, invokeHookingFunction(rustls_execute)],
    //     [/.*\.go.so$/, invokeHookingFunction(gotls_execute)], // Go executables
    //     [/.*go[0-9.]+$/, invokeHookingFunction(gotls_execute)] // Go versioned binaries
    // ]
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /.*libssl.*\.so/, hookFn: invokeHookingFunction(ssl_python_execute), library: "Python OpenSSL", pathFilter: "python" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: invokeHookingFunction(gnutls_execute), library: "GnuTLS" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: invokeHookingFunction(wolfssl_execute), library: "WolfSSL" },
        { platform: plattform_name, pattern: /.*libnspr[0-9]?\.so/, hookFn: invokeHookingFunction(nss_execute), library: "NSS" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: invokeHookingFunction(mbedTLS_execute), library: "mbedTLS" },
        { platform: plattform_name, pattern: /libssl_s.a/, hookFn: invokeHookingFunction(matrixSSL_execute), library: "MatrixSSL" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: invokeHookingFunction(s2ntls_execute), library: "s2n-tls" },
        { platform: plattform_name, pattern: /.*rustls.*/, hookFn: invokeHookingFunction(rustls_execute), library: "Rustls" },
        { platform: plattform_name, pattern: /.*\.go.so$/, hookFn: invokeHookingFunction(gotls_execute), library: "Go TLS" },
        { platform: plattform_name, pattern: /.*go[0-9.]+$/, hookFn: invokeHookingFunction(gotls_execute), library: "Go TLS" },
        // IPSec libraries (detection stubs — key extraction in the future)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: invokeHookingFunction(ipsec_detect_execute), library: "strongSwan (charon)", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: invokeHookingFunction(ipsec_detect_execute), library: "strongSwan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libipsec\.so/, hookFn: invokeHookingFunction(ipsec_detect_execute), library: "strongSwan (IPSec)", protocol: "ipsec" },
        // SSH libraries (detection stubs)
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*sshd/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "OpenSSH", protocol: "ssh" },
    ]);

    hook_Linux_SSL_Libs(hookRegistry, true);
    hook_Linux_Dynamic_Loader(hookRegistry, false);
}