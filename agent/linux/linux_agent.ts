import { module_library_mapping, ModuleHookingType } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, invokeHookingFunction } from "../shared/shared_functions.js";
import { gnutls_execute } from "./gnutls_linux.js";
import { wolfssl_execute } from "./wolfssl_linux.js";
import { nss_execute } from "./nss_linux.js";
import { mbedTLS_execute } from "./mbedTLS_linux.js";
import { boring_execute, ssl_python_execute } from "./openssl_boringssl_linux.js";
import { matrixSSL_execute } from "./matrixssl_linux.js";
import { s2ntls_execute } from "./s2ntls_linux.js";
import { cronet_execute } from "./cronet_linux.js";
import { rustls_execute } from "./rustls_linux.js";
import { gotls_execute } from "./gotls_linux.js";

var plattform_name = "linux";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType, string?]> }, is_base_hook: boolean): void {
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
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0]
                        let func = map[1]
                        let optionalPath = map[2]; // Optional path for module matching
                        
                        if (regex.test(this.moduleName)) {

                             // If path condition exists, try to retrieve module and check path
                            if (optionalPath) {
                                try {
                                    const mod = Process.getModuleByName(this.moduleName);
                                    if (!mod.path.toLowerCase().includes(optionalPath.toLowerCase())) {
                                        continue;
                                    }
                                } catch (_) {
                                    continue; // Module not yet loaded or not found
                                }
                            }


                            log(`${this.moduleName} was loaded & will be hooked on Linux!`)
                            try {
                                func(this.moduleName, is_base_hook)
                            }
                            catch (error_msg) { 
                                devlog(`Linux dynamic loader error: ${error_msg}`)
                            }
                            
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

function hook_Linux_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType, string?]> }, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"Linux", is_base_hook)
}


export function load_linux_hooking_agent() {
    module_library_mapping[plattform_name] = [
        [/.*libssl_sb.so/, invokeHookingFunction(boring_execute)], 
        [/.*libssl\.so/, invokeHookingFunction(boring_execute)],
        [/.*libssl.*\.so/, invokeHookingFunction(ssl_python_execute), "python"], // Python-specific OpenSSL
        [/.*cronet.*\.so/, invokeHookingFunction(cronet_execute)], 
        [/.*libgnutls\.so/, invokeHookingFunction(gnutls_execute)], 
        [/.*libwolfssl\.so/, invokeHookingFunction(wolfssl_execute)], 
        [/.*libnspr[0-9]?\.so/, invokeHookingFunction(nss_execute)], 
        [/libmbedtls\.so.*/, invokeHookingFunction(mbedTLS_execute)], 
        [/libssl_s.a/, invokeHookingFunction(matrixSSL_execute)],
        [/.*libs2n.so/, invokeHookingFunction(s2ntls_execute)],
        [/.*rustls.*/, invokeHookingFunction(rustls_execute)],
        [/.*\.go$/, invokeHookingFunction(gotls_execute)], // Go executables
        [/.*go[0-9.]+$/, invokeHookingFunction(gotls_execute)] // Go versioned binaries
    ]

    hook_Linux_SSL_Libs(module_library_mapping, true);
    hook_Linux_Dynamic_Loader(module_library_mapping, false);
}