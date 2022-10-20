import { module_library_mapping } from "../shared/shared_structures.js"
import { log, devlog } from "../util/log.js"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions.js"
import { gnutls_execute } from "./gnutls_linux.js"
import { wolfssl_execute } from "./wolfssl_linux.js"
import { nss_execute } from "./nss_linux.js"
import { mbedTLS_execute } from "./mbedTLS_linux.js"
import { boring_execute } from "./openssl_boringssl_linux.js"

var plattform_name = "linux";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {
        const regex_libdl = /.*libdl.*\.so/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Linux Dynamic loader not found!"
        }

        var dlopen = "dlopen"

        Interceptor.attach(Module.getExportByName(libdl, dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString()
            },
            onLeave: function (retval: any) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0]
                        let func = map[1]
                        if (regex.test(this.moduleName)) {
                            log(`${this.moduleName} was loaded & will be hooked on Linux!`)
                            func(this.moduleName)
                        }

                    }
                }
            }


        })

        console.log(`[*] Linux dynamic loader hooked.`)
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}

function hook_Linux_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"Linux")
}


export function load_linux_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libssl_sb.so/, boring_execute], [/.*libssl\.so/, boring_execute], [/.*libgnutls\.so/, gnutls_execute], [/.*libwolfssl\.so/, wolfssl_execute], [/.*libnspr[0-9]?\.so/, nss_execute], [/libmbedtls\.so.*/, mbedTLS_execute]]
    hook_Linux_SSL_Libs(module_library_mapping);
    hook_Linux_Dynamic_Loader(module_library_mapping);
}