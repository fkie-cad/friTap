import { module_library_mapping } from "../shared/shared_structures"
import { log, devlog } from "../util/log"
import { getModuleNames } from "../shared/shared"
import { gnutls_execute } from "./gnutls_linux"
import { wolfssl_execute } from "./wolfssl_linux"
import { nss_execute } from "./nss_linux"
import { mbedTLS_execute } from "./mbedTLS_linux"
import { boring_execute } from "./openssl_boringssl_linux"


module_library_mapping["linux"] = [[/.*libssl_sb.so/, boring_execute], [/.*libssl\.so/, boring_execute], [/.*libgnutls\.so/, gnutls_execute], [/.*libwolfssl\.so/, wolfssl_execute], [/.*libnspr[0-9]?\.so/, nss_execute], [/libmbedtls\.so.*/, mbedTLS_execute]]
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_Dynamic_Loader(): void {
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
                    for (let map of module_library_mapping["linux"]) {
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

function hook_Linux_SSL_Libs() {
    for (let map of module_library_mapping["linux"]) {
        let regex = map[0]
        let func = map[1]
        for (let module of moduleNames) {
            if (regex.test(module)) {
                try {
                    log(`${module} found & will be hooked on Linux!`)
                    func(module)
                } catch (error) {
                    log(`error: skipping module ${module}`)
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }

            }
        }
    }

}


export function load_linux_hooking_agent() {
    hook_Linux_SSL_Libs();
    hook_Linux_Dynamic_Loader();
}