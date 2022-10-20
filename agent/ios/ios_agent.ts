import { module_library_mapping } from "../shared/shared_structures.js"
import { log, devlog } from "../util/log.js"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions.js"
import { boring_execute } from "./openssl_boringssl_ios.js"


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {
        const regex_libdl = /libSystem.B.dylib/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!"
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
                            log(`${this.moduleName} was loaded & will be hooked on iOS!`)
                            func(this.moduleName)
                        }

                    }
                }
            }


        })

        console.log(`[*] iOS dynamic loader hooked.`)
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking on iOS.")
    }
}


function hook_iOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"iOS")
}



export function load_ios_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, boring_execute]]
    hook_iOS_SSL_Libs(module_library_mapping);
    hook_iOS_Dynamic_Loader(module_library_mapping);
}