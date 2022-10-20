
import { module_library_mapping } from "../shared/shared_structures.js"
import { log, devlog } from "../util/log.js"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions.js"
import { boring_execute } from "./openssl_boringssl_macos.js"


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {
        const regex_libdl = /libSystem.B.dylib/
        const libdl = moduleNames.find(element => element.match(regex_libdl))
        if (libdl === undefined) {
            throw "Darwin Dynamic loader not found!"
        }

        var dlopen = "dlopen"

        Interceptor.attach(Module.getExportByName("libSystem.B.dylib", dlopen), {
            onEnter: function (args) {
                this.moduleName = args[0].readCString()
            },
            onLeave: function (retval: any) {
                if (this.moduleName != undefined) {
                    for (let map of module_library_mapping[plattform_name]) {
                        let regex = map[0]
                        let func = map[1]
                        if (regex.test(this.moduleName)) {
                            log(`${this.moduleName} was loaded & will be hooked on MacOS!`)
                            func(this.moduleName)
                        }

                    }
                }
            }


        })

        log("MacOS dynamic loader hooked.")
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking on MacOS.")
    }
}


function hook_macOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"MacOS")
}



export function load_macos_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, boring_execute]]
    hook_macOS_SSL_Libs(module_library_mapping); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader(module_library_mapping);
}