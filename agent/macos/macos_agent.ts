
import { module_library_mapping, ModuleHookingType } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, invokeHookingFunction } from "../shared/shared_functions.js";
import { boring_execute } from "./openssl_boringssl_macos.js";
import { cronet_execute } from "./cronet_macos.js"


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean): void {
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
                            try {   
                                func(this.moduleName, is_base_hook);
                            } catch (error_msg) {
                                devlog(`MacOS dynamic loader error: ${error_msg}`)
                            }

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


function hook_macOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"MacOS", is_base_hook)
}



export function load_macos_hooking_agent() {
    module_library_mapping[plattform_name] = [
        [/.*libboringssl\.dylib/, invokeHookingFunction(boring_execute)],
        [/.*cronet.*\.dylib/, invokeHookingFunction(cronet_execute)]]
        
    hook_macOS_SSL_Libs(module_library_mapping, true); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader(module_library_mapping, false);
}