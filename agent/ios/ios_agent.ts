import { module_library_mapping, ModuleHookingType } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, invokeHookingFunction } from "../shared/shared_functions.js";
import { boring_execute } from "./openssl_boringssl_ios.js";
import { cronet_execute } from "./cronet_ios.js"
import { flutter_execute } from "./flutter_ios.js"


var plattform_name = "darwin";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean): void {
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
                            try{
                                func(this.moduleName, is_base_hook)
                            }catch(error_msg){
                                devlog(`iOS dynamic loader error: ${error_msg}`)
                            }
                            
                        }

                    }
                }
            }


        })

        log(`[*] iOS dynamic loader hooked.`)
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking on iOS.")
    }
}


function hook_iOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"iOS",is_base_hook)
}



export function load_ios_hooking_agent() {
    module_library_mapping[plattform_name] = [
        [/.*libboringssl\.dylib/, invokeHookingFunction(boring_execute)],
        [/.*cronet.*\.dylib/, invokeHookingFunction(cronet_execute)],
        [/.*flutter.*\.dylib/, invokeHookingFunction(flutter_execute)]]
        
    hook_iOS_SSL_Libs(module_library_mapping, true);
    hook_iOS_Dynamic_Loader(module_library_mapping, false);
}