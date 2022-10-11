import { module_library_mapping } from "../shared/shared_structures.js"
import { log, devlog } from "../util/log.js"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions.js"
import { boring_execute } from "./openssl_boringssl_ios.js"


var plattform_name = "iOS";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {
        devlog("Missing dynamic loader hook implementation!");
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}


function hook_iOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames)
}



export function load_ios_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, boring_execute]]
    hook_iOS_SSL_Libs(module_library_mapping);
    hook_iOS_Dynamic_Loader(module_library_mapping);
}