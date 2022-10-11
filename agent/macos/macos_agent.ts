
import { module_library_mapping } from "../shared/shared_structures.js"
import { log, devlog } from "../util/log.js"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions.js"
import { boring_execute } from "./openssl_boringssl_macos.js"


var plattform_name = "MacOS";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {
        devlog("Missing dynamic loader hook implementation!");
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}


function hook_macOS_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames)
}



export function load_macos_hooking_agent() {
    module_library_mapping[plattform_name] = [[/.*libboringssl\.dylib/, boring_execute]]
    hook_macOS_SSL_Libs(module_library_mapping); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader(module_library_mapping);
}