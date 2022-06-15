import { module_library_mapping } from "../shared/shared_structures"
import { log, devlog } from "../util/log"
import { getModuleNames } from "../shared/shared"
import { boring_execute } from "./openssl_boringssl_ios"

module_library_mapping["darwin"] = [[/.*libboringssl\.dylib/, boring_execute]]
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_iOS_Dynamic_Loader(): void {
    try {
        devlog("Missing dynamic loader hook implementation!");
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}


function hook_iOS_SSL_Libs() {
    for (let map of module_library_mapping["darwin"]) {
        let regex = map[0]
        let func = map[1]
        for (let module of moduleNames) {
            if (regex.test(module)) {
                log(`${module} found & will be hooked on Darwin!`)
                func(module)
            }
        }
    }
}



export function load_ios_hooking_agent() {
    hook_iOS_SSL_Libs();
    hook_iOS_Dynamic_Loader();
}