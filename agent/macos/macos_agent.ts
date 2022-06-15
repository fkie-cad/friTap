
import { module_library_mapping } from "../shared/shared_structures"
import { log, devlog } from "../util/log"
import { getModuleNames } from "../shared/shared"
import { boring_execute } from "./openssl_boringssl_macos"

module_library_mapping["darwin"] = [[/.*libboringssl\.dylib/, boring_execute]]
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libSystem.B.dylib"


function hook_macOS_Dynamic_Loader(): void {
    try {
        devlog("Missing dynamic loader hook implementation!");
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}


function hook_macOS_SSL_Libs() {
    for (let map of module_library_mapping["darwin"]) {
        let regex = map[0]
        let func = map[1]
        for (let module of moduleNames) {
            if (regex.test(module)) {
                log(`${module} found & will be hooked on MacOS!`)
                func(module)
            }
        }
    }
}



export function load_macos_hooking_agent() {
    hook_macOS_SSL_Libs(); // actually we are using the same implementation as we did on iOS, therefore this needs addtional testing
    hook_macOS_Dynamic_Loader();
}