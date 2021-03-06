import { module_library_mapping } from "../shared/shared_structures"
import { log, devlog } from "../util/log"
import { getModuleNames, ssl_library_loader } from "../shared/shared_functions"
import { sspi_execute } from "./sspi"
import { boring_execute } from "./openssl_boringssl_windows"
import { gnutls_execute } from "./gnutls_windows"
import { mbedTLS_execute } from "./mbedTLS_windows"
import { nss_execute } from "./nss_windows"
import { wolfssl_execute } from "./wolfssl_windows"



var plattform_name = "Windows";
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "WS2_32.dll";

function hook_Windows_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }): void {
    try {

        const resolver: ApiResolver = new ApiResolver('module')
        var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW")

        if (loadLibraryExW.length == 0) return console.log("[-] Missing windows dynamic loader!")


        Interceptor.attach(loadLibraryExW[0].address, {
            onLeave(retval: NativePointer) {

                let map = new ModuleMap();
                let moduleName = map.findName(retval)
                if (moduleName === null) return

                for (let map of module_library_mapping[plattform_name]) {
                    let regex = map[0]
                    let func = map[1]

                    if (regex.test(moduleName)) {
                        log(`${moduleName} was loaded & will be hooked on Windows!`)
                        func(moduleName)
                    }

                }
            }
        })
        console.log("[*] Windows dynamic loader hooked.")
    } catch (error) {
        devlog("Loader error: " + error)
        log("No dynamic loader present for hooking.")
    }
}

function hook_Windows_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }) {
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames)
}

export function load_windows_hooking_agent() {
    module_library_mapping[plattform_name] = [[/libssl-[0-9]+(_[0-9]+)?\.dll/, boring_execute], [/.*wolfssl.*\.dll/, wolfssl_execute], [/.*libgnutls-[0-9]+\.dll/, gnutls_execute], [/nspr[0-9]*\.dll/, nss_execute], [/sspicli\.dll/i, sspi_execute], [/mbedTLS\.dll/, mbedTLS_execute]]
    hook_Windows_SSL_Libs(module_library_mapping);
    hook_Windows_Dynamic_Loader(module_library_mapping);
}