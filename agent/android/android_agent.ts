import { module_library_mapping } from "../shared/shared_structures"
import { getModuleNames } from "../shared/shared"
import { log, devlog } from "../util/log"
import { gnutls_execute } from "./gnutls_android"
import { wolfssl_execute } from "./wolfssl_android"
import { nss_execute } from "./nss_android"
import { mbedTLS_execute } from "./mbedTLS_android"
import { boring_execute } from "./openssl_boringssl_android"
import { java_execute} from "./android_java_tls_libs"


module_library_mapping["linux"] = [[/.*libssl_sb.so/, boring_execute],[/.*libssl\.so/, boring_execute],[/.*libgnutls\.so/, gnutls_execute],[/.*libwolfssl\.so/, wolfssl_execute],[/.*libnspr[0-9]?\.so/,nss_execute], [/libmbedtls\.so.*/, mbedTLS_execute]]
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function install_java_hooks(){
    java_execute();
}

function hook_Android_Dynamic_Loader():void{
    try {
    const regex_libdl = /.*libdl.*\.so/
    const libdl = moduleNames.find(element => element.match(regex_libdl))
    if (libdl === undefined){
        throw "Android Dynamic loader not found!"
    } 

    let dl_exports = Process.getModuleByName(libdl).enumerateExports()
    var dlopen = "dlopen"
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext"
            break
        }
    }


    Interceptor.attach(Module.getExportByName(libdl, dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString()
        },
        onLeave: function (retval: any) {
            if (this.moduleName != undefined) {
                for(let map of module_library_mapping["linux"]){
                    let regex = map[0]
                    let func = map[1]
                    if (regex.test(this.moduleName)){
                        log(`${this.moduleName} was loaded & will be hooked on Android!`)
                        func(this.moduleName)
                    } 
                    
                }
            }
        }

        
    })

    console.log(`[*] Android dynamic loader hooked.`)
} catch (error) {
    devlog("Loader error: "+ error)
    log("No dynamic loader present for hooking.")
}
}

function hook_native_Android_SSL_Libs(){
    for(let map of module_library_mapping["linux"]){
        let regex = map[0]
        let func = map[1]
        for(let module of moduleNames){
            if (regex.test(module)){
                try{
                    log(`${module} found & will be hooked on Android!`)
                    func(module) // on some Android Apps we encounterd the problem of multiple SSL libraries but only one is used for the SSL encryption/decryption
                }catch (error) {
                    log(`error: skipping module ${module}`)
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }
                
            } 
        }
    }

}


export function load_android_hooking_agent() {
    install_java_hooks();
    hook_native_Android_SSL_Libs();
    hook_Android_Dynamic_Loader();
}