import { module_library_mapping, ModuleHookingType } from "../shared/shared_structures.js";
import { getModuleNames, ssl_library_loader, invokeHookingFunction } from "../shared/shared_functions.js";
import { log, devlog } from "../util/log.js";
import { gnutls_execute } from "./gnutls_android.js";
import { wolfssl_execute } from "./wolfssl_android.js";
import { nss_execute } from "./nss_android.js";
import { mbedTLS_execute } from "./mbedTLS_android.js";
import { boring_execute } from "./openssl_boringssl_android.js";
import { java_execute} from "./android_java_tls_libs.js";
import { cronet_execute } from "./cronet_android.js";
import { flutter_execute } from "./flutter_android.js";
import { s2ntls_execute } from "./s2ntls_android.js";


var plattform_name = "linux";
var moduleNames: Array<string> = getModuleNames();
(global as any).addresses = {};

export const socket_library = "libc"

function install_java_hooks(){
    java_execute();
}

function hook_Android_Dynamic_Loader(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean): void{
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
                for(let map of module_library_mapping[plattform_name]){
                    let regex = map[0]
                    let func = map[1]
                    if (regex.test(this.moduleName)){
                        log(`${this.moduleName} was loaded & will be hooked on Android!`)
                        func(this.moduleName, is_base_hook)
                    } 
                    
                }
            }
        }

        
    })

    console.log(`[*] Android dynamic loader hooked.`)
} catch (error) {
    devlog("Dynamic loader error: "+ error)
    log("No dynamic loader present for hooking on Android.")
}
}

function hook_native_Android_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean){
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"Android",is_base_hook)

}


export function load_android_hooking_agent() {
    module_library_mapping[plattform_name] = [
        [/.*libssl_sb.so/, invokeHookingFunction(boring_execute)],
        [/.*libssl\.so/, invokeHookingFunction(boring_execute)],
        [/.*cronet.*\.so/, invokeHookingFunction(cronet_execute)],
        [/.*flutter.*\.so/, invokeHookingFunction(flutter_execute)],
        [/.*libgnutls\.so/, invokeHookingFunction(gnutls_execute)],
        [/.*libwolfssl\.so/, invokeHookingFunction(wolfssl_execute)],
        [/.*libnspr[0-9]?\.so/,invokeHookingFunction(nss_execute)], 
        [/libmbedtls\.so.*/, invokeHookingFunction(mbedTLS_execute)],
        [/.*libs2n.so/, invokeHookingFunction(s2ntls_execute)]];

    install_java_hooks();
    hook_native_Android_SSL_Libs(module_library_mapping, true);
    hook_Android_Dynamic_Loader(module_library_mapping, false);
}