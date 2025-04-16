import { module_library_mapping, ModuleHookingType } from "../shared/shared_structures.js";
import { getModuleNames, ssl_library_loader, invokeHookingFunction } from "../shared/shared_functions.js";
import { log, devlog } from "../util/log.js";
import { findModulesWithSSLKeyLogCallback, createModuleLibraryMappingExtend } from "../shared/library_identification.js";
import { gnutls_execute } from "./gnutls_android.js";
import { wolfssl_execute } from "./wolfssl_android.js";
import { nss_execute } from "./nss_android.js";
import { mbedTLS_execute } from "./mbedTLS_android.js";
import { boring_execute } from "./openssl_boringssl_android.js";
import { java_execute} from "./android_java_tls_libs.js";
import { cronet_execute } from "./cronet_android.js";
import { conscrypt_native_execute } from "./conscrypt.js"; 
import { flutter_execute } from "./flutter_android.js";
import { s2ntls_execute } from "./s2ntls_android.js";
import { mono_btls_execute } from "./mono_btls_android.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { pattern_execute } from "./pattern_android.js"
import { rustls_execute } from "./rustls_android.js";


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
                        try{
                            func(this.moduleName, is_base_hook)
                        }catch (error_msg){
                            devlog(`[-] Error in hooking ${this.moduleName}: ${error_msg}`);
                        }
                        
                    } 
                    
                }
            }
        }

        
    })

    log(`[*] Android dynamic loader hooked.`)
} catch (error) {
    devlog("Dynamic loader error: "+ error)
    log("No dynamic loader present for hooking on Android.")
}
}

function hook_native_Android_SSL_Libs(module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, is_base_hook: boolean){
    ssl_library_loader(plattform_name, module_library_mapping,moduleNames,"Android",is_base_hook)

}

function loadPatternsFromJSON(jsonContent: string): any {
    try {
        let data = JSON.parse(jsonContent);
        return data;
    } catch (error) {
        devlog("[-] Error loading or parsing JSON pattern:  "+ error);
        return null;
    }
}

// Support for this feature is currently limited to Android systems.
function install_pattern_based_hooks(){
    try{
        let data = loadPatternsFromJSON(patterns);
        if (data !== null && data.modules) {
            for (const moduleName in data.modules) {
                if (Object.prototype.hasOwnProperty.call(data.modules, moduleName)) {
                    log("[*] Module name:"+ moduleName);
                    module_library_mapping[plattform_name] = [
                        [moduleName, invokeHookingFunction(pattern_execute)]];
                    
                    hook_native_Android_SSL_Libs(module_library_mapping, true);
                }
            }
        }

    }catch(e){

    }
    
    //console.log("data: \n"+data);
    /*
    for (const moduleName in data.modules) {
        /*if (Object.prototype.hasOwnProperty.call(data.modules, moduleName)) {
          console.log("[*] Module name:", moduleName);
        }
      }*/

      /*
      const hooker = new PatternBasedHooking(cronetModule);
      hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns.");
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
      */
}


export function load_android_hooking_agent() {
    module_library_mapping[plattform_name] = [
        [/.*libssl_sb.so/, invokeHookingFunction(boring_execute)],
        [/.*libssl\.so/, invokeHookingFunction(boring_execute)],
        [/libconscrypt_gmscore_jni.so/, invokeHookingFunction(conscrypt_native_execute)], // inspired from https://github.com/PiRogueToolSuite/pirogue-cli/blob/debian-12/pirogue_cli/frida-scripts/log_ssl_keys.js#L55
        [/ibconscrypt_jni.so/, invokeHookingFunction(conscrypt_native_execute)],
        [/.*flutter.*\.so/, invokeHookingFunction(flutter_execute)],
        [/.*libgnutls\.so/, invokeHookingFunction(gnutls_execute)],
        [/.*libwolfssl\.so/, invokeHookingFunction(wolfssl_execute)],
        [/.*libnss[3-4]\.so/,invokeHookingFunction(nss_execute)],
        [/libmbedtls\.so.*/, invokeHookingFunction(mbedTLS_execute)],
        [/.*libs2n.so/, invokeHookingFunction(s2ntls_execute)],
        [/.*mono-btls.*\.so/, invokeHookingFunction(mono_btls_execute)],
        [/.*cronet.*\.so/, invokeHookingFunction(cronet_execute)],
        [/.*monochrome.*\.so/, invokeHookingFunction(cronet_execute)],
        [/.*libwarp_mobile.*\.so/, invokeHookingFunction(cronet_execute)], // here the client_random is not working
        [/.*lib*quiche*.*\.so/, invokeHookingFunction(cronet_execute)],
        [/.*librustls.*\.so/, invokeHookingFunction(rustls_execute)]];


    install_java_hooks();
    hook_native_Android_SSL_Libs(module_library_mapping, true);
    hook_Android_Dynamic_Loader(module_library_mapping, false);
    if (isPatternReplaced()){
        install_pattern_based_hooks();
    }

    /*
     * Our simple approach to find the modules which might use BoringSSL internally
     */
    try{
        let matchedModules = findModulesWithSSLKeyLogCallback();
        if (matchedModules.length > 0) {
            const moduleLibraryMappingExtend: { [key: string]: Array<[RegExp, ModuleHookingType]> } = {};

            moduleLibraryMappingExtend[plattform_name] = createModuleLibraryMappingExtend(matchedModules, boring_execute);
            hook_native_Android_SSL_Libs(moduleLibraryMappingExtend, false);
            hook_Android_Dynamic_Loader(moduleLibraryMappingExtend, false);
            log("[*] Hooked additional modules with SSL_CTX_set_keylog_callback.");
        }
    }catch (error_msg){
        devlog("[-] Error in hooking additional modules: " + error_msg);
    } 
}