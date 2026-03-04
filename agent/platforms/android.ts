import { hookRegistry } from "../shared/registry.js";
import { getModuleNames, ssl_library_loader_v2, invokeHookingFunction } from "../shared/shared_functions.js";
import { log, devlog } from "../util/log.js";
import { findModulesWithSSLKeyLogCallback } from "../tls/shared/library_identification.js";
import { gnutls_execute } from "../tls/platforms/android/gnutls_android.js";
import { wolfssl_execute } from "../tls/platforms/android/wolfssl_android.js";
import { nss_execute } from "../tls/platforms/android/nss_android.js";
import { mbedTLS_execute } from "../tls/platforms/android/mbedTLS_android.js";
import { boring_execute } from "../tls/platforms/android/openssl_boringssl_android.js";
import { java_execute} from "../tls/platforms/android/android_java_tls_libs.js";
import { cronet_execute } from "../tls/platforms/android/cronet_android.js";
import { conscrypt_native_execute } from "../tls/platforms/android/conscrypt.js";
import { flutter_execute } from "../tls/platforms/android/flutter_android.js";
import { s2ntls_execute } from "../tls/platforms/android/s2ntls_android.js";
import { mono_btls_execute } from "../tls/platforms/android/mono_btls_android.js";
import { patterns, isPatternReplaced, selected_protocol } from "../fritap_agent.js"
import { pattern_execute } from "../tls/platforms/android/pattern_android.js"
import { rustls_execute } from "../tls/platforms/android/rustls_android.js";
import { gotls_execute } from "../tls/platforms/android/gotls_android.js";
import { metartc_execute } from "../tls/platforms/android/metartc.js";
//import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";

var plattform_name = "linux";
var moduleNames: Array<string> = getModuleNames();
(globalThis as any).addresses = {};

export const socket_library = "libc"

function install_java_hooks(){
    java_execute();
}

function hook_Android_Dynamic_Loader(hookRegistry: any, is_base_hook: boolean): void{
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


    Interceptor.attach(Process.getModuleByName(libdl).getExportByName(dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString()
        },
        onLeave: function (retval: any) {
            if (this.moduleName != undefined) {
                const matches = hookRegistry.findAllMatches(plattform_name, this.moduleName, undefined, selected_protocol);
                for (let match of matches) {
                    log(`${this.moduleName} was loaded & will be hooked on Android!`)
                    try {
                        match.hookFn(this.moduleName, is_base_hook)
                    } catch (error_msg) {
                        devlog(`[-] Error in hooking ${this.moduleName}: ${error_msg}`)
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

function hook_native_Android_SSL_Libs(hookRegistry: any, is_base_hook: boolean){
    ssl_library_loader_v2(plattform_name, hookRegistry, moduleNames, "Android", is_base_hook, selected_protocol)

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

// Support for this feature is currently limited to Android systems and allows that any given module can be hooked provided by the JSON to hook the .
function install_pattern_based_hooks(){
    try{
        let data = loadPatternsFromJSON(patterns);
        if (data !== null && data.modules) {
            for (const moduleName in data.modules) {
                if (Object.prototype.hasOwnProperty.call(data.modules, moduleName)) {
                    devlog("[*] Module name: " + moduleName);
                    hookRegistry.register({
                        platform: plattform_name,
                        pattern: new RegExp(moduleName),
                        hookFn: invokeHookingFunction(pattern_execute),
                        library: "Pattern: " + moduleName,
                    });
                }
            }
            // Re-run the loaders with updated registry
            hook_native_Android_SSL_Libs(hookRegistry, true);
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
    // LEGACY: module_library_mapping[plattform_name] = [
    //     [/.*libssl_sb.so/, invokeHookingFunction(boring_execute)],
    //     [/.*libssl\.so/, invokeHookingFunction(boring_execute)],
    //     [/libconscrypt_gmscore_jni.so/, invokeHookingFunction(conscrypt_native_execute)],
    //     [/libconscrypt_jni.so/, invokeHookingFunction(conscrypt_native_execute)],
    //     [/.*flutter.*\.so/, invokeHookingFunction(flutter_execute)],
    //     [/.*libgnutls\.so/, invokeHookingFunction(gnutls_execute)],
    //     [/.*libwolfssl\.so/, invokeHookingFunction(wolfssl_execute)],
    //     [/.*libnss[3-4]\.so/,invokeHookingFunction(nss_execute)],
    //     [/libmbedtls\.so.*/, invokeHookingFunction(mbedTLS_execute)],
    //     [/.*libs2n.so/, invokeHookingFunction(s2ntls_execute)],
    //     [/.*mono-btls.*\.so/, invokeHookingFunction(mono_btls_execute)],
    //     [/.*cronet.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*libringrtc_rffi.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*libsignal_jni.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*monochrome.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*libwarp_mobile.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*lib*quiche*.*\.so/, invokeHookingFunction(cronet_execute)],
    //     [/.*librustls.*\.so/, invokeHookingFunction(rustls_execute)],
    //     [/.*libstartup.*\.so/, invokeHookingFunction(metartc_execute)],
    //     [/libgojni.*\.so/, invokeHookingFunction(gotls_execute)]
    // ];
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: invokeHookingFunction(boring_execute), library: "OpenSSL/BoringSSL" },
        { platform: plattform_name, pattern: /libconscrypt_gmscore_jni.so/, hookFn: invokeHookingFunction(conscrypt_native_execute), library: "Conscrypt" },
        { platform: plattform_name, pattern: /libconscrypt_jni.so/, hookFn: invokeHookingFunction(conscrypt_native_execute), library: "Conscrypt" },
        { platform: plattform_name, pattern: /.*flutter.*\.so/, hookFn: invokeHookingFunction(flutter_execute), library: "Flutter BoringSSL" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: invokeHookingFunction(gnutls_execute), library: "GnuTLS" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: invokeHookingFunction(wolfssl_execute), library: "WolfSSL" },
        { platform: plattform_name, pattern: /.*libnss[3-4]\.so/, hookFn: invokeHookingFunction(nss_execute), library: "NSS" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: invokeHookingFunction(mbedTLS_execute), library: "mbedTLS" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: invokeHookingFunction(s2ntls_execute), library: "s2n-tls" },
        { platform: plattform_name, pattern: /.*mono-btls.*\.so/, hookFn: invokeHookingFunction(mono_btls_execute), library: "Mono BTLS" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet" },
        { platform: plattform_name, pattern: /.*libringrtc_rffi.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet (RingRTC)" },
        { platform: plattform_name, pattern: /.*libsignal_jni.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet (Signal)" },
        { platform: plattform_name, pattern: /.*monochrome.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet (Monochrome)" },
        { platform: plattform_name, pattern: /.*libwarp_mobile.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet (Warp Mobile)" },
        { platform: plattform_name, pattern: /.*lib*quiche*.*\.so/, hookFn: invokeHookingFunction(cronet_execute), library: "Cronet (QUICHE)" },
        { platform: plattform_name, pattern: /.*librustls.*\.so/, hookFn: invokeHookingFunction(rustls_execute), library: "Rustls" },
        { platform: plattform_name, pattern: /.*libstartup.*\.so/, hookFn: invokeHookingFunction(metartc_execute), library: "metaRTC" },
        { platform: plattform_name, pattern: /libgojni.*\.so/, hookFn: invokeHookingFunction(gotls_execute), library: "Go TLS" },
        // IPSec libraries — strongSwan VPN is common on Android (detection stub, key extraction in Phase 3.8)
        /*
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: invokeHookingFunction(ipsec_detect_execute), library: "strongSwan (charon)", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: invokeHookingFunction(ipsec_detect_execute), library: "strongSwan", protocol: "ipsec" },
         */
        // SSH libraries
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*dropbear/, hookFn: invokeHookingFunction(ssh_detect_execute), library: "Dropbear", protocol: "ssh" },
    ]);


    install_java_hooks();
    hook_native_Android_SSL_Libs(hookRegistry, true);
    hook_Android_Dynamic_Loader(hookRegistry, false);
    if (isPatternReplaced()){
        install_pattern_based_hooks();
    }

    /*
     * Our simple approach to find the modules which might use BoringSSL internally
     */
    try{
        let matchedModules = findModulesWithSSLKeyLogCallback();
        if (matchedModules.length > 0) {
            for (const mod of matchedModules) {
                devlog("[!] Installing BoringSSL hooks for " + mod);
                hookRegistry.register({
                    platform: plattform_name,
                    pattern: new RegExp(`.*${mod}`),
                    hookFn: invokeHookingFunction(boring_execute),
                    library: "BoringSSL (auto-detected)",
                });
            }
            hook_native_Android_SSL_Libs(hookRegistry, false);
            hook_Android_Dynamic_Loader(hookRegistry, false);
            log("[*] Hooked additional modules with SSL_CTX_set_keylog_callback.");
        }
    }catch (error_msg){
        devlog("[-] Error in hooking additional modules: " + error_msg);
    }
}