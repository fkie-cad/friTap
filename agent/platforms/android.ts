import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader } from "../shared/shared_functions.js";
import { Platform, PLATFORM_LINUX } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { findModulesWithSSLKeyLogCallback } from "../tls/shared/library_identification.js";
// Modern (definition-based) executors
import { gnutls_execute_modern } from "../tls/platforms/android/gnutls_android.js";
import { wolfssl_execute_modern } from "../tls/platforms/android/wolfssl_android.js";
import { nss_execute_modern } from "../tls/platforms/android/nss_android.js";
import { mbedTLS_execute_modern } from "../tls/platforms/android/mbedTLS_android.js";
import { boring_execute_modern } from "../tls/platforms/android/openssl_boringssl_android.js";
import { conscrypt_execute_modern } from "../tls/platforms/android/conscrypt.js";
import { s2ntls_execute_modern } from "../tls/platforms/android/s2ntls_android.js";
// Legacy (class-based) executors
import { boring_execute } from "../legacy/tls/platforms/android/openssl_boringssl_android.js";
import { gnutls_execute } from "../legacy/tls/platforms/android/gnutls_android.js";
import { wolfssl_execute } from "../legacy/tls/platforms/android/wolfssl_android.js";
import { nss_execute } from "../legacy/tls/platforms/android/nss_android.js";
import { mbedTLS_execute } from "../legacy/tls/platforms/android/mbedTLS_android.js";
import { cronet_execute } from "../legacy/tls/platforms/android/cronet_android.js";
import { conscrypt_native_execute } from "../legacy/tls/platforms/android/conscrypt.js";
import { s2ntls_execute } from "../legacy/tls/platforms/android/s2ntls_android.js";
// V1-only (re-exported from legacy)
import { java_execute } from "../tls/platforms/android/android_java_tls_libs.js";
import { flutter_execute } from "../tls/platforms/android/flutter_android.js";
import { mono_btls_execute } from "../tls/platforms/android/mono_btls_android.js";
import { patterns, isPatternReplaced, selected_protocol, use_modern, scan_results, library_scan_enabled } from "../fritap_agent.js"
import { processScanResults } from "../shared/library_scanner.js";
import { pattern_execute } from "../tls/platforms/android/pattern_android.js"
import { rustls_execute } from "../tls/platforms/android/rustls_android.js";
import { gotls_execute } from "../tls/platforms/android/gotls_android.js";
import { metartc_execute } from "../tls/platforms/android/metartc.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";

var plattform_name: Platform = PLATFORM_LINUX;
var moduleNames: Array<string> = getModuleNames();

export const socket_library = "libc"

function install_java_hooks(){
    java_execute();
}

function hook_native_Android_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean){
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Android", is_base_hook, selected_protocol)

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
                        hookFn: pattern_execute,
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
    hookRegistry.registerAll([
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl" },
        { platform: plattform_name, pattern: /libconscrypt_gmscore_jni.so/, hookFn: (use_modern ? conscrypt_execute_modern : conscrypt_native_execute), library: "Conscrypt", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /libconscrypt_jni.so/, hookFn: (use_modern ? conscrypt_execute_modern : conscrypt_native_execute), library: "Conscrypt", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*flutter.*\.so/, hookFn: flutter_execute, library: "Flutter BoringSSL", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl" },
        { platform: plattform_name, pattern: /.*libnss[3-4]\.so/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: (use_modern ? s2ntls_execute_modern : s2ntls_execute), library: "s2n-tls", libraryType: "s2ntls" },
        { platform: plattform_name, pattern: /.*mono-btls.*\.so/, hookFn: mono_btls_execute, library: "Mono BTLS", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, excludePattern: /_(libpki|libcrypto)\.so$/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libringrtc_rffi.*\.so/, hookFn: cronet_execute, library: "Cronet (RingRTC)", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libsignal_jni.*\.so/, excludePattern: /_testing\.so$/, hookFn: cronet_execute, library: "Cronet (Signal)", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*monochrome.*\.so/, hookFn: cronet_execute, library: "Cronet (Monochrome)", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*libwarp_mobile.*\.so/, hookFn: cronet_execute, library: "Cronet (Warp Mobile)", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*lib*quiche*.*\.so/, hookFn: cronet_execute, library: "Cronet (QUICHE)", libraryType: "boringssl" },
        { platform: plattform_name, pattern: /.*librustls.*\.so/, hookFn: rustls_execute, library: "Rustls", libraryType: "rustls" },
        { platform: plattform_name, pattern: /.*libstartup.*\.so/, hookFn: metartc_execute, library: "metaRTC" },
        { platform: plattform_name, pattern: /libgojni.*\.so/, hookFn: gotls_execute, library: "Go TLS", libraryType: "gotls" },
        // IPSec libraries — strongSwan VPN is common on Android (detection stub, key extraction in Phase 3.8)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: ipsec_detect_execute, library: "strongSwan (charon)", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: ipsec_detect_execute, library: "strongSwan", protocol: "ipsec" },
        // SSH libraries
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: ssh_detect_execute, library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /.*dropbear/, hookFn: ssh_detect_execute, library: "Dropbear", protocol: "ssh" },
    ]);


    install_java_hooks();
    hook_native_Android_SSL_Libs(hookRegistry, true);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    hookDynamicLoader({
        platform: plattform_name,
        platformLabel: "Android",
        loaderLibrary: /.*libdl.*\.so/,
        functionName: "dlopen",
        preferFunction: "android_dlopen_ext",
    }, hookRegistry, moduleNames, false, selected_protocol);
    if (isPatternReplaced()){
        install_pattern_based_hooks();
    }

    /*
     * Our simple approach to find the modules which might use BoringSSL internally.
     * Only runs when --library-scan is enabled to avoid slow startup from scanning all modules.
     */
    if (library_scan_enabled) {
        try{
            let matchedModules = findModulesWithSSLKeyLogCallback();
            // Filter out modules already matched by registry to prevent double-hooking
            matchedModules = matchedModules.filter(mod => !hookRegistry.findMatch(plattform_name, mod, "", selected_protocol));
            if (matchedModules.length > 0) {
                for (const mod of matchedModules) {
                    devlog("[!] Installing BoringSSL hooks for " + mod);
                    hookRegistry.register({
                        platform: plattform_name,
                        pattern: new RegExp(`.*${mod}`),
                        hookFn: (use_modern ? boring_execute_modern : boring_execute),
                        library: "BoringSSL (auto-detected)",
                        libraryType: "boringssl",
                    });
                }
                hook_native_Android_SSL_Libs(hookRegistry, false);
                hookDynamicLoader({
                    platform: plattform_name,
                    platformLabel: "Android",
                    loaderLibrary: /.*libdl.*\.so/,
                    functionName: "dlopen",
                    preferFunction: "android_dlopen_ext",
                }, hookRegistry, moduleNames, false, selected_protocol);
                log("[*] Hooked additional modules with SSL_CTX_set_keylog_callback.");
            }
        }catch (error_msg){
            devlog("[-] Error in hooking additional modules: " + error_msg);
        }
    }
}