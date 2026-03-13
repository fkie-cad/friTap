import { devlog, devlog_error, log } from "../../../../util/log.js";
import { getAndroidVersion } from "../../../../util/process_infos.js";
import {OpenSSL_BoringSSL } from "../../../tls/libs/openssl_boringssl.js";
import { socket_library } from "../../../../platforms/android.js";
import { isSymbolAvailable } from "../../../../shared/shared_functions.js";
import { Java, JavaMethod, JavaWrapper } from "../../../../shared/javalib.js";
import { patterns, isPatternReplaced, experimental } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";


export class Consycrypt_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        var library_method_mapping : { [key: string]: Array<string> }= {};
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_new", "SSL_CTX_set_keylog_callback"]

        super(moduleName,socket_library,is_base_hook, library_method_mapping);
    }



    install_conscrypt_tls_keys_callback_hook (){
        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;

        if (isSymbolAvailable(this.module_name, "SSL_CTX_new")){

            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"], {
                onLeave: function(retval) {
                    const ssl = new NativePointer(retval);
                    if (!ssl.isNull()) {
                        devlog("BoringSSL/Conscrypt SSL_CTX_new - setting keylog callback");
                        instance.SSL_CTX_set_keylog_callback(ssl, instance.keylog_callback);
                    }
                }
            });
        }

    }


    execute_conscrypt_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        this.resolveWithPipeline([
            "SSL_CTX_new", "SSL_CTX_set_keylog_callback",
        ]);

        this.install_conscrypt_tls_keys_callback_hook();
    }

}

export function conscrypt_native_execute(moduleName:string, is_base_hook: boolean){
    try{
        var boring_ssl = new Consycrypt_BoringSSL_Android(moduleName,socket_library,is_base_hook);
    try {
        boring_ssl.execute_conscrypt_hooks();
    }catch(error_msg){
        devlog(`conscrypt_execute error: ${error_msg}`);
    }
    } catch (error_msg) {
        devlog_error(`Error in conscrypt_native_execute: ${error_msg}`);
    }

    if (is_base_hook) {
        try {
        const init_addresses = boring_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }}catch(error_msg){
            devlog(`conscrypt_execute base-hook error: ${error_msg}`)
        }
    }

}

/**
 * Block ProviderInstallerImpl.insertProvider() and ProviderInstaller.installIfNeeded()
 * to prevent the Conscrypt provider from being updated at runtime.
 */
function blockProviderInstaller(): void {
    Java.perform(function () {
        // Part one: Hook ProviderInstallerImpl
        var javaClassLoader: JavaWrapper = Java.use("java.lang.ClassLoader");
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation;
        try {
            javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className: string) {
                let retval = this.loadClass(className);
                if (className.endsWith("ProviderInstallerImpl")) {
                    log("Process is loading ProviderInstallerImpl");
                    var providerInstallerImpl = findProviderInstallerImplFromClassloaders(javaClassLoader, backupImplementation);
                    if (providerInstallerImpl === null) {
                        log("ProviderInstallerImpl could not be found, although it has been loaded");
                    } else {
                        providerInstallerImpl.insertProvider.implementation = function () {
                            log("ProviderinstallerImpl redirection/blocking");
                        };
                    }
                }
                return retval;
            };
        } catch (error) {
            devlog_error(`Failed to hook ClassLoader.loadClass: ${error}`);
            devlog("Attempting fallback: hooking ProviderInstallerImpl via class enumeration");
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className: string) {
                        if (className === "com.google.android.gms.common.security.ProviderInstallerImpl") {
                            try {
                                var providerInstallerImpl = Java.use(className);
                                providerInstallerImpl.insertProvider.implementation = function() {
                                    log("ProviderinstallerImpl redirection/blocking (fallback)");
                                };
                                devlog("Successfully hooked ProviderInstallerImpl via fallback");
                            } catch (hookError) {
                                devlog_error(`Failed to hook ProviderInstallerImpl in fallback: ${hookError}`);
                            }
                        }
                    },
                    onComplete: function() {
                        devlog("Fallback class enumeration complete");
                    }
                });
            } catch (fallbackError) {
                devlog_error(`Fallback enumeration also failed: ${fallbackError}`);
            }
        }

        // Part two: Hook ProviderInstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
            providerInstaller.installIfNeeded.implementation = function (context: any) {
                devlog("Providerinstaller redirection/blocking");
            };
            providerInstaller.installIfNeededAsync.implementation = function (context: any, callback: any) {
                devlog("ProviderinstallerAsync redirection/blocking");
                callback.onProviderInstalled();
            };
        } catch (error) {
            try {
                var providerInstallerFromClassloder = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation);
                var providerInstallerImpl2 = null;
                if (providerInstallerFromClassloder === null) {
                    providerInstallerImpl2 = findProviderInstallerImplFromClassloaders(javaClassLoader, backupImplementation);
                }

                if ((providerInstallerFromClassloder === null && providerInstallerImpl2 === null) || providerInstallerFromClassloder === undefined) {
                    devlog("ProviderInstaller could not be found");
                } else {
                    if (providerInstallerImpl2 !== null) {
                        providerInstallerImpl2.insertProvider.implementation = function () {
                            devlog("ProviderinstallerImpl redirection/blocking");
                        };
                    } else {
                        providerInstallerFromClassloder.installIfNeeded.implementation = function (context: any) {
                            devlog("Providerinstaller redirection/blocking");
                        };
                        providerInstallerFromClassloder.installIfNeededAsync.implementation = function (context: any, callback: any) {
                            devlog("ProviderinstallerAsync redirection/blocking");
                            callback.onProviderInstalled();
                        };
                    }
                }
            } catch (error2) {
                devlog_error("Some error in hooking the Providerinstaller");
                if (!error2.toString().includes("java.lang.ClassNotFoundException") && !error2.toString().includes("TypeError")) {
                    devlog_error("Error message: " + error2);
                }
            }
        }
    });
}

function findProviderInstallerImplFromClassloaders(currentClassLoader: JavaWrapper, backupImplementation: JavaMethod) : JavaWrapper | null {

    let providerInstallerImpl: JavaWrapper | null = null;
    var classLoaders = Java.enumerateClassLoadersSync()
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl)
            providerInstallerImpl = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl")
            break
        } catch (error) {
            if(!error.toString().includes("java.lang.ClassNotFoundException")){
                devlog_error("Error in hooking ProviderInstallerImpl (findProviderInstallerImplFromClassloaders):")
                devlog_error("Error message: (findProviderInstallerImplFromClassloaders): "+error);
            }
            providerInstallerImpl = null;
            // On error we return null
        }

    }

    var version = getAndroidVersion()

    if (version <= 12){
        //Revert the implementation to avoid an infinitloop of "Loadclass"
        currentClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation
    }

    return providerInstallerImpl
}

function findProviderInstallerFromClassloaders(currentClassLoader: JavaWrapper, backupImplementation: any) : JavaWrapper | null  {

    var providerInstaller = null
    var classLoaders = Java.enumerateClassLoadersSync()
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl)
            providerInstaller = classFactory.use("com.google.android.gms.security.ProviderInstaller")
            break
        } catch (error) {

            if(!error.toString().includes("java.lang.ClassNotFoundException")){
                devlog_error("Error in hooking ProviderInstallerImpl (findProviderInstallerFromClassloaders):")
                devlog_error("Error message (findProviderInstallerFromClassloaders): "+error);
            }
            providerInstaller = null;
            // On error we return null
        }

    }

    var version = getAndroidVersion()
    //log("is here the error")
    //log(typeof version)

    if (version <= 12){
        //Revert the implementation to avoid an infinitloop of "Loadclass"
        currentClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation
    }

    return providerInstaller
}

export function execute() {
    //We have to hook multiple entrypoints: ProviderInstallerImpl and ProviderInstaller
    blockProviderInstaller();
}
