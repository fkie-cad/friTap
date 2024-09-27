import { devlog, log } from "../util/log.js";
import { getAndroidVersion } from "../util/process_infos.js";

function findProviderInstallerImplFromClassloaders(currentClassLoader: Java.Wrapper, backupImplementation: any) : Java.Wrapper | null {

    var providerInstallerImpl = null;
    var classLoaders = Java.enumerateClassLoadersSync()
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl)
            providerInstallerImpl = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl")
            break
        } catch (error) {
            devlog("Error in hooking ProviderInstallerImpl (findProviderInstallerImplFromClassloaders):")
            devlog("[-] Error message: "+error);
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

function findProviderInstallerFromClassloaders(currentClassLoader: Java.Wrapper, backupImplementation: any) : Java.Wrapper | null  {

    var providerInstaller = null
    var classLoaders = Java.enumerateClassLoadersSync()
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl)
            providerInstaller = classFactory.use("com.google.android.gms.security.ProviderInstaller")
            break
        } catch (error) {
            devlog("Error in hooking ProviderInstallerImpl (findProviderInstallerFromClassloaders):")
            if(!error.toString().includes("java.lang.ClassNotFoundException")){
                devlog("[-] Error message: "+error);
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
    Java.perform(function () {
        //Part one: Hook ProviderInstallerImpl
        var javaClassLoader = Java.use("java.lang.ClassLoader")
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation
        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.  
        javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className: string) {
            let retval = this.loadClass(className)
            if (className.endsWith("ProviderInstallerImpl")) {
                log("Process is loading ProviderInstallerImpl")
                var providerInstallerImpl = findProviderInstallerImplFromClassloaders(javaClassLoader, backupImplementation)
                if (providerInstallerImpl === null) {
                    log("ProviderInstallerImpl could not be found, although it has been loaded")
                } else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log("ProviderinstallerImpl redirection/blocking")

                    }

                }
            }
            return retval
        }
        
        //Part two: Hook Providerinstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller")
            providerInstaller.installIfNeeded.implementation = function (context: any) {
                devlog("Providerinstaller redirection/blocking")
            }
            providerInstaller.installIfNeededAsync.implementation = function (context: any, callback: any) {
                devlog("ProviderinstallerAsncy redirection/blocking")
                callback.onProviderInstalled()
            }
        } catch (error) {
            try {
                // probably class wasn't loaded by the app's main class loader therefore we load it
                var providerInstallerImpl = null;
                var providerInstallerFromClassloder = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation)
                if (providerInstallerFromClassloder === null){
                    providerInstallerImpl = findProviderInstallerImplFromClassloaders(javaClassLoader, backupImplementation)
                }


                if (providerInstallerFromClassloder === null && providerInstallerImpl  === null || providerInstallerFromClassloder === undefined) {
                    devlog("ProviderInstaller could not be found, although it has been loaded")
                }else{

                    if(providerInstallerImpl !== null){
                        providerInstallerImpl.insertProvider.implementation = function () {
                            devlog("ProviderinstallerImpl redirection/blocking")
    
                        }
                    }else{

                    providerInstallerFromClassloder.installIfNeeded.implementation = function (context: any) {
                        devlog("Providerinstaller redirection/blocking")
                    }
                    providerInstallerFromClassloder.installIfNeededAsync.implementation = function (context: any, callback: any) {
                        devlog("ProviderinstallerAsync redirection/blocking")
                        callback.onProviderInstalled()
                    }
                }
                }
            }catch (error) {
                devlog("Some error in hooking the Providerinstaller")
                if(!error.toString().includes("java.lang.ClassNotFoundException")){
                    devlog("[-] Error message: "+error);
                }
                // As it is not available, do nothing
            }
            
        }
    })



}