import { log } from "./log"

export function execute() {

    //We have to hook multiple entrypoints: ProviderInstallerImpl and ProviderInstaller
    Java.perform(function () {

        //Part one: Hook ProviderInstallerImpl
        var javaClassLoader = Java.use("java.lang.ClassLoader")
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation

        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.  
        javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className: string) {
            if (className.endsWith("ProviderInstallerImpl")) {
                var providerInstallerImpl = null
                var classLoaders = Java.enumerateClassLoadersSync()
                for (var cl of classLoaders) {
                    try {
                        var classFactory = Java.ClassFactory.get(cl)
                        providerInstallerImpl = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl")
                        //Revert the implementation to avoid an infinitloop of "Loadclass"
                        javaClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation
                        break
                    } catch (error) {
                        // Nullcheck follows
                    }

                }
                if (providerInstallerImpl === null) {
                    // Do nothing
                } else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log("ProviderinstallerImpl redirection/blocking")

                    }

                }
            }
            return this.loadClass(className)
        }

        //Part two: Hook Providerinstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller")
            providerInstaller.installIfNeeded.implementation = function (context: any) {
                log("Providerinstaller redirection/blocking")
            }
            providerInstaller.installIfNeededAsync.implementation = function (context: any, callback: any) {
                log("Providerinstaller redirection/blocking")
                callback.onProviderInstalled()
            }
        } catch (error) {
            // As it is not available, do nothing
        }
    })

}