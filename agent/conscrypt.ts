import { log } from "./log"

export function execute() {
    Java.perform(function () {
        var javaClassLoader = Java.use("java.lang.ClassLoader")
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation
        javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className: string) {
            if (className.endsWith("ProviderInstallerImpl")) {
                var providerInstaller = null
                var classLoaders = Java.enumerateClassLoadersSync()
                log("WILL " + className + " LADEN")
                for (var cl of classLoaders) {
                    try {
                        var classFactory = Java.ClassFactory.get(cl)
                        providerInstaller = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl")
                        log("Got it, reverting implementation")
                        javaClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation
                        break
                    } catch (error) {
                        // Nullcheck follows
                    }

                }
                if (providerInstaller === null) {
                    log("Not found")
                } else {
                    providerInstaller.insertProvider.implementation = function () {
                        log("Providerinstaller redirection/blocking")

                    }

                }
            }
            return this.loadClass(className)


            /*
            // Nativecrypto is not loaded via the default classloader, so we have to find the right one
            
            var NativeCrypto = null
            for (var cl of classLoaders) {
                try {
                    var classFactory = Java.ClassFactory.get(cl)
                    NativeCrypto = classFactory.use("com.google.android.gms.org.conscrypt.NativeCrypto")
                    break
                } catch (error) {
                    // Nullcheck follows
                }
    
            }
            if (NativeCrypto === null) {
                throw new Error("Was unable to load NativeCrypto!")
            } else {
                NativeCrypto.SSL_read.implementation = function (a: any, b: any, c: any, d: any, e: any, f: any, g: any, h: any) {
                    var Log = Java.use("android.util.Log");
                    var Exception = Java.use("java.lang.Exception");
                    log(Log.getStackTraceString(Exception.$new()));
                    return this.SSL_read(a, b, c, d, e, f, g, h)
                }
            }
            */

        }
    })

}