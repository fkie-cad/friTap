import { off } from "process"
import { execute as boring_execute } from "./openssl_boringssl"
import { execute as wolf_execute } from "./wolfssl"
import { execute as bouncy_execute } from "./bouncycastle"
import { execute as conscrypt_execute } from "./conscrypt"
import { execute as nss_execute } from "./nss"
import { log } from "./log"

// sometimes libraries loaded but don't have function implemented we need to hook
function hasRequiredFunctions(libName : string,expectedFuncName : string) : boolean {
    var functionList = Process.getModuleByName(libName).enumerateExports().filter(exports => exports.name.toLowerCase().includes(expectedFuncName));
    if (functionList.length == 0){
        return false;
    }else{
        return true;
    }
}

var moduleNames: Array<string> = []
Process.enumerateModules().forEach(item => moduleNames.push(item.name))

for (var mod of moduleNames) {
    if (mod.indexOf("libssl.so") >= 0) {
        if(hasRequiredFunctions(mod,"SSL_read")){
            log("OpenSSL/BoringSSL detected.")
            boring_execute()
        }
        
        break
    }
}

for (var mod of moduleNames) {
    if (mod.indexOf("libwolfssl.so") >= 0) {
        log("WolfSSL detected.")
        wolf_execute()
        break
    }
}


for (var mod of moduleNames) {
    if (mod.indexOf("libnspr") >= 0) {
        log("NSS SSL detected.")
        nss_execute()
        break
    }
}


if (Java.available) {
    Java.perform(function () {
        try {
            //If we can load a class of spongycastle, we know its present and we have to hook it
            var testLoad = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect")
            log("Bouncycastle/Spongycastle detected.")
            bouncy_execute()
        } catch (error) {
            //On error, just do nothing
        }
    })
}



//Hook the dynamic loader, in case library gets loaded at a later point in time
//check wether we are on android or linux
try {
    let dl_exports = Process.getModuleByName("libdl.so").enumerateExports()
    var dlopen = "dlopen"
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext"
            break
        }
    }


    Interceptor.attach(Module.getExportByName("libdl.so", dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString()
        },
        onLeave: function (retval: any) {
            if (this.moduleName != undefined) {
                if (this.moduleName.endsWith("libssl.so")) {
                    log("OpenSSL/BoringSSL detected.")
                    boring_execute()
                } else if (this.moduleName.endsWith("libwolfssl.so")) {
                    log("WolfSSL detected.")
                    wolf_execute()
                }
            }

        }
    })
} catch (error) {
    log("No dynamic loader present for hooking.")
}

if (Java.available) {
    Java.perform(function () {
        //Conscrypt needs early instrumentation as we block the provider installation
        var Security = Java.use("java.security.Security");
        if (Security.getProviders().toString().includes("GmsCore_OpenSSL")) {
            log("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Trying to remove it to fall back on default Provider")
            Security.removeProvider("GmsCore_OpenSSL")
            log("Removed GmsCore_OpenSSL")
        }

        //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
        //we always have to watch the classloader activity
        conscrypt_execute()

        //Now do the same for Ssl_guard
        if (Security.getProviders().toString().includes("Ssl_Guard")) {
            log("Ssl_Guard deteced, removing it to fall back on default Provider")
            Security.removeProvider("Ssl_Guard")
            log("Removed Ssl_Guard")
        }

        //Same thing for Conscrypt provider which has been manually inserted (not by providerinstaller)
        if (Security.getProviders().toString().includes("Conscrypt version")) {
            log("Conscrypt detected")
            Security.removeProvider("Conscrypt")
            log("Removed Conscrypt")
        }
        //Uncomment this line to show all remaining providers
        //log("Remaining: " + Security.getProviders().toString())


        //Hook insertProviderAt/addprovider for dynamic provider blocking
        Security.insertProviderAt.implementation = function (provider: any, position: number) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log("Blocking provider registration of " + provider.getName())
                return position
            } else {
                return this.insertProviderAt(provider, position)
            }
        }
        //Same for addProvider
        Security.insertProviderAt.implementation = function (provider: any) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log("Blocking provider registration of " + provider.getName())
                return 1
            } else {
                return this.addProvider(provider)
            }
        }
    })
}