import { off } from "process"
import { execute as boring_execute } from "./openssl_boringssl"
import { execute as wolf_execute } from "./wolfssl"
import { execute as bouncy_execute } from "./bouncycastle"
import { execute as conscrypt_execute } from "./conscrypt"
import { log } from "./log"

var moduleNames: Array<string> = []
Process.enumerateModules().forEach(item => moduleNames.push(item.name))

for(var mod of moduleNames){
    if(mod.indexOf("libssl.so") >= 0){
        log("OpenSSL/BoringSSL detected.")
        boring_execute()
        break
    }
}

for(var mod of moduleNames){
    if(mod.indexOf("libwolfssl.so") >= 0){
        log("WolfSSL detected.")
        wolf_execute()
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
    for (var ex of dl_exports){
        if (ex.name === "android_dlopen_ext"){
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
        var provider = Java.use("java.security.Security");
        if (provider.getProviders().toString().includes("GmsCore_OpenSSL")) {
            log("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Consider rerunning with the -spawn flag")
            provider.removeProvider("GmsCore_OpenSSL")
            console.log("removed it")
            console.log(provider.getProviders().toString())
        }

        //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
        //we always have to watch the classloader activity
        conscrypt_execute()
    })
}