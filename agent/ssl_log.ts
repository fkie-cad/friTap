import { off } from "process"
import { execute as boring_execute } from "./openssl_boringssl"
import { execute as wolf_execute } from "./wolfssl"
import { execute as bouncy_execute } from "./bouncycastle"
import { log } from "./log"

var moduleNames: Array<string> = []
Process.enumerateModules().forEach(item => moduleNames.push(item.name))
if (moduleNames.indexOf("libssl.so") > -1) {
    log("OpenSSL/BoringSSL detected.")
    boring_execute()
}
if (moduleNames.indexOf("libwolfssl.so") > -1) {
    log("WolfSSL detected.")
    wolf_execute()
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
Interceptor.attach(Module.getExportByName("libdl.so", "android_dlopen_ext"), {
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
