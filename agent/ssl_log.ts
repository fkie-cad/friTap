import { off } from "process"
import { execute as boring_execute } from "./openssl_boringssl"
import { execute as wolf_execute } from "./wolfssl"

var moduleNames: Array<string> = []
Process.enumerateModules().forEach(item => moduleNames.push(item.name))
if (moduleNames.indexOf("libssl.so") > -1) {
    console.log("OpenSSL/BoringSSL detected.")
    boring_execute()
}
if (moduleNames.indexOf("libwolfssl.so") > -1) {
    console.log("WolfSSL detected.")
    wolf_execute()
}

Interceptor.attach(Module.getExportByName("libdl.so", "android_dlopen_ext"), {
    onEnter: function (args) {
        this.moduleName = args[0].readCString()
    },
    onLeave: function (retval: any) {
        if (this.moduleName != undefined) {
            if (this.moduleName.endsWith("libssl.so")) {
                console.log("OpenSSL/BoringSSL detected.")
                boring_execute()
            } else if (this.moduleName.endsWith("libwolfssl.so")) {
                console.log("WolfSSL detected. Warning: Key logging is currently not yet supported for WolfSSL. Master Keys will be printed.")
                wolf_execute()
            }
        }

    }
})