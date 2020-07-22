import { off } from "process"
import { execute as boring_execute } from "./openssl_boringssl"

var moduleNames: Array<string> = []
Process.enumerateModules().forEach(item => moduleNames.push(item.name))
if (moduleNames.indexOf("libssl.so") > -1) {
    console.log("OpenSSL/BoringSSL detected.")
    boring_execute()
}
if (moduleNames.indexOf("libwolfssl.so") > -1) {
    console.log("WolfSSL detected, not yet supported.")
}

Interceptor.attach(Module.getExportByName("libdl.so", "android_dlopen_ext"), function (args) {
    var moduleName = args[0].readCString()
    if (moduleName?.endsWith("libssl.so")) {
        console.log("OpenSSL/BoringSSL detected.")
        boring_execute()
    } else if (moduleName?.endsWith("libwolfssl.so")) {
        console.log("WolfSSL detected, not yet supported.")
    }

})