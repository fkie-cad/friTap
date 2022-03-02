import { execute as boring_execute } from "./openssl_boringssl"
import { execute as wolf_execute } from "./wolfssl"
import { execute as bouncy_execute } from "./bouncycastle"
import { execute as conscrypt_execute } from "./conscrypt"
import { execute as sspi_execute } from "./sspi"
import { execute as nss_execute } from "./nss"
import { execute as gnutls_execute } from "./gnutls"
import {execute as mbedtls_execute } from "./mbedTLS"
import { log, devlog } from "./log"
import { getModuleNames} from "./shared"
import { isAndroid } from "./util/process_infos"



// sometimes libraries loaded but don't have function implemented we need to hook
function hasRequiredFunctions(libName: string, expectedFuncName: string): boolean {
    var functionList = Process.getModuleByName(libName).enumerateExports().filter(exports => exports.name.toLowerCase().includes(expectedFuncName));
    if (functionList.length == 0) {
        return false;
    } else {
        return true;
    }
}


var moduleNames: Array<string> = getModuleNames()

var module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> } = {}
module_library_mapping["windows"] = [[/libssl-[0-9]+(_[0-9]+)?\.dll/, boring_execute],[/.*wolfssl.*\.dll/, wolf_execute],[/.*libgnutls-[0-9]+\.dll/, gnutls_execute],[/nspr[0-9]*\.dll/,nss_execute], [/sspicli\.dll/i,sspi_execute], [/mbedTLS\.dll/, mbedtls_execute]] 
module_library_mapping["linux"] = [[/.*libssl_sb.so/, boring_execute],[/.*libssl\.so/, boring_execute],[/.*libgnutls\.so/, gnutls_execute],[/.*libwolfssl\.so/, wolf_execute],[/.*libnspr[0-9]?\.so/,nss_execute], [/libmbedtls\.so.*/, mbedtls_execute]]
module_library_mapping["darwin"] = [[/.*libboringssl\.dylib/, boring_execute]]


if(Process.platform === "windows"){
    for(let map of module_library_mapping["windows"]){
        let regex = map[0]
        let func = map[1]
        for(let module of moduleNames){
            if (regex.test(module)){
                log(`${module} found & will be hooked on Windows!`)
                func(module)
            } 
        }
    }
        
}

if(Process.platform === "linux"){
    for(let map of module_library_mapping["linux"]){
        let regex = map[0]
        let func = map[1]
        for(let module of moduleNames){
            if (regex.test(module)){
              if(isAndroid()){
                log(`${module} found & will be hooked on Android!`)
              }else{
                log(`${module} found & will be hooked on Linux!`)
              }
                try{
                    func(module) // on some Android Apps we encounterd the problem of multiple SSL libraries but only one is used for the SSL encryption/decryption
                }catch (error) {
                    log(`error: skipping module ${module}`)
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }
                
            } 
        }
    }
}

if(Process.platform === "darwin"){
    for(let map of module_library_mapping["darwin"]){
        let regex = map[0]
        let func = map[1]
        for(let module of moduleNames){
            if (regex.test(module)){
                log(`${module} found & will be hooked on Darwin!`)
                func(module)
            } 
        }
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



//Hook the dynamic loaders, in case library gets loaded at a later point in time

//! Repeated module loading results in multiple intereceptions. This will cause multiple log entries if module is loaded into the same address space 
try {

    switch(Process.platform){
        case "windows":
            hookWindowsDynamicLoader()
            break;
        case "linux":
            hookLinuxDynamicLoader()
            break;
        default:
            devlog("Missing dynamic loader hook implementation!");
    }

    
} catch (error) {
    devlog("Loader error: "+ error)
    log("No dynamic loader present for hooking.")
}

function hookLinuxDynamicLoader():void{
    const regex_libdl = /.*libdl.*\.so/
    const libdl = moduleNames.find(element => element.match(regex_libdl))
    if (libdl === undefined){
        if(isAndroid()){
            throw "Android Dynamic loader not found!"
        }else{
            throw "Linux Dynamic loader not found!"
        }
        
    } 

    let dl_exports = Process.getModuleByName(libdl).enumerateExports()
    var dlopen = "dlopen"
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext"
            break
        }
    }


    Interceptor.attach(Module.getExportByName(libdl, dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString()
        },
        onLeave: function (retval: any) {
            if (this.moduleName != undefined) {
                for(let map of module_library_mapping["linux"]){
                    let regex = map[0]
                    let func = map[1]
                    if (regex.test(this.moduleName)){
                        if(isAndroid()){
                            log(`${this.moduleName} was loaded & will be hooked on Android!`)
                        }else{
                            log(`${this.moduleName} was loaded & will be hooked on Linux!`)
                        }
                        
                        func(this.moduleName)
                    } 
                    
                }
            }
        }

        
    })

    console.log(`[*] ${dlopen.indexOf("android") == -1 ? "Linux" : "Android"} dynamic loader hooked.`)
}

function hookWindowsDynamicLoader():void{
    const resolver:ApiResolver = new ApiResolver('module')
    var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW")
    
    if(loadLibraryExW.length == 0) return console.log("[!] Missing windows dynamic loader!")


    Interceptor.attach(loadLibraryExW[0].address, {
        onLeave(retval: NativePointer){
                        
            let map = new ModuleMap();
            let moduleName = map.findName(retval)
            if(moduleName === null) return

            for(let map of module_library_mapping["windows"]){
                let regex = map[0]
                let func = map[1]
                
                if (regex.test(moduleName)){
                    log(`${moduleName} was loaded & will be hooked on Windows!`)
                    func(moduleName)
                } 
                
            }
        }
    })
    console.log("[*] Windows dynamic loader hooked.")
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
