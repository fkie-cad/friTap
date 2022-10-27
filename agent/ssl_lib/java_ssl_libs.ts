import { log } from "../util/log.js"
import { execute as conscrypt_execute } from "../android/conscrypt.js"
import { isAndroid} from "../util/process_infos.js";


export class SSL_Java {

    install_java_hooks(){
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

                        if(isAndroid()){
                            /*
                            When a NetworkProvider will be installed it is only allow at position 1
                            s. https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/security/net/config/NetworkSecurityConfigProvider.java
                            */
                            if(provider.getName() === "AndroidNSSP"){
                                return this.insertProviderAt(provider,1)
                            }

                            // when the "Failed to install provider as highest priority provider. Provider was installed at position"-error is prompted on logcat please uncomment the following line, recompile the typescript and reopen the following
                            // https://github.com/fkie-cad/friTap/issues/1
                            // var android_Version = Java.androidVersion
                            // devlog("highest priority provider error with: "+provider.getName())
                        }
                        
                        return this.addProvider(provider)
                    }
                }
            })
        }
    }
}