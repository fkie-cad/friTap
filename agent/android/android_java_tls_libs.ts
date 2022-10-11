import { log } from "../util/log.js"
import { execute as bouncy_execute } from "./bouncycastle.js"
import { SSL_Java } from "../ssl_lib/java_ssl_libs.js"


export class SSL_Java_Android extends SSL_Java {


    install_java_android_hooks(){
        if (Java.available) {
            Java.perform(function () {
        
                // Bouncycastle/Spongycastle
                try {
                    //If we can load a class of spongycastle, we know its present and we have to hook it
                    var testLoad = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect")
                    log("Bouncycastle/Spongycastle detected.")
                    bouncy_execute()
                } catch (error) {
                    //On error, just do nothing
                }
            });
        }
    }


    execute_hooks(){
        this.install_java_android_hooks();
        this.install_java_hooks();
    }

}


export function java_execute(){
    var java_ssl = new SSL_Java_Android();
    java_ssl.execute_hooks();
}

