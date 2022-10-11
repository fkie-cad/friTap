
import {mbed_TLS } from "../ssl_lib/mbedTLS.js"
import { socket_library } from "./android_agent.js";

export class mbed_TLS_Android extends mbed_TLS {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }

    /*
    SSL_CTX_set_keylog_callback not exported by default on windows. 

    We need to find a way to install the callback function for doing that

	Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook(){
        // install hooking for windows
    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }

}


export function mbedTLS_execute(moduleName:String){
    var mbedTLS_ssl = new mbed_TLS_Android(moduleName,socket_library);
    mbedTLS_ssl.execute_hooks();


}