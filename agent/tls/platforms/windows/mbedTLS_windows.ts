
import {mbed_TLS } from "../../libs/mbedTLS.js";
import { socket_library } from "../../../platforms/windows.js";
import { executeSSLLibrary } from "../../../shared/shared_functions.js";

export class mbed_TLS_Windows extends mbed_TLS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
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


export function mbedTLS_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(mbed_TLS_Windows, moduleName, socket_library, is_base_hook);
}