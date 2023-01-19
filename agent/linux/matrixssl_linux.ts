
import {matrix_SSL } from "../ssl_lib/matrixssl.js"
import { socket_library } from "./linux_agent.js";

export class matrix_SSL_Linux extends matrix_SSL {

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


export function matrixSSL_execute(moduleName:String){
    var matrix_ssl = new matrix_SSL_Linux(moduleName,socket_library);
    matrix_ssl.execute_hooks();


}