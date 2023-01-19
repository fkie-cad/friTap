
import {matrix_SSL } from "../ssl_lib/matrixssl.js"
import { socket_library } from "./windows_agent.js";

export class matrix_SSL_Windows extends matrix_SSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_helper_hook();

        //this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        //Not implemented yet
    }

}


export function matrixSSL_execute(moduleName:String){
    var matrix_ssl = new matrix_SSL_Windows(moduleName,socket_library);
    matrix_ssl.execute_hooks();


}