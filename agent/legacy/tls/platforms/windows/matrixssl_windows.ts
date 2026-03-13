
import {matrix_SSL } from "../../../../tls/libs/matrixssl.js";
import { socket_library } from "../../../../platforms/windows.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class matrix_SSL_Windows extends matrix_SSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
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


export function matrixSSL_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(matrix_SSL_Windows, moduleName, socket_library, is_base_hook);
}
