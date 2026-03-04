
import {GnuTLS } from "../../libs/gnutls.js";
import { socket_library } from "../../../platforms/windows.js";
import { executeSSLLibrary } from "../../../shared/shared_functions.js";

export class GnuTLS_Windows extends GnuTLS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();

        //this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        //Not implemented yet
    }

}


export function gnutls_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(GnuTLS_Windows, moduleName, socket_library, is_base_hook);
}