
import {GnuTLS } from "../ssl_lib/gnutls.js"
import { socket_library } from "./windows_agent.js";

export class GnuTLS_Windows extends GnuTLS {

    constructor(public moduleName:String, public socket_library:String){
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


export function gnutls_execute(moduleName:String){
    var gnu_ssl = new GnuTLS_Windows(moduleName,socket_library);
    gnu_ssl.execute_hooks();


}