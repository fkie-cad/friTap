
import {GnuTLS } from "../ssl_lib/gnutls"
import { socket_library } from "./linux_agent";

export class GnuTLS_Linux extends GnuTLS {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

}


export function gnutls_execute(moduleName:String){
    var gnutls_ssl = new GnuTLS_Linux(moduleName,socket_library);
    gnutls_ssl.execute_hooks();


}