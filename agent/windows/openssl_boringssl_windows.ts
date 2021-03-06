
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl"
import { readAddresses, getPortsAndAddresses } from "../shared/shared_functions"
import { socket_library } from "./windows_agent";

export class OpenSSL_BoringSSL_Windows extends OpenSSL_BoringSSL {

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


export function boring_execute(moduleName:String){
    var boring_ssl = new OpenSSL_BoringSSL_Windows(moduleName,socket_library);
    boring_ssl.execute_hooks();


}