
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl"
import { socket_library } from "./android_agent";

export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

}


export function boring_execute(moduleName:String){
    var boring_ssl = new OpenSSL_BoringSSL_Android(moduleName,socket_library);
    boring_ssl.execute_hooks();


}