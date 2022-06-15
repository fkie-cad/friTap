
import {WolfSSL } from "../ssl_lib/wolfssl";
import { socket_library } from "./android_agent";

export class WolfSSL_Android extends WolfSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

}


export function wolfssl_execute(moduleName:String){
    var wolf_ssl = new WolfSSL_Android(moduleName,socket_library);
    wolf_ssl.execute_hooks();


}