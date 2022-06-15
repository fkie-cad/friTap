
import {WolfSSL } from "../ssl_lib/wolfssl";
import { socket_library } from "./windows_agent";

export class WolfSSL_Windows extends WolfSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    install_tls_keys_callback_hook(){

    }




    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook(); currently not implemented
    }

}


export function wolfssl_execute(moduleName:String){
    var wolf_ssl = new WolfSSL_Windows(moduleName,socket_library);
    wolf_ssl.execute_hooks();


}