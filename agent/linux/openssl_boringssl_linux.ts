
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js"
import { socket_library } from "./linux_agent.js";

export class OpenSSL_BoringSSL_Linux extends OpenSSL_BoringSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook (){

        OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(this.addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(this.addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])    
    
        Interceptor.attach(this.addresses["SSL_new"],
        {
            onEnter: function (args: any) {
                OpenSSL_BoringSSL.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback)
            }
    
        })
    }

}






export function boring_execute(moduleName:String){
    var boring_ssl = new OpenSSL_BoringSSL_Linux(moduleName,socket_library);
    boring_ssl.execute_hooks();


}