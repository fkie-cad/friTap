
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { socket_library } from "./linux_agent.js";

export class OpenSSL_BoringSSL_Linux extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook (){

        this.SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;
    
        Interceptor.attach(this.addresses[this.module_name]["SSL_new"],
        {
            onEnter: function (args: any) {
                instance.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback)
            }
    
        })
    }

}






export function boring_execute(moduleName:string, is_base_hook: boolean){
    var boring_ssl = new OpenSSL_BoringSSL_Linux(moduleName,socket_library, is_base_hook);
    boring_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = boring_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }

}