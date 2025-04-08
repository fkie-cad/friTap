
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { socket_library } from "./linux_agent.js";
import { devlog } from "../util/log.js";

export class OpenSSL_BoringSSL_Linux extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_tls_keys_callback_hook (){

        this.SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;
        
        if (this.addresses[this.module_name]["SSL_CTX_new"] === null) {
            Interceptor.attach(this.addresses[this.module_name]["SSL_new"],
                {
                    onEnter: function (args: any) {
                        instance.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback)
                    }
            
                });
        } else {
            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"],
                {
                    onLeave: function (retval: any) {
                        instance.SSL_CTX_set_keylog_callback(retval, OpenSSL_BoringSSL.keylog_callback)
                    }
            
                });
        }

        // In case a callback is set by the appliction, we attach to this callback instead 
        // Only succeeds if SSL_CTX_new is available
        let setter_address = ObjC.available ? "SSL_CTX_set_info_callback" : "SSL_CTX_set_keylog_callback";
        Interceptor.attach(this.addresses[this.module_name][setter_address], {
            onEnter: function(args: any) {
                let callback_func = args[1];
                //devlog("args[1]: " + callback_func);

                Interceptor.attach(callback_func, {
                    onEnter: function(args: any) {
                        var message: { [key: string]: string | number | null } = {}
                        message["contentType"] = "keylog"
                        message["keylog"] = args[1].readCString()
                        send(message)
                    }
                });
            }
        });
        
    }



    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
        this.install_extended_hooks();
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