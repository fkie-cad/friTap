
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { devlog, devlog_error } from "../util/log.js";
import { socket_library } from "./android_agent.js";

export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_tls_keys_callback_hook (){

        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;
        let callback_already_set = false;        
                
        Interceptor.attach(this.addresses[this.module_name]["SSL_new"],
            {
                onEnter: function (args: any) {
                    try{
                        callback_already_set = true;
                        instance.SSL_CTX_set_keylog_callback(args[0], instance.keylog_callback);
                    }catch (e) {
                        callback_already_set = false;
                        devlog_error(`Error in SSL_new hook: ${e}`);
                    }
                    
                }
        
            });
            if (this.addresses[this.module_name]["SSL_CTX_new"] !== null && callback_already_set === false) {
            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"],
                {
                    onLeave: function (retval: any) {
                        try {
                            if (retval.isNull()) {
                                devlog_error("SSL_CTX_new returned NULL");
                                return;
                            }
                            instance.SSL_CTX_set_keylog_callback(retval, instance.keylog_callback);
                        }catch (e) {
                            devlog_error(`Error in SSL_CTX_new hook: ${e}`);
                        }
                    }
            
                });
        }

        // In case a callback is set by the application, we attach to this callback instead
        // Only succeeds if SSL_CTX_new is available
        Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], {
            onEnter: function (args: any) {
                let callback_func = args[1];

                Interceptor.attach(callback_func, {
                    onEnter: function (args: any) {
                        var message: { [key: string]: string | number | null } = {};
                        message["contentType"] = "keylog";
                        message["keylog"] = args[1].readCString();
                        send(message);
                    }
                });
            }
        });
    }

    install_conscrypt_tls_keys_callback_hook (){
        try{    
            this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
            var instance = this;

            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"], {
                onLeave: function(retval) {
                    const ssl = new NativePointer(retval);
                    if (!ssl.isNull()) {
                        instance.SSL_CTX_set_keylog_callback(ssl, instance.keylog_callback)
                    }
                }
            });
        }catch(e){
            // right now this will sillently fail
        }

    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
        this.install_conscrypt_tls_keys_callback_hook();
        this.install_extended_hooks();
    }

    execute_conscrypt_hooks(){
        this.install_conscrypt_tls_keys_callback_hook();
    }

}


export function boring_execute(moduleName:string, is_base_hook: boolean){
    var boring_ssl = new OpenSSL_BoringSSL_Android(moduleName,socket_library,is_base_hook);
    try {
        boring_ssl.execute_hooks();
    }catch(error_msg){
        devlog(`boring_execute error: ${error_msg}`)
    }

    if (is_base_hook) {
        try {
        const init_addresses = boring_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }}catch(error_msg){
            devlog(`boring_execute base-hook error: ${error_msg}`)
        }
    }

}