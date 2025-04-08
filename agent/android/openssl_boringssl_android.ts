
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { devlog } from "../util/log.js";
import { socket_library } from "./android_agent.js";

export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_tls_keys_callback_hook (){

        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;

        if (this.addresses[this.module_name]["SSL_CTX_new"] === null) {
            Interceptor.attach(this.addresses[this.module_name]["SSL_new"], {
                onEnter: function (args: any) {
                    instance.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback);
                }
            });
        } else {
            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"], {
                onLeave: function (retval: any) {
                    instance.SSL_CTX_set_keylog_callback(retval, OpenSSL_BoringSSL.keylog_callback);
                }
            });
        }

        // In case a callback is set by the application, we attach to this callback instead
        // Only succeeds if SSL_CTX_new is available
        let setter_address = ObjC.available ? "SSL_CTX_set_info_callback" : "SSL_CTX_set_keylog_callback";
        Interceptor.attach(this.addresses[this.module_name][setter_address], {
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
                        instance.SSL_CTX_set_keylog_callback(ssl, OpenSSL_BoringSSL.keylog_callback)
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
            (global as any).init_addresses[moduleName] = init_addresses;
        }}catch(error_msg){
            devlog(`boring_execute base-hook error: ${error_msg}`)
        }
    }

}