import { socket_library } from "./linux_agent.js";
import { S2nTLS } from "../ssl_lib/s2ntls.js";

export class S2nTLS_Linux extends S2nTLS{

    constructor(public moduleName: String, public socket_library: String){
        super(moduleName, socket_library);
    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        S2nTLS.s2n_set_key_log_cb = new NativeFunction(this.addresses["s2n_config_set_key_log_cb"], "int", ["pointer", "pointer", "pointer"]); //args=[config, callback, ctx]
    
        Interceptor.attach(this.addresses["s2n_connection_set_config"], 
        {
            onEnter: function(args: any){
                S2nTLS.s2n_set_key_log_cb(args[0], S2nTLS.keylog_callback, NULL);
            }
        })
    }
}

export function s2ntls_execute(moduleName: String){
    var s2n_tls = new S2nTLS_Linux(moduleName, socket_library);
    s2n_tls.execute_hooks();
}