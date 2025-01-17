
import {GnuTLS } from "../ssl_lib/gnutls.js";
import { socket_library } from "./android_agent.js";
import { devlog } from "../util/log.js";

export class GnuTLS_Linux extends GnuTLS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        Interceptor.attach(this.addresses[this.module_name]["gnutls_init"],
    {
        onEnter: function (args: any) {
            this.session = args[0]
        },
        onLeave: function (retval: any) {
            devlog("[!] Logging session information: "+this.session);
            GnuTLS.gnutls_session_set_keylog_function(this.session.readPointer(), GnuTLS.keylog_callback)

        }
    })

    }
}


export function gnutls_execute(moduleName:string, is_base_hook: boolean){
    var gnutls_ssl = new GnuTLS_Linux(moduleName,socket_library, is_base_hook);
    gnutls_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = gnutls_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }

}