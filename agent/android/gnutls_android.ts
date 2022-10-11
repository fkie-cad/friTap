
import {GnuTLS } from "../ssl_lib/gnutls.js"
import { socket_library } from "./android_agent.js";

export class GnuTLS_Linux extends GnuTLS {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        Interceptor.attach(this.addresses["gnutls_init"],
    {
        onEnter: function (args: any) {
            this.session = args[0]
        },
        onLeave: function (retval: any) {
            console.log(this.session)
            GnuTLS.gnutls_session_set_keylog_function(this.session.readPointer(), GnuTLS.keylog_callback)

        }
    })

    }
}


export function gnutls_execute(moduleName:String){
    var gnutls_ssl = new GnuTLS_Linux(moduleName,socket_library);
    gnutls_ssl.execute_hooks();


}