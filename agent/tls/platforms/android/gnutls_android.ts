
import {GnuTLS } from "../../libs/gnutls.js";
import { socket_library } from "../../../platforms/android.js";
import { devlog } from "../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions.js";

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
    executeSSLLibrary(GnuTLS_Linux, moduleName, socket_library, is_base_hook);
}