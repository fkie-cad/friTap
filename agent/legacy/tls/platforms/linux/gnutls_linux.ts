
import {GnuTLS } from "../../../../tls/libs/gnutls.js";
import { socket_library } from "../../../../platforms/linux.js";
import { devlog, log } from "../../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

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
        const addrs = this.addresses[this.module_name];
        devlog(`[gnutls] hooks: init @ ${addrs["gnutls_init"]}, set_keylog @ ${addrs["gnutls_session_set_keylog_function"]}, handshake @ ${addrs["gnutls_handshake"]}`);

        // One-shot pattern discovery on the callback address (see
        // attachDynamicDiscovery in agent/tls/libs/gnutls.ts). Detaches itself
        // after the first resolution — no ongoing per-secret overhead.
        GnuTLS.attachDynamicDiscovery();

        // Inject our keylog callback into every session created via
        // gnutls_init. Wine's schannel takes this path on every fresh
        // handshake, which is why the callback fires reliably.
        Interceptor.attach(addrs["gnutls_init"], {
            onEnter(args: any) { this.session = args[0]; },
            onLeave(_retval: any) {
                try {
                    GnuTLS.gnutls_session_set_keylog_function(this.session.readPointer(), GnuTLS.keylog_callback);
                } catch (e) {
                    devlog(`[gnutls] set_keylog_function on new session failed: ${e}`);
                }
            },
        });
    }

}




export function gnutls_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(GnuTLS_Linux, moduleName, socket_library, is_base_hook);
}
