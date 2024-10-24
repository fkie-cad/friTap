
import {GnuTLS } from "../ssl_lib/gnutls.js";
import { socket_library } from "./windows_agent.js";

export class GnuTLS_Windows extends GnuTLS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();

        //this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        //Not implemented yet
    }

}


export function gnutls_execute(moduleName:string, is_base_hook: boolean){
    var gnu_ssl = new GnuTLS_Windows(moduleName,socket_library, is_base_hook);
    gnu_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = gnu_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }
}