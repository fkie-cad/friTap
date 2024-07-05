
import {WolfSSL } from "../ssl_lib/wolfssl.js";
import { socket_library } from "./windows_agent.js";
import { log } from "../util/log.js";

export class WolfSSL_Windows extends WolfSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        let mapping:{ [key: string]: Array<string> } = {};
        mapping[`${moduleName}`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays"]
        mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        super(moduleName,socket_library, mapping);
    }

    
    install_tls_keys_callback_hook(){
        log("Key extraction currently not implemented for windows!");
    }




    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook(); currently not implemented
    }

}


export function wolfssl_execute(moduleName:string, is_base_hook: boolean){
    var wolf_ssl = new WolfSSL_Windows(moduleName,socket_library, is_base_hook);
    wolf_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = wolf_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }
}