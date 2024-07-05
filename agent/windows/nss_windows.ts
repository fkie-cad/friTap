
import {NSS } from "../ssl_lib/nss.js";
import { socket_library } from "./windows_agent.js";

export class NSS_Windows extends NSS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        var library_method_mapping : { [key: string]: Array<string> }= {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity"]
        // library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
        library_method_mapping["*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"]

        super(moduleName,socket_library,library_method_mapping);
    }

    install_tls_keys_callback_hook(){
        // TBD
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        // this.install_tls_keys_callback_hook(); needs to be implemented
    }

}


export function nss_execute(moduleName:string, is_base_hook: boolean){
    var nss_ssl = new NSS_Windows(moduleName,socket_library, is_base_hook);
    nss_ssl.execute_hooks();

    if (is_base_hook) {
        const init_addresses = nss_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }

}