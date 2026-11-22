
import {NSS } from "../../../../tls/libs/nss.js";
import { socket_library } from "../../../../platforms/linux.js";
import { installLegacyNssKeyExtraction } from "../../libs/nss_key_extraction.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class NSS_Linux extends NSS {

    constructor(public moduleName:string, public socket_library:String){
        var library_method_mapping : { [key: string]: Array<string> }= {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"]
        library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData", "NSSSSL_GetVersion"]
        library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback", "SSL_GetExperimentalAPI"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

        super(moduleName,socket_library,library_method_mapping);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook()
    }

    install_tls_keys_callback_hook() {
        void installLegacyNssKeyExtraction(this.module_name, this.addresses[this.module_name]);
    }

}


export function nss_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(NSS_Linux as any, moduleName, socket_library, is_base_hook);
}
