
import {NSS } from "../ssl_lib/nss.js"
import { socket_library } from "./android_agent.js";

export class NSS_Android extends NSS {

    constructor(public moduleName:String, public socket_library:String){
        var library_method_mapping : { [key: string]: Array<String> }= {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"]
        library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
        library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

        super(moduleName,socket_library,library_method_mapping);
    }

    
    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        //this.install_tls_keys_callback_hook() // might fail 
    }

}


export function nss_execute(moduleName:String){
    var nss_ssl = new NSS_Android(moduleName,socket_library);
    nss_ssl.execute_hooks();


}