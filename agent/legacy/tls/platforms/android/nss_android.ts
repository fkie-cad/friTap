
import { NSS } from "../../../../tls/libs/nss.js";
import { installLegacyNssKeyExtraction } from "../../libs/nss_key_extraction.js";
import { socket_library } from "../../../../platforms/android.js";
import { devlog } from "../../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class NSS_Android extends NSS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        var library_method_mapping : { [key: string]: Array<string> }= {};
        devlog("Hooking module "+moduleName);
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType", "SSL_ImportFD", "SSL_HandshakeCallback", "PK11_ExtractKeyValue", "PK11_GetKeyData", "SSL_GetExperimentalAPI", "NSSSSL_GetVersion"]
        // "SSL_GetSessionID" is not available
        //library_method_mapping[`*libnss.*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
        //library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

        super(moduleName,socket_library,library_method_mapping);
    }




    execute_hooks(){
        // Plaintext PR_Read / PR_Write (shared NSS class), as on legacy Linux/macOS/Windows and
        // modern Android. NSPR's own PR_GetPeerName/PR_GetSockName/PR_GetDescType resolve from
        // the folded libnss3.so; libc's getpeername/getsockname/ntohs/ntohl from socket_library.
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        try{
            devlog("[!] NSS 1.3 Client Random working; keys are still not exported..");
            this.install_tls_keys_callback_hook() // might fail
        }catch(e){
            devlog("Installing NSS key hooking - still early development stage");
            devlog("NSS Error code: "+e);
        }
    }

    install_tls_keys_callback_hook() {
        void installLegacyNssKeyExtraction(this.module_name, this.addresses[this.module_name]);
    }

}


export function nss_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(NSS_Android, moduleName, socket_library, is_base_hook);
}
