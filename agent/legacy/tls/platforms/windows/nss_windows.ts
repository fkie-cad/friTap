import {NSS } from "../../../../tls/libs/nss.js";
import { socket_library } from "../../../../platforms/windows.js";
import { devlog } from "../../../../util/log.js";
import { nssWindowsMethodMapping } from "../../../../tls/libs/nss_windows_libraries.js";
import { installLegacyNssKeyExtraction } from "../../libs/nss_key_extraction.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class NSS_Windows extends NSS {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        // Folded nss3.dll (Firefox/Thunderbird, MOZ_FOLD_LIBS) carries PR_*, SSL_* and PK11_*;
        // an unfolded (lib)nspr4.dll gets SSL_* from (lib)ssl3.dll and PK11_* from (lib)nss3.dll.
        // See agent/tls/libs/nss_windows_libraries.ts (shared with the modern definition).
        var library_method_mapping : { [key: string]: Array<string> } = nssWindowsMethodMapping(moduleName, String(socket_library));

        super(moduleName,socket_library,library_method_mapping);
    }

    install_tls_keys_callback_hook(){
        void installLegacyNssKeyExtraction(this.module_name, this.addresses[this.module_name]);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        try {
            this.install_tls_keys_callback_hook();
        } catch (e) {
            devlog("Installing NSS key hooking failed");
            devlog("NSS Error code: " + e);
        }
    }

}


export function nss_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(NSS_Windows, moduleName, socket_library, is_base_hook);
}
