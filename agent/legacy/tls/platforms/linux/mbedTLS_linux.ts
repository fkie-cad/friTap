
import {mbed_TLS } from "../../../../tls/libs/mbedTLS.js";
import { socket_library } from "../../../../platforms/linux.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class mbed_TLS_Linux extends mbed_TLS {

    constructor(public moduleName:string, public socket_library:String){
        super(moduleName,socket_library);
    }

    /*
    mbedTLS does not expose a keylog callback by default.
    We need to find a way to install the callback function for doing that.

	Alternatives?: SSL_export_keying_material, custom struct offset extraction
    */
    install_tls_keys_callback_hook(){
        // mbedTLS keylog extraction not yet implemented
    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }

}


export function mbedTLS_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(mbed_TLS_Linux as any, moduleName, socket_library, is_base_hook);
}
