import { S2nTLS } from "../ssl_lib/s2ntls";

export class S2nTLS_Linux extends S2nTLS{

    constructor(public moduleName: String, public socket_library: String){
        super(moduleName, socket_library);
    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }
}