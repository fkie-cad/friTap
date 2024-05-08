import { socket_library } from "./linux_agent.js";
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

    //implement key callback hook
}

export function s2ntls_execute(moduleName: String){
    var s2n_tls = new S2nTLS_Linux(moduleName, socket_library);
    s2n_tls.execute_hooks();
}