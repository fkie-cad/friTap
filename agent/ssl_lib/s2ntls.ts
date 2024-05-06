import { readAddresses} from "../shared/shared_functions.js"

export class S2nTLS {

    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };

    constructor(public moduleName: String, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<String>}){

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["s2n_send", "s2n_recv"];
            this.library_method_mapping[`*${socket_library}*`] = ["??"]; //welche Socketlibraries? an welcher Stelle relevant?
        }

        this.addresses = readAddresses(this.library_method_mapping);
    }

    install_tls_keys_callback_hook(){}

    install_plaintext_read_hook(){}

    install_plaintext_write_hook(){}

}