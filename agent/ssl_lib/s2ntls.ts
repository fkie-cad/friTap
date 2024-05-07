import { readAddresses, getBaseAddress} from "../shared/shared_functions.js"
import { offsets } from "../ssl_log.js" 
import { log } from "../util/log.js"

export class S2nTLS {

    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };

    static s2n_get_read_fd: any;
    static s2n_get_write_fd: any;
    static s2n_get_session: any;

    constructor(public moduleName: String, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<String>}){

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["s2n_send", "s2n_recv", "s2n_connection_get_read_fd", "s2n_connection_get_write_fs", "s2n_connection_get_session"]; //natürlich noch erweitern
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]; //welche Socketlibraries? an welcher Stelle relevant?
        }

        this.addresses = readAddresses(this.library_method_mapping);

        //@ts-ignore
        if(offsets != "{OFFSETS}" && offsets.s2n != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library);

                for(const method of Object.keys(offsets.sockets)){
                    
                    const methodOffset = offsets.sockets[`${method}`];
                    const isAbsolute = methodOffset.absolute;
                    //@ts-ignore
                    const methodAddress = ptr(methodOffset.address);

                    if(isAbsolute || socketBaseAddress == null){
                        this.addresses[`${method}`] = methodAddress;
                    }else{
                        this.addresses[`${method}`] = socketBaseAddress.add(methodAddress);
                    }

                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName);

            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!");
            }

            for(const method of Object.keys(offsets.s2n)){

                const methodOffset = offsets.s2n[`${method}`];
                const isAbsolute = methodOffset.absolute;
                //@ts-ignore
                const methodAddress = ptr(methodOffset.address);

                if(isAbsolute || libraryBaseAddress == null){
                    this.addresses[`${method}`] = methodAddress;
                }else{
                    this.addresses[`${method}`] = libraryBaseAddress.add(methodAddress);
                }

            }
        }

        //s2n_connection-get_read_fd und s2n_connection_get_write_fd
        S2nTLS.s2n_get_read_fd = new NativeFunction(this.addresses["s2n_connection_get_read_fd"], "int", ["pointer"]);
        S2nTLS.s2n_get_write_fd = new NativeFunction(this.addresses["s2n_connection_get_write_fd"], "int", ["pointer"]);

        S2nTLS.s2n_get_session = new NativeFunction(this.addresses["s2n_connection_get_session"], "pointer", ["pointer"]);
    }

    install_tls_keys_callback_hook(){}

    install_plaintext_read_hook(){}

    install_plaintext_write_hook(){}

}