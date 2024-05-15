import { readAddresses, getBaseAddress, getPortsAndAddresses} from "../shared/shared_functions.js"
import { offsets, enable_default_fd } from "../ssl_log.js" 
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
            this.library_method_mapping[`*${moduleName}*`] = ["s2n_send", "s2n_recv", "s2n_connection_get_read_fd", "s2n_connection_get_write_fd", "s2n_connection_get_session"]; //natürlich noch erweitern
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
        S2nTLS.s2n_get_read_fd = new NativeFunction(this.addresses["s2n_connection_get_read_fd"], "int", ["pointer", "pointer"]);
        S2nTLS.s2n_get_write_fd = new NativeFunction(this.addresses["s2n_connection_get_write_fd"], "int", ["pointer", "pointer"]);

    
        S2nTLS.s2n_get_session = new NativeFunction(this.addresses["s2n_connection_get_session"], "int", ["pointer", "pointer", "size_t"]);
    }

    install_tls_keys_callback_hook(){}

    install_plaintext_read_hook(){

        var lib_addresses = this.addresses;

        Interceptor.attach(lib_addresses["s2n_send"], {

            onEnter: function(args: any){
                
                var readfdPtr = Memory.alloc(Process.pointerSize) as NativePointer;
                S2nTLS.s2n_get_read_fd(args[0], readfdPtr);
                var readfd = readfdPtr.readInt();
                var message = getPortsAndAddresses(readfd, true, lib_addresses, enable_default_fd);

                message["function"] = "s2n_send";
                message["ssl_session_id"] = "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338" //no session ids
                this.message = message;
                this.buf = args[1];
            },
            onLeave: function(retval: any){
                
                retval = parseInt(retval);
                if(retval < 0){ //on Failure: retval = S2N_Failure = -1
                    return;
                }

                //on Success: retval = number of bytes sent
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        })
    }

    install_plaintext_write_hook(){
        //args(conn, buf, size, blocked)
        var lib_addresses = this.addresses;

        Interceptor.attach(lib_addresses["s2n_recv"], {

            onEnter: function(args: any){

                var writefdPtr = Memory.alloc(Process.pointerSize) as NativePointer;
                S2nTLS.s2n_get_write_fd(args[0], writefdPtr);
                var writefd = writefdPtr.readInt();
                var message = getPortsAndAddresses(writefd, false, lib_addresses, enable_default_fd);

                message["function"] = "s2n_recv";
                message["ssl_session_id"] = "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338" //no session ids
                this.message = message;
                this.buf = args[1];

            },
            onLeave: function(retval: any){
                retval = parseInt(retval);
                if(retval < 0){ //on Failure: retval = S2N_Failure = -1
                    return;
                }

                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        })
    }

    /*
    static get_Tls_session_id(connection: NativePointer, ses: NativePointer){

        var session = S2nTLS.s2n_get_session(connection, ses, 1) as NativePointer;
        if(session.isNull()){

            if(enable_default_fd){
                log("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338");
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338";
            }

            log("Session is null");
            return 0;
        }
        //überprüfen
        var len = 32;
        var sessionid = "";
        var p = session.add(0);
        for(var i = 0; i < len; i++){
            sessionid += ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }

        return sessionid;
    }
    */

}