import { readAddresses, getPortsAndAddresses, getBaseAddress} from "../shared/shared_functions.js";
import { enable_default_fd, offsets } from "../ssl_log.js";
import { log } from "../util/log.js";


export class matrix_SSL {



    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;

    static matrixSslNewCLientSession: any;
    static sessionId: string;
    static matrixSslGetSid: any;


    constructor(public moduleName: string, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<string> }) {
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        } else {
            this.library_method_mapping[`*${moduleName}*`] = ["matrixSslReceivedData", "matrixSslGetWritebuf", "matrixSslGetSid", "matrixSslEncodeWritebuf"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl", "socket"];
        }

        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.matrixssl != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[this.moduleName][`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            }

            
            for (const method of Object.keys(offsets.matrixssl)){
                //@ts-ignore
                this.addresses[this.moduleName][`${method}`] = offsets.matrixssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.matrixssl[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.matrixssl[`${method}`].address));
            }

           
        }

        //Creates a new client session. If this happens we will save the id of this new session
        matrix_SSL.matrixSslNewCLientSession = new NativeFunction(this.addresses[this.moduleName]["matrixSslNewClientSession"], "int", ["pointer", "pointer", "pointer", "pointer", "int", "pointer", "pointer", "pointer", "pointer", "pointer"]);
        //This function extracts the sessionID object out of the ssl object
        matrix_SSL.matrixSslGetSid = new NativeFunction(this.addresses[this.moduleName]["matrixSslGetSid"], "pointer", ["pointer"]);
        
    }


    


    install_plaintext_read_hook() {
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        
    
        Interceptor.attach(this.addresses[this.moduleName]["matrixSslReceivedData"], {
            onEnter: function (args) {
                this.buffer = args[2];
                this.len = args[3];
                

                var message = getPortsAndAddresses(this.fd as number, true, lib_addesses[current_module_name], enable_default_fd)
                message["ssl_session_id"] = this.addresses[this.moduleName]["matrixSslGetSid"] === undefined ? matrix_SSL.sessionId : this.getSessionId(args[0]);
                message["function"] = "matrixSslReceivedData"
                this.message = message
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }

                var data = this.buffer.readByteArray(this.len);
                this.message["contentType"] = "datalog"
                send(this.message, data)


            }

        });

    }


    install_plaintext_write_hook() {
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        //This function is needed to extract the buffer address in which the plaintext will be stored before registring this buffer as the "sent data" buffer.
        Interceptor.attach(this.addresses[this.moduleName]["matrixSslGetWritebuf"], {
            onEnter: function (args) {
                this.outBuffer = args[1];
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }
                this.outBufferLength = retval


            }
           
        });

         //This function actual encodes the plaintext. We need to hook this, because the user will fill the data out buffer between matrixSslGetWritebuf and matrixSslEncodeWritebuf call.
         //So at the time this function is called, the buffer with the plaintext will be final 
         Interceptor.attach(this.addresses[this.moduleName]["matrixSslEncodeWritebuf"], {

            onEnter: function (args) {
                var data = this.outBuffer.readByteArray(this.outBufferLength);
                var message = getPortsAndAddresses(this.fd, false, lib_addesses[current_module_name], enable_default_fd)
                message["ssl_session_id"] = this.addresses[this.moduleName]["matrixSslGetSid"] === undefined ? matrix_SSL.sessionId : this.getSessionId(args[0]);
                message["function"] = "matrixSslEncodeWritebuf"
                message["contentType"] = "datalog"
                send(message, data)
            }
        });

    }


    install_tls_keys_callback_hook() {
        // TBD
    }

    install_helper_hook(){        
    
        Interceptor.attach(this.addresses[this.moduleName]["matrixSslNewSessionId"], {
            onEnter: function (args) {
                this.sslSessionPointer = args[0];
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }

                var sessionIdLength = this.sslSessionPointer.add(2 * Process.pointerSize).readU32();
                matrix_SSL.sessionId = this.sslSessionPointer.add(Process.pointerSize).readPointer().readCString(sessionIdLength);                
            }

        });

        Interceptor.attach(this.addresses[this.moduleName]["connect"], {
            onEnter: function (args) {
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }

                this.fd = retval;               
            }
        })
    }

    getSessionId(ssl: any){
        const sid = matrix_SSL.matrixSslGetSid(ssl);
        const sessionIdLength = sid.add(2 * Process.pointerSize).readU32();
        const sessionId = sid.add(Process.pointerSize).readPointer().readCString(sessionIdLength);
        return sessionId;
    }


}

