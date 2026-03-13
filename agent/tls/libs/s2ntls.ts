import { readAddresses, getPortsAndAddresses, resolveOffsets} from "../../shared/shared_functions.js"
import { sendKeylog, sendDatalog } from "../../shared/shared_structures.js"
import { enable_default_fd } from "../../fritap_agent.js"
import { log, devlog } from "../../util/log.js"
import { resolveWithPipeline } from "../../shared/pipeline_utils.js"


export class S2nTLS {

    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;

    static s2n_get_read_fd: any;
    static s2n_get_write_fd: any;
    static s2n_set_key_log_cb: any;

    //this function logs the given keylog line
    static keylog_callback = new NativeCallback(function(ctxPtr, conn: NativePointer, logline: NativePointer, len: NativePointer){
        devlog("invoking keylog_callback from s2ntls");
        sendKeylog(logline.readCString(len.toInt32()));
        return 1;
    }, "int", ["pointer", "pointer", "pointer", "pointer"]);

    constructor(public moduleName: string, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<string>}){

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["s2n_send", "s2n_recv", "s2n_connection_get_read_fd", "s2n_connection_get_write_fd", "s2n_connection_new", "s2n_config_set_key_log_cb", "s2n_connection_set_config", "s2n_config_new"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]; 
        }

        this.addresses = readAddresses(moduleName, this.library_method_mapping);
        this.module_name = moduleName;

        resolveOffsets(this.addresses, this.moduleName, socket_library, "s2n");

        resolveWithPipeline(this.addresses, this.moduleName, "s2n", [
            "s2n_send", "s2n_recv", "s2n_connection_get_read_fd",
            "s2n_connection_get_write_fd", "s2n_connection_new",
            "s2n_config_set_key_log_cb"
        ]);

        //s2n_connection-get_read_fd and s2n_connection_get_write_fd return the corresponding file descriptors
        S2nTLS.s2n_get_read_fd = new NativeFunction(this.addresses[this.moduleName]["s2n_connection_get_read_fd"], "int", ["pointer", "pointer"]);
        S2nTLS.s2n_get_write_fd = new NativeFunction(this.addresses[this.moduleName]["s2n_connection_get_write_fd"], "int", ["pointer", "pointer"]);
    }

    install_tls_keys_callback_hook(){}

    //Hooks the s2n_send function
    //Get the buffer on enter and read the data from it
    install_plaintext_read_hook(){
        var current_module_name = this.module_name;
        var lib_addresses = this.addresses;

        Interceptor.attach(lib_addresses[this.moduleName]["s2n_recv"], {

            onEnter: function(args: any){

                var readfdPtr = Memory.alloc(Process.pointerSize) as NativePointer;
                S2nTLS.s2n_get_read_fd(args[0], readfdPtr);
                var readfd = readfdPtr.readInt();
                var message = getPortsAndAddresses(readfd, false, lib_addresses[current_module_name], enable_default_fd);

                message["function"] = "s2n_recv";
                message["ssl_session_id"] = "0"
                this.message = message;
                this.buf = args[1];

            },
            onLeave: function(retval: any){
                try {
                    retval = parseInt(retval);
                    if (retval <= 0 || retval > 184332) { 
                        return;
                    }
            
                    // Ensure this.buf is valid before accessing it
                    if (this.buf && this.buf.readByteArray) {
                        sendDatalog(this.message, this.buf.readByteArray(retval));
                    } else {
                        console.error("Buffer is not valid or readByteArray method is missing.");
                    }
                } catch (error) {
                    console.error("Error in onLeave (retval: "+retval+ "):", error);
                }
            }
        })
    }

    //Hooks the s2n_recv function
    //Get the buffer on enter and read the retval bytes from it on leave
    install_plaintext_write_hook(){
        var current_module_name = this.module_name;
        var lib_addresses = this.addresses;

        Interceptor.attach(lib_addresses[this.moduleName]["s2n_send"], {

            onEnter: function(args: any){
                
                var writefdPtr = Memory.alloc(Process.pointerSize) as NativePointer;
                S2nTLS.s2n_get_write_fd(args[0], writefdPtr);
                var writefd = writefdPtr.readInt();
                var message = getPortsAndAddresses(writefd, true, lib_addresses[current_module_name], enable_default_fd);

                message["function"] = "s2n_send";
                message["ssl_session_id"] = "0"
                this.message = message;
                this.buf = args[1];
            },
            onLeave: function(retval: any){
                
                retval = parseInt(retval);
                if(retval < 0){ 
                    return;
                }

                sendDatalog(this.message, this.buf.readByteArray(retval));
            }
        })
    }

}