import { readAddresses, getPortsAndAddresses, getBaseAddress } from "../shared/shared_functions.js"
import { pointerSize } from "../shared/shared_structures.js"
import { getOffsets, offsets } from "../ssl_log.js"
import { devlog, log } from "../util/log.js"

/**
 * 
 * ToDO
 *  We need to find a way to calculate the offsets in a automated manner.
 *  Darwin: SSL_read/write need improvments
 *  Windows: how to extract the key material?
 *  Android: We need to find a way, when on some Android Apps the fd is below 0
 */

export class OpenSSL_BoringSSL {

    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };
    static SSL_SESSION_get_id: any;
    static SSL_CTX_set_keylog_callback : any;
    static SSL_get_fd: any;
    static SSL_get_session: any;
   

    static keylog_callback = new NativeCallback(function (ctxPtr, linePtr: NativePointer) {
        devlog("invoking keylog_callback from OpenSSL_BoringSSL");
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = linePtr.readCString()
        send(message)
    }, "void", ["pointer", "pointer"])

   


    constructor(public moduleName:String, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<String> }){
        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }
        
        this.addresses = readAddresses(this.library_method_mapping);

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.openssl != null){
            
            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null)
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            

            
            for (const method of Object.keys(offsets.openssl)){
                //@ts-ignore
                this.addresses[`${method}`] = offsets.openssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.openssl[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.openssl[`${method}`].address));
            }

            

        }

        OpenSSL_BoringSSL.SSL_SESSION_get_id = new NativeFunction(this.addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
        OpenSSL_BoringSSL.SSL_get_fd = ObjC.available ? new NativeFunction(this.addresses["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(this.addresses["SSL_get_fd"], "int", ["pointer"]);
        OpenSSL_BoringSSL.SSL_get_session = new NativeFunction(this.addresses["SSL_get_session"], "pointer", ["pointer"]);
        
    }


    install_plaintext_read_hook(){
        var lib_addesses = this.addresses;

        Interceptor.attach(this.addresses["SSL_read"],
        {
            onEnter: function (args: any) {
                this.fd = OpenSSL_BoringSSL.SSL_get_fd(args[0])
                if(this.fd < 0) {
                    return
                }
            
                var message = getPortsAndAddresses(this.fd as number, true, lib_addesses)
                message["ssl_session_id"] = OpenSSL_BoringSSL.getSslSessionId(args[0])
                message["function"] = "SSL_read"
                this.message = message
                this.buf = args[1]
            
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0 || this.fd < 0) {
                    return
                }
                this.message["contentType"] = "datalog"
                send(this.message, this.buf.readByteArray(retval))
            }
        })

    }

    install_plaintext_write_hook(){
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["SSL_write"],
        {
            onEnter: function (args: any) {
                if (!ObjC.available){
                this.fd = OpenSSL_BoringSSL.SSL_get_fd(args[0])
                if(this.fd < 0) {
                    return
                }
                var message = getPortsAndAddresses(this.fd as number, false, lib_addesses)
                message["ssl_session_id"] = OpenSSL_BoringSSL.getSslSessionId(args[0])
                message["function"] = "SSL_write"
                message["contentType"] = "datalog"
                send(message, args[1].readByteArray(parseInt(args[2])))
                } // this is a temporary workaround for the fd problem on iOS
            },
            onLeave: function (retval: any) {
            }
        })
    }

    install_tls_keys_callback_hook(){
        log("Error: TLS key extraction not implemented yet.")
    }

     /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
      static getSslSessionId(ssl: NativePointer) {
          
        var session = OpenSSL_BoringSSL.SSL_get_session(ssl) as NativePointer
        if (session.isNull()) {
            log("Session is null")
            return 0
        }
        var len_pointer = Memory.alloc(4)
        var p = OpenSSL_BoringSSL.SSL_SESSION_get_id(session, len_pointer) as NativePointer
        var len = len_pointer.readU32()
        var session_id = ""
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return session_id
    }



}