import { readAddresses, getPortsAndAddresses, toHexString, getBaseAddress } from "../shared/shared_functions.js"
import { log } from "../util/log.js"
import { offsets } from "../ssl_log.js";

export class GnuTLS {

    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };
    
    static gnutls_transport_get_int : any;
    static gnutls_session_get_id: any;
    static gnutls_session_get_random: any;
    static gnutls_session_set_keylog_function: any;

    
   

    constructor(public moduleName:String, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<String> }){
        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }
        
        this.addresses = readAddresses(this.library_method_mapping);


        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.gnutls != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            }

            
            for (const method of Object.keys(offsets.gnutls)){
                //@ts-ignore
                this.addresses[`${method}`] = offsets.gnutls[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.gnutls[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.gnutls[`${method}`].address));
            }


        }

        GnuTLS.gnutls_transport_get_int = new NativeFunction(this.addresses["gnutls_transport_get_int"], "int", ["pointer"])
        GnuTLS.gnutls_session_get_id = new NativeFunction(this.addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"])
        GnuTLS.gnutls_session_set_keylog_function = new NativeFunction(this.addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"])
        GnuTLS.gnutls_session_get_random = new NativeFunction(this.addresses["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"])

    }

    //NativeCallback
    static keylog_callback = new NativeCallback(function (session: NativePointer, label: NativePointer, secret: NativePointer) {
        
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"

        var secret_len = secret.add(Process.pointerSize).readUInt()
        var secret_str = ""
        var p = secret.readPointer()

        for (var i = 0; i < secret_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to secret_str.

            secret_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        
        var server_random_ptr = Memory.alloc(Process.pointerSize + 4)
        var client_random_ptr = Memory.alloc(Process.pointerSize + 4)
        
        if( typeof this !== "undefined"){
            
            GnuTLS.gnutls_session_get_random(session, client_random_ptr, server_random_ptr)
        }else{
            console.log("[-] Error while installing keylog callback");
        }
       
        var client_random_str = ""
        var client_random_len = 32
        p = client_random_ptr.readPointer()
        for (i = 0; i < client_random_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to client_random_str.

            client_random_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        message["keylog"] = label.readCString() + " " + client_random_str + " " + secret_str
        send(message)
        return 0
    }, "int", ["pointer", "pointer", "pointer"])


    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
     static getSslSessionId(session: NativePointer) {
        var len_pointer = Memory.alloc(4)
        var err = GnuTLS.gnutls_session_get_id(session, NULL, len_pointer)
        if (err != 0) {
            return ""
        }
        var len = len_pointer.readU32()
        var p = Memory.alloc(len)
        err = GnuTLS.gnutls_session_get_id(session, p, len_pointer)
        if (err != 0) {
            return ""
        }
        var session_id = ""
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return session_id
    }

    install_plaintext_read_hook(){
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["gnutls_record_recv"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(GnuTLS.gnutls_transport_get_int(args[0]) as number, true, lib_addesses)
            message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0])
            message["function"] = "SSL_read"
            this.message = message
            this.buf = args[1]
        },
        onLeave: function (retval: any) {
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            this.message["contentType"] = "datalog"
            send(this.message, this.buf.readByteArray(retval))
        }
    })

    }
    
    install_plaintext_write_hook(){
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses["gnutls_record_send"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(GnuTLS.gnutls_transport_get_int(args[0]) as number, false, lib_addesses)
            message["ssl_session_id"] = GnuTLS.getSslSessionId(args[0])
            message["function"] = "SSL_write"
            message["contentType"] = "datalog"
            send(message, args[1].readByteArray(parseInt(args[2])))
        },
        onLeave: function (retval: any) {
        }
    })

    }
    
    install_tls_keys_callback_hook(){
        
    }



}