import { readAddresses, getPortsAndAddresses, getBaseAddress } from "../shared/shared_functions.js"
import { pointerSize } from "../shared/shared_structures.js"
import { getOffsets, offsets } from "../ssl_log.js"
import { devlog, log } from "../util/log.js"


class ModifyReceiver{
    public readModification: ArrayBuffer | null = null;
    public writeModification: ArrayBuffer | null = null;
    constructor(){
        this.listenForReadMod();
        this.listenForWriteMod();    
    }

    private listenForReadMod(){
        recv("readmod", (newBuf)=>{
            //@ts-ignore
            this.readModification = newBuf.payload != null ?  new Uint8Array(newBuf.payload.match(/[\da-f]{2}/gi).map(function (h) {
                return parseInt(h, 16)
              })).buffer : null
            this.listenForReadMod();
        });
        
    }

    private listenForWriteMod(){
        recv("writemod", (newBuf)=>{
            //@ts-ignore
            this.writeModification = newBuf.payload != null ? new Uint8Array(newBuf.payload.match(/[\da-f]{2}/gi).map(function (h) {
                return parseInt(h, 16)
              })).buffer : null;
            this.listenForWriteMod()
        });

    }

    get readmod(): ArrayBuffer | null {
        return this.readModification;
    }

    get writemod(): ArrayBuffer | null {
        return this.writeModification;
    }

    set readmod(val: ArrayBuffer | null) {
        this.readModification = val;
    }

    set writemod(val: ArrayBuffer | null){
        this.writeModification = val;
    }


}

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
    static modReceiver: ModifyReceiver;
   

    static keylog_callback = new NativeCallback(function (ctxPtr, linePtr: NativePointer) {
        devlog("invoking keylog_callback from OpenSSL_BoringSSL");
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = linePtr.readCString()
        send(message)
    }, "void", ["pointer", "pointer"])

   


    constructor(public moduleName:String, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<String> }){
        OpenSSL_BoringSSL.modReceiver = new ModifyReceiver();

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
        function ab2str(buf: ArrayBuffer) {
            //@ts-ignore
            return String.fromCharCode.apply(null, new Uint16Array(buf));
        }
        function str2ab(str: string ) {
            var buf = new ArrayBuffer(str.length + 1); // 2 bytes for each char
            var bufView = new Uint8Array(buf);
            for (var i=0, strLen=str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
            }
            bufView[str.length] = 0;
            return buf;
        }

        var lib_addesses = this.addresses;

        Interceptor.attach(this.addresses["SSL_read"],
        {
            
            onEnter: function (args: any) 
            {
                this.bufLen = args[2].toInt32()
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

                
                if(OpenSSL_BoringSSL.modReceiver.readmod !== null){
                    //NULL out buffer
                    //@ts-ignore
                    Memory.writeByteArray(this.buf, new Uint8Array(this.bufLen));

                    //@ts-ignore
                    Memory.writeByteArray(this.buf, OpenSSL_BoringSSL.modReceiver.readmod);
                    retval = OpenSSL_BoringSSL.modReceiver.readmod.byteLength;                
                }

                this.message["contentType"] = "datalog"
                
                
                
                send(this.message, this.buf.readByteArray(retval))
                
            }
        })

    }

    

    install_plaintext_write_hook(){
        function str2ab(str: string ) {
            var buf = new ArrayBuffer(str.length + 1); // 2 bytes for each char
            var bufView = new Uint8Array(buf);
            for (var i=0, strLen=str.length; i < strLen; i++) {
            bufView[i] = str.charCodeAt(i);
            }
            bufView[str.length] = 0;
            return buf;
        }
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
                

                if(OpenSSL_BoringSSL.modReceiver.writemod !== null){
                    const newPointer = Memory.alloc(OpenSSL_BoringSSL.modReceiver.writemod.byteLength)
                    //@ts-ignore
                    Memory.writeByteArray(newPointer, OpenSSL_BoringSSL.modReceiver.writemod);                    
                    args[1] = newPointer;
                    args[2] = new NativePointer(OpenSSL_BoringSSL.modReceiver.writemod.byteLength); 
                }

                send(message, args[1].readByteArray(args[2].toInt32()))
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