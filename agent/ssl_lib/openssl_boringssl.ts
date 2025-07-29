import { readAddresses, getPortsAndAddresses, getBaseAddress, isSymbolAvailable, checkNumberOfExports, calculateZeroBytePercentage } from "../shared/shared_functions.js";
import { getOffsets, offsets, enable_default_fd } from "../ssl_log.js";
import { devlog, devlog_error, log } from "../util/log.js";
import { ObjC } from "../shared/objclib.js";

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
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    SSL_SESSION_get_id: any;
    SSL_CTX_set_keylog_callback : any;
    SSL_get_fd: any;
    SSL_get_session: any;
    static modReceiver: ModifyReceiver;
   

    static keylog_callback = new NativeCallback(function (ctxPtr: NativePointer, linePtr: NativePointer) {
        devlog("invoking keylog_callback from OpenSSL_BoringSSL");
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = linePtr.readCString().toUpperCase()
        send(message)
    }, "void", ["pointer", "pointer"])

    is_base_hook: boolean;
    is_openssl: boolean;

   


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        OpenSSL_BoringSSL.modReceiver = new ModifyReceiver();

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            if(checkNumberOfExports(moduleName) > 2 ){
                this.library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"]
            }
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        if (isSymbolAvailable(moduleName, "SSL_CTX_new")) {
            this.library_method_mapping[`*${moduleName}*`].push("SSL_CTX_new");
        }

    
        // Check and add SSL_read_ex if available
        if (isSymbolAvailable(moduleName, "SSL_read_ex")) {
            this.library_method_mapping[`*${moduleName}*`].push("SSL_read_ex");
            this.is_openssl = true;
        }else{
            this.is_openssl = false;
        }

        // Check and add SSL_write_ex if available
        if (isSymbolAvailable(moduleName, "SSL_write_ex")) {
            this.library_method_mapping[`*${moduleName}*`].push("SSL_write_ex");
        }



        this.is_base_hook = is_base_hook;
        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.openssl != null){
            
            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[this.moduleName][`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null)
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            

            
            for (const method of Object.keys(offsets.openssl)){
                //@ts-ignore
                this.addresses[this.moduleName][`${method}`] = offsets.openssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.openssl[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.openssl[`${method}`].address));
            }

            

        }

        if(!ObjC.available && checkNumberOfExports(moduleName) > 2){
            this.SSL_SESSION_get_id = new NativeFunction(this.addresses[this.moduleName]["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
            this.SSL_get_fd = ObjC.available ? new NativeFunction(this.addresses[this.moduleName]["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(this.addresses[this.moduleName]["SSL_get_fd"], "int", ["pointer"]);
            this.SSL_get_session = new NativeFunction(this.addresses[this.moduleName]["SSL_get_session"], "pointer", ["pointer"]);
        }
        
    }


    install_plaintext_read_hook(){
        if(!ObjC.available){
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
            var instance = this;
            var current_module_name = this.module_name;
    
            Interceptor.attach(this.addresses[this.moduleName]["SSL_read"],
            {
                
                onEnter: function (args: any) 
                {
                    this.bufLen = args[2].toInt32()
                    this.fd = instance.SSL_get_fd(args[0])
                    if(this.fd < 0 && enable_default_fd == false) {
                        return
                    }
    
    
    
                
                    var message = getPortsAndAddresses(this.fd as number, true, lib_addesses[current_module_name], enable_default_fd)
                    message["ssl_session_id"] = instance.getSslSessionId(args[0])
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
                        this.buf.writeByteArray(new Uint8Array(this.bufLen));
    
                        this.buf.writeByteArray(OpenSSL_BoringSSL.modReceiver.readmod);
                        retval = OpenSSL_BoringSSL.modReceiver.readmod.byteLength;                
                    }
    
                    this.message["contentType"] = "datalog"
                    
                    
                    
                    send(this.message, this.buf.readByteArray(retval))
                    
                }
            })
        }
        

    }

    

    install_plaintext_write_hook(){
        if(!ObjC.available){
            function str2ab(str: string ) {
                var buf = new ArrayBuffer(str.length + 1); // 2 bytes for each char
                var bufView = new Uint8Array(buf);
                for (var i=0, strLen=str.length; i < strLen; i++) {
                bufView[i] = str.charCodeAt(i);
                }
                bufView[str.length] = 0;
                return buf;
            }
    
            var current_module_name = this.module_name;
            var lib_addesses = this.addresses;
            var instance = this;
            Interceptor.attach(this.addresses[this.moduleName]["SSL_write"],
            {
                onEnter: function (args: any) {
                    if (!ObjC.available){
                        try {
                           
                            this.fd = instance.SSL_get_fd(args[0]);
                            
                        
                    }catch (error) {
                        if (!this.is_base_hook) {
                            const fallback_addresses = (globalThis as any).init_addresses;
    
                            //console.log("Current ModuleName: "+current_module_name);
                            let keys = Object.keys(fallback_addresses);
                            let firstKey = keys[0];
                            instance.SSL_SESSION_get_id = new NativeFunction(fallback_addresses[firstKey]["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
                            instance.SSL_get_fd = ObjC.available ? new NativeFunction(fallback_addresses[firstKey]["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(fallback_addresses["SSL_get_fd"], "int", ["pointer"]);
                            instance.SSL_get_session = new NativeFunction(fallback_addresses[firstKey]["SSL_get_session"], "pointer", ["pointer"]);
                        }else{
                            if (error instanceof Error) {
                                console.log("Error: " + error.message);
                                console.log("Stack: " + error.stack);
                            } else {
                                console.log("Unexpected error:", error);
                            }
                        }
                            
                        }
                    if(this.fd < 0 && enable_default_fd == false) {
                        return
                    }
                    var message = getPortsAndAddresses(this.fd as number, false, lib_addesses[current_module_name], enable_default_fd)
                    message["ssl_session_id"] = instance.getSslSessionId(args[0])
                    message["function"] = "SSL_write"
                    message["contentType"] = "datalog"
                    
    
                    if(OpenSSL_BoringSSL.modReceiver.writemod !== null){
                        const newPointer = Memory.alloc(OpenSSL_BoringSSL.modReceiver.writemod.byteLength)
                        newPointer.writeByteArray(OpenSSL_BoringSSL.modReceiver.writemod);                    
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
        
    }

    install_tls_keys_callback_hook(){
        log("Error: TLS key extraction not implemented yet.");
    }

    /*
     * These hooks differ between OpenSSL and BoringSSL.
     */ 

    install_openssl_key_extraction_hook(){
        log("Error: TLS key extraction not implemented yet.");
    }


    dump_keys_openssl(label, identifier, key, length) {
        const KEY_LENGTH_FINAL = length.toInt32();
        //console.log("KEy length: "+KEY_LENGTH_FINAL);
        //const MAX_KEY_LENGTH = 64;
        const RANDOM_KEY_LENGTH = 32; 
        var labelStr = "";
        var client_random_str = "";
        var secret_key = "";


        if (!label.isNull()) {
            labelStr = label.readCString(); // Read the C string
        } else {
            devlog_error("[Error] Argument 'label' is NULL");
        }

        if (!identifier.isNull()) {
            //devlog("SSL_Struct_pointer (working): ",identifier);
            try{
                let client_random = identifier.add(0x160).readByteArray(RANDOM_KEY_LENGTH);
                let hex_client_random = Array
                .from(new Uint8Array(client_random)) // Convert byte array to Uint8Array and then to Array
                .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
                .join(''); // Join all the hex values with a space

                client_random_str = hex_client_random
                if(calculateZeroBytePercentage(client_random_str) > 50){
                    devlog_error("[OpenSSL Dump Keys Error] Client random contains too many zero bytes, this is likely not the correct pointer to the client random value.");
                    client_random = identifier.add(0x140).readByteArray(RANDOM_KEY_LENGTH);
                    hex_client_random = Array
                    .from(new Uint8Array(client_random)) // Convert byte array to Uint8Array and then to Array
                    .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
                    .join(''); // Join all the hex values with a space

                    client_random_str = hex_client_random
                }
            }catch (error) {
                client_random_str = "Error_reading_client_random";
            }
            ;
        } else {
            devlog_error("[OpenSSL Dump Keys Error] Argument 'identifier' is NULL");
        }


        // Read the binary key from key (second parameter) and print it in a clean hex format
        //console.log("Key:");
        if (!key.isNull()) {
            
            // old brute force method to determine the key length will be removed in the future
            /*
            let KEY_LENGTH = 0;
            let calculatedKeyLength = 0;

            // Iterate through the memory to determine key length
            while (calculatedKeyLength < MAX_KEY_LENGTH) {
                const byte = key.add(calculatedKeyLength).readU8(); // Read one byte at a time


                if (byte === 0) { // Stop if null terminator is found (optional, adjust as needed)
                    if(calculatedKeyLength < 20){
                        calculatedKeyLength++;
                        continue;
                    }
                    break;
                }
                calculatedKeyLength++;
            }


            if (calculatedKeyLength > 24 && calculatedKeyLength <= 46) {
                KEY_LENGTH = 32; // Closest match is 32 bytes
            } else if (calculatedKeyLength => 47) {
                KEY_LENGTH = 48; // Closest match is 48 bytes
            }else{
                KEY_LENGTH = 32; // fall back size
            }*/

            const keyData = key.readByteArray(KEY_LENGTH_FINAL); // Read the key data (KEY_LENGTH bytes)
            
            // Convert the byte array to a string of space-separated hex values
            const hexKey = Array
                .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
                .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
                .join(''); // Join all the hex values with a space

            secret_key = hexKey;
        } else {
            devlog_error("[OpenSSL Dump Keys Error] Argument 'key' is NULL");
        }

        //devlog("OpenSSL log: "+labelStr+" "+client_random_str+" "+secret_key);
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = labelStr+" "+client_random_str+" "+secret_key;
        send(message);
    }

    install_boringssl_key_extraction_hook(){
        log("Error: TLS key extraction not implemented yet.")
    }


    install_extended_hooks(){
        // these functions (and its symbols) only available on OpenSSL
        if (this.is_openssl){

        
            var current_module_name = this.module_name;
            var lib_addesses = this.addresses;
            var instance = this;

            Interceptor.attach(this.addresses[this.moduleName]["SSL_read_ex"],
            {
                
                onEnter: function (args: any) 
                {
                    this.bufLen = args[2].toInt32()
                    this.fd = instance.SSL_get_fd(args[0])
                    if(this.fd < 0 && enable_default_fd == false) {
                        return
                    }

                    var message = getPortsAndAddresses(this.fd as number, true, lib_addesses[current_module_name], enable_default_fd)
                    message["ssl_session_id"] = instance.getSslSessionId(args[0])
                    message["function"] = "SSL_read_ex"
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
            });

            Interceptor.attach(this.addresses[this.moduleName]["SSL_write_ex"],
            {
                onEnter: function (args: any) {
                    if (!ObjC.available){
                        try {
                        
                            this.fd = instance.SSL_get_fd(args[0]);
                            
                        
                    }catch (error) {
                        if (!this.is_base_hook) {
                            const fallback_addresses = (globalThis as any).init_addresses;

                            let keys = Object.keys(fallback_addresses);
                            let firstKey = keys[0];
                            instance.SSL_SESSION_get_id = new NativeFunction(fallback_addresses[firstKey]["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
                            instance.SSL_get_fd = ObjC.available ? new NativeFunction(fallback_addresses[firstKey]["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(fallback_addresses["SSL_get_fd"], "int", ["pointer"]);
                            instance.SSL_get_session = new NativeFunction(fallback_addresses[firstKey]["SSL_get_session"], "pointer", ["pointer"]);
                        }else{
                            if (error instanceof Error) {
                                console.log("Error: " + error.message);
                                console.log("Stack: " + error.stack);
                            } else {
                                console.log("Unexpected error:", error);
                            }
                        }
                            
                        }
                    if(this.fd < 0 && enable_default_fd == false) {
                        return
                    }
                    var message = getPortsAndAddresses(this.fd as number, false, lib_addesses[current_module_name], enable_default_fd)
                    message["ssl_session_id"] = instance.getSslSessionId(args[0])
                    message["function"] = "SSL_write_ex"
                    message["contentType"] = "datalog"

                    send(message, args[1].readByteArray(args[2].toInt32()))
                    } // this is a temporary workaround for the fd problem on iOS
                },
                onLeave: function (retval: any) {
                }
            });
        }
    }


     /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
      getSslSessionId(ssl: NativePointer) {
          
        var session = this.SSL_get_session(ssl) as NativePointer
        if (session.isNull()) {
            if(enable_default_fd){
                log("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336")
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336"
            }
            log("Session is null")
            return 0
        }
        var len_pointer = Memory.alloc(4)
        var p = this.SSL_SESSION_get_id(session, len_pointer) as NativePointer
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