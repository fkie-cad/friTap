import { readAddresses, getPortsAndAddresses, toHexString, getBaseAddress } from "../shared/shared_functions.js";
import { log } from "../util/log.js";
import { offsets, enable_default_fd } from "../ssl_log.js";
import { isSymbolAvailable } from "../shared/shared_functions.js";
import { devlog } from "../util/log.js";

export class WolfSSL {

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    static wolfSSL_get_server_random: any;
    static wolfSSL_get_client_random : any;
    static wolfSSL_get_fd: any;
    static wolfSSL_get_session: any;
    static wolfSSL_SESSION_get_master_key: any;
   

    constructor(public moduleName:string, public socket_library:String,public passed_library_method_mapping?: { [key: string]: Array<string> }){
        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            this.library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays", "wolfSSL_get_client_random", "wolfSSL_get_server_random"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

            // wolfSSL_SESSION_get_master_key is not available in some of the newer versions
            if (isSymbolAvailable(moduleName, "wolfSSL_SESSION_get_master_key")) {
                this.library_method_mapping[`*${moduleName}*`].push("wolfSSL_SESSION_get_master_key");
            }
        }
        
        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.wolfssl != null){

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

            
            for (const method of Object.keys(offsets.wolfssl)){
                //@ts-ignore
                this.addresses[this.moduleName][`${method}`] = offsets.wolfssl[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.wolfssl[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.wolfssl[`${method}`].address));
            }


        }

        

        WolfSSL.wolfSSL_get_fd = new NativeFunction(this.addresses[this.moduleName]["wolfSSL_get_fd"], "int", ["pointer"])
        WolfSSL.wolfSSL_get_session = new NativeFunction(this.addresses[this.moduleName]["wolfSSL_get_session"], "pointer", ["pointer"])
       

    }


    // https://github.com/wolfSSL/wolfssl/blob/6d299ea943d14ddeac37bed20ae84807e82b1c19/wolfssl/internal.h#L5809
    // Default config: haproxy = false, nginx = false
    static get_arrays_offset(haproxy: boolean, nginx: boolean, module_name: string) {
        // Depending on the available symbols we can determine the used build config in order to calculate the offset of the arrays struct
        let extra: boolean = isSymbolAvailable(module_name, "wolfSSL_OPENSSL_init_ssl") // default config: true
        let all: boolean = isSymbolAvailable(module_name, "wolfSSL_CTX_set_cert_verify_callback") // default config: false

        let offset = Process.pointerSize; // ctx: NativePointer, 
        if (haproxy) offset += Process.pointerSize; // inital_ctx: NatviePointer
        offset += Process.pointerSize * 2 // suites: NativePointer, clSuites: NativePointer
        // suitesStack: NativePointer, clSuitesStack
        if (haproxy || extra || all || nginx) offset += Process.pointerSize * 2;
        return offset;
    }

    // parse the structure containing the used secrets
    // https://github.com/wolfSSL/wolfssl/blob/6d299ea943d14ddeac37bed20ae84807e82b1c19/wolfssl/internal.h#L5175
    static parse_arrays(arrays: NativePointer, client_random: string, server_random: string) {
        let have_session_ticket: boolean;
        let offset = Process.pointerSize * 2;
        offset += 3 * 4; // 3 unsigned ints

        // read the memory and check if its the client_random
        try {
            let possible_cr_str = arrays.add(offset).readByteArray(32);
            let possible_cr_hex = Array.from(new Uint8Array(possible_cr_str)).map(b => b.toString(16).padStart(2, '0')).join('');
            devlog("Comparing client_randoms: " + possible_cr_hex + " and " + client_random);
            if (possible_cr_hex === client_random) {
                have_session_ticket = false;
            } else {
                have_session_ticket = true;
            }
        } catch(e) {
            have_session_ticket = true;
        }

        if (have_session_ticket) {
            // Add the offsets
        }

        // read the memory and check if its the server_random
        try {
            let possible_sr_str = arrays.add(offset).readByteArray(32);
            let possible_sr_hex = Array.from(new Uint8Array(possible_sr_str)).map(b => b.toString(16).padStart(2, '0')).join('');
            devlog("Comparing server_randoms: " + possible_sr_hex + " and " +server_random);
            if (possible_sr_hex === server_random) {
                
            }
        }
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
        var session = WolfSSL.wolfSSL_get_session(ssl) as NativePointer
        if (session.isNull()) {
            if(enable_default_fd){
                log("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338")
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76338"
            }
            log("Session is null")
            return 0
        }
        var p = session.add(8)
        var len = 32 // This comes from internals.h. It is untested!
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
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses[this.moduleName]["wolfSSL_read"],
        {
            onEnter: function (args: any) {
                
                var message = getPortsAndAddresses(WolfSSL.wolfSSL_get_fd(args[0]) as number, true, lib_addesses[current_module_name], enable_default_fd)
                
                message["function"] = "wolfSSL_read"
                message["ssl_session_id"] = WolfSSL.getSslSessionId(args[0])
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
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;
        Interceptor.attach(this.addresses[this.moduleName]["wolfSSL_write"],
        {
            onEnter: function (args: any) {
                var message = getPortsAndAddresses(WolfSSL.wolfSSL_get_fd(args[0]) as number, false, lib_addesses[current_module_name], enable_default_fd)
                message["ssl_session_id"] = WolfSSL.getSslSessionId(args[0])
                message["function"] = "wolfSSL_write"
                message["contentType"] = "datalog"
                send(message, args[1].readByteArray(parseInt(args[2])))
            },
            onLeave: function (retval: any) {
            }
        })
    }



    static parse_WOLFSSL_struct(ssl: NativePointer) {

    }
    

}