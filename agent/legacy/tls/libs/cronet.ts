import { get_hex_string_from_byte_array, readAddresses, isSymbolAvailable, getPortsAndAddresses } from "../../../shared/shared_functions.js";
import { checkNumberOfExports } from "../../shared/shared_functions_legacy.js";
import { sendKeylog, sendDatalog } from "../../../shared/shared_structures.js";
import { devlog, devlog_debug, devlog_error } from "../../../util/log.js";
import { safeKeyLenLogged } from "../../../shared/keylog_length.js";
import { LruMap } from "../../../shared/lru.js";
import {
    CLIENT_RANDOM_CACHE_MAX,
    tryReadClientRandomAt,
} from "../../../shared/ssl_struct_walk.js";
import { keylog_enabled, pcap_enabled, enable_default_fd } from "../../../fritap_agent.js";




export class Cronet {
    

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    is_base_hook: boolean;
    SSL_CTX_set_keylog_callback : any;
    keylog_callback: any;
    can_we_install_keylog_callback: boolean = false;
    SSL_get_fd: any;
    SSL_get_session: any;
    SSL_SESSION_get_id: any;
    do_read_write_hooks: boolean = false;
    private clientRandomCache: LruMap<string, string> = new LruMap(CLIENT_RANDOM_CACHE_MAX);


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            if(checkNumberOfExports(moduleName) > 2 ){
                if (isSymbolAvailable(moduleName, "SSL_CTX_new") && isSymbolAvailable(moduleName, "SSL_CTX_set_keylog_callback")) {
                            this.library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_new", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id"];
                            this.can_we_install_keylog_callback = true;
                }
            }
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }

        this.keylog_callback = new NativeCallback(function (ctxPtr: NativePointer, linePtr: NativePointer) {
            devlog("invoking keylog_callback from Cronet ("+ moduleName +")");
            sendKeylog(linePtr.readCString().toUpperCase());
        }, "void", ["pointer", "pointer"])

        try{
            this.addresses = readAddresses(moduleName,this.library_method_mapping);
        }catch(e){
            this.can_we_install_keylog_callback = false;
        }

        // Bind the read/write surface independently of keylog. Only enable the
        // plaintext hooks when every required symbol resolved non-null, so the
        // keylog path keeps working even when read/write resolution fails.
        try{
            const moduleAddresses = this.addresses ? this.addresses[this.moduleName] : undefined;
            if (moduleAddresses
                && moduleAddresses["SSL_read"]
                && moduleAddresses["SSL_write"]
                && moduleAddresses["SSL_get_fd"]
                && moduleAddresses["SSL_get_session"]
                && moduleAddresses["SSL_SESSION_get_id"]) {
                this.SSL_get_fd = new NativeFunction(moduleAddresses["SSL_get_fd"], "int", ["pointer"]);
                this.SSL_get_session = new NativeFunction(moduleAddresses["SSL_get_session"], "pointer", ["pointer"]);
                this.SSL_SESSION_get_id = new NativeFunction(moduleAddresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
                this.do_read_write_hooks = true;
            }else{
                this.do_read_write_hooks = false;
            }
        }catch(e){
            this.do_read_write_hooks = false;
            devlog_error("Error while loading plaintext read/write hooks for Cronet: "+ e);
        }

    }

    are_callbacks_symbols_available(): boolean{
        return this.can_we_install_keylog_callback;
    }

    get_client_random(s3_ptr: NativePointer, SSL3_RANDOM_SIZE: number): string {
        if (!s3_ptr.isNull()) {
            const client_random_ptr: NativePointer = s3_ptr.add(0x30); // Offset in s3 struct

            const client_random = client_random_ptr.readByteArray(SSL3_RANDOM_SIZE);
            
            // Convert the byte array to a hex string
            const hexClientRandom = get_hex_string_from_byte_array(new Uint8Array(client_random as ArrayBuffer));
    
            return hexClientRandom;
        } else {
            devlog("[Error] s3 pointer is NULL");
            return "";
        }
    }
    
    get_client_random_from_ssl_struct(ssl_st_ptr: NativePointer): string {
        if (ssl_st_ptr.isNull()) return "";

        const cacheKey = ssl_st_ptr.toString();
        const cached = this.clientRandomCache.get(cacheKey);
        if (cached !== undefined) return cached;

        let primary: number;
        switch (Process.arch) {
            case 'x64':
            case 'arm64':
                primary = 0x30;
                break;
            case 'ia32':
            case 'arm':
                primary = 0x2C;
                break;
            default:
                devlog("[Error] Unsupported architecture");
                return "";
        }

        // Probe order: arch-primary first (preserves prior behaviour for
        // stock BoringSSL), then the opposite-width primary, then two nearby
        // slots observed in BoringSSL forks such as Cloudflare WARP's
        // libwarp_mobile.so.
        const alt = primary === 0x30 ? 0x2C : 0x30;
        const candidates = [primary, alt, 0x28, 0x38];

        for (const off of candidates) {
            const cr = tryReadClientRandomAt(ssl_st_ptr, off);
            if (cr) {
                if (off !== primary) {
                    devlog_debug(
                        `[Cronet legacy] client_random recovered via fallback s3 offset 0x${off.toString(16)}`
                    );
                }
                this.clientRandomCache.set(cacheKey, cr);
                return cr;
            }
        }

        // Negative-cache the failure so repeated keylog calls on the same
        // SSL* (5x per TLS 1.3 session) don't re-probe four offsets and re-log.
        devlog_debug("[Cronet legacy] client_random not recoverable via struct walk");
        this.clientRandomCache.set(cacheKey, "");
        return "";
    }

    keyLenheuristic(label: string, keyPtr: NativePointer): number {
        // heuristic to determine the key length based on the cipher suite
        // this is not 100% accurate but should work in most cases
        // returns the key length in bytes
        // common key lengths are 16, 24, 32, 48
        // for TLS 1.3 its usually 32 or 48
        const MAX_KEY_LENGTH = 64;
        let KEY_LENGTH = 0;
        let calculatedKeyLength = 0;

        if (label === "CLIENT_RANDOM") {
            return 48; // TLS 1.2 master secret
        }

        // Iterate through the memory to determine key length
        while (calculatedKeyLength < MAX_KEY_LENGTH) {

            const byte = keyPtr.add(calculatedKeyLength).readU8(); // Read one byte at a time

            if (byte === 0) { // Stop if null terminator is found (optional, adjust as needed)
                if(calculatedKeyLength < 20){
                    calculatedKeyLength++;
                    continue;
                }
                break;
            }
            calculatedKeyLength++;
        }

        if (calculatedKeyLength > 24 && calculatedKeyLength <= 42) {
            KEY_LENGTH = 32; // Closest match is 32 bytes
        } else if (calculatedKeyLength >= 46 && calculatedKeyLength <=49) {
            KEY_LENGTH = 48; // Closest match is 48 bytes
        }else{
            KEY_LENGTH = 32; // fall back size
        }

    // TBD: implement a better heuristic based on the cipher suite
    return KEY_LENGTH;
    }


    dumpKeys(labelPtr: NativePointer, sslStructPtr: NativePointer, keyPtr: NativePointer, keyLen?: number,): void {
        let labelStr = '';
        let client_random = '';
        let secret_key = '';

        // Read the label (the label pointer might contain a C string)
        if (!labelPtr.isNull()) {
            labelStr = labelPtr.readCString() ?? '';  // Read label as a C string
            //devlog(`Label: ${labelStr}`);
        } else {
            devlog("[Error] Argument 'labelPtr' is NULL");
        }

        // Extract client_random from the SSL structure
        if (!sslStructPtr.isNull()) {
            client_random = this.get_client_random_from_ssl_struct(sslStructPtr)
        }else {
            devlog("[Error] Argument 'sslStructPtr' is NULL");
        }

        if (!keyPtr.isNull()) {
            const { len: KEY_LENGTH } = safeKeyLenLogged(
                keyLen,
                labelStr,
                keyPtr,
                (label, ptr) => this.keyLenheuristic(label, ptr),
            );

            const keyData = keyPtr.readByteArray(KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)

            // Convert the byte array to a string of  hex values
            const hexKey = get_hex_string_from_byte_array(keyData);

            secret_key = hexKey;
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }

        //devlog("invoking ssl_log_secret() from BoringSSL statically linked into Cronet");
        sendKeylog(labelStr+" "+client_random+" "+secret_key);
    }

    getSslSessionId(ssl: NativePointer) {

        var session = this.SSL_get_session(ssl) as NativePointer
        if (session.isNull()) {
            if(enable_default_fd){
                devlog("using dummy SessionID: 59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336")
                return "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336"
            }
            devlog("Session is null")
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

    install_plaintext_read_hook(){
        if (!pcap_enabled) return;
        if (!this.do_read_write_hooks) return;

        var lib_addesses = this.addresses;
        var instance = this;
        var current_module_name = this.module_name;
        let cronetReadCount = 0;

        Interceptor.attach(this.addresses[this.moduleName]["SSL_read"],
        {
            onEnter: function (args: any) {
                if (cronetReadCount < 5) {
                    cronetReadCount++;
                    devlog_debug(`[Cronet legacy SSL_read] call #${cronetReadCount} in ${current_module_name}`);
                }
                this.fd = instance.SSL_get_fd(args[0])
                if(this.fd < 0 && enable_default_fd == false) {
                    return
                }

                var message = getPortsAndAddresses(this.fd as number, true, lib_addesses[current_module_name], enable_default_fd)
                if (message === null) { return; }
                message["ssl_session_id"] = instance.getSslSessionId(args[0])
                message["function"] = "SSL_read"
                this.message = message
                this.buf = args[1]
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0 || (this.fd < 0 && !enable_default_fd)) {
                    return
                }
                if (this.message) {
                    sendDatalog(this.message, this.buf.readByteArray(retval))
                }
            }
        })
    }

    install_plaintext_write_hook(){
        if (!pcap_enabled) return;
        if (!this.do_read_write_hooks) return;

        var lib_addesses = this.addresses;
        var instance = this;
        var current_module_name = this.module_name;

        Interceptor.attach(this.addresses[this.moduleName]["SSL_write"],
        {
            onEnter: function (args: any) {
                this.fd = instance.SSL_get_fd(args[0])
                if(this.fd < 0 && enable_default_fd == false) {
                    return
                }
                var message = getPortsAndAddresses(this.fd as number, false, lib_addesses[current_module_name], enable_default_fd)
                if (message === null) { return; }
                message["ssl_session_id"] = instance.getSslSessionId(args[0])
                message["function"] = "SSL_write"
                sendDatalog(message, args[1].readByteArray(args[2].toInt32()))
            },
            onLeave: function (retval: any) {
            }
        })
    }

    install_key_extraction_pattern_hook(){
        if (!keylog_enabled) return;
        // needs to be setup for the specific plattform
    }
}