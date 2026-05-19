import { get_hex_string_from_byte_array, readAddresses, checkNumberOfExports, isSymbolAvailable } from "../../shared/shared_functions.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { devlog, log } from "../../util/log.js";
import { safeKeyLenLogged } from "../../shared/keylog_length.js";
import { pcap_enabled, patterns as patternsJson, isPatternReplaced } from "../../fritap_agent.js";
import { hasModulePatterns } from "../shared/cronet_patterns.js";




export class Cronet {
    

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    is_base_hook: boolean;
    SSL_CTX_set_keylog_callback : any;
    keylog_callback: any;
    can_we_install_keylog_callback: boolean = false;


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            if(checkNumberOfExports(moduleName) > 2 ){
                if (isSymbolAvailable(moduleName, "SSL_CTX_new") && isSymbolAvailable(moduleName, "SSL_CTX_set_keylog_callback")) {               
                            this.library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_new", "SSL_new", "SSL_CTX_set_keylog_callback"];
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
        const SSL3_RANDOM_SIZE = 32;
        let offset_s3: number;
    
        switch (Process.arch) {
            case 'x64':
                offset_s3 = 0x30;
                break;
            case 'arm64':
                offset_s3 = 0x30;
                break;
            case 'ia32':
                offset_s3 = 0x2C;
                break;
            case 'arm':
                offset_s3 = 0x2C;
                break;
            default:
                devlog("[Error] Unsupported architecture");
                return "";
        }
    
        const s3_ptr = ssl_st_ptr.add(offset_s3).readPointer();
        return this.get_client_random(s3_ptr, SSL3_RANDOM_SIZE);
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
        devlog("invoking shadow keylog_callback from Cronet (" + this.module_name + ")");
        sendKeylog(labelStr+" "+client_random+" "+secret_key);
    }

    // Cronet plaintext hooks ride on byte patterns (SSL_Read / SSL_Write
    // entries in pattern.json) because Cronet statically links BoringSSL and
    // strips the SSL_read / SSL_write exports symbol-based capture would need.
    // Pattern scanning is expensive, so callers only attempt this when the
    // user actually requested a plaintext PCAP (pcap_enabled flag plumbed from
    // --pcap). When patterns are not provided, emit a single per-(module,action)
    // notice so the user knows why plaintext is missing.
    private static plaintextNoticeShown = new Set<string>();

    private noticePlaintextMissing(action: "SSL_Read" | "SSL_Write"): void {
        const key = `${this.module_name}:${action}`;
        if (Cronet.plaintextNoticeShown.has(key)) return;
        Cronet.plaintextNoticeShown.add(key);
        log(`[!] ${this.module_name}: plaintext PCAP requested but no ${action} byte-pattern provided for this module; plaintext capture will be unavailable for it.`);
    }

    install_plaintext_read_hook(){
        if (!pcap_enabled) return;
        if (!isPatternReplaced() || !hasModulePatterns(patternsJson, this.module_name, "libcronet.so", "SSL_Read")) {
            this.noticePlaintextMissing("SSL_Read");
            return;
        }
        // TODO: Cronet plaintext data plumbing — pattern is present but the
        // sendDatalog callback (SSL_get_fd / port-address extraction without
        // exported symbols) is not yet implemented for Cronet. Surface that to
        // the user explicitly so they're not surprised by an empty PCAP.
        log(`[!] ${this.module_name}: SSL_Read pattern detected but Cronet plaintext capture pipeline is not yet implemented; only keylog will be emitted for this module.`);
    }

    install_plaintext_write_hook(){
        if (!pcap_enabled) return;
        if (!isPatternReplaced() || !hasModulePatterns(patternsJson, this.module_name, "libcronet.so", "SSL_Write")) {
            this.noticePlaintextMissing("SSL_Write");
            return;
        }
        log(`[!] ${this.module_name}: SSL_Write pattern detected but Cronet plaintext capture pipeline is not yet implemented; only keylog will be emitted for this module.`);
    }

    install_key_extraction_pattern_hook(){
        // needs to be setup for the specific plattform
    }
}