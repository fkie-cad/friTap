import { readAddresses, resolveOffsets, isSymbolAvailable, checkNumberOfExports, calculateZeroBytePercentage } from "../../shared/shared_functions.js";
import { enable_default_fd, pcap_enabled } from "../../fritap_agent.js";
import { devlog, devlog_error, log, devlog_info } from "../../util/log.js";
import { initializePipeline as sharedInitializePipeline, resolveWithPipelineAsync as sharedResolveWithPipelineAsync } from "../../shared/pipeline_utils.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { readKeylogLine, isNssKeylogLine } from "../shared/keylog_line.js";
import { addModuleMethod, hasResolvableSslSurface } from "../../legacy/tls/libs/ssl_method_mapping.js";
import { SslPlaintextHooks } from "../../shared/ssl_plaintext_hooks.js";

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

/**
 * True only for Apple's system BoringSSL (libboringssl.dylib), whose SSL objects
 * need BIO_get_fd semantics instead of the genuine SSL_get_fd of OpenSSL/LibreSSL.
 * Accepts a bare module name or a full path.
 */
export function usesBioGetFd(moduleName: string): boolean {
    return moduleName.split("/").pop() === "libboringssl.dylib";
}

export class OpenSSL_BoringSSL {

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    SSL_SESSION_get_id: any;
    SSL_CTX_set_keylog_callback : any;
    keylog_callback: any;
    SSL_get_fd: any;
    SSL_get_session: any;
    static modReceiver: ModifyReceiver;
    do_read_write_hooks: boolean = true; // we want to hook read and write by default

    is_base_hook: boolean;
    is_openssl: boolean;

   


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        if (!OpenSSL_BoringSSL.modReceiver) {
            OpenSSL_BoringSSL.modReceiver = new ModifyReceiver();
        }

        // A module exposes a usable SSL surface either via enough dynamic exports
        // (.dynsym) or, for deep-resolution opt-ins (e.g. libhttpengine.so), via
        // .symtab — where readAddresses' symbol-table fallback resolves SSL_*.
        // Computed once: the export count is invariant for this install, so this
        // also avoids a second checkNumberOfExports() (enumerateExports) pass below.
        const sslSurfaceResolvable = hasResolvableSslSurface(moduleName, checkNumberOfExports(moduleName));

        if(typeof passed_library_method_mapping !== 'undefined'){
            this.library_method_mapping = passed_library_method_mapping;
        }else{
            // Build the mapping when the SSL surface is resolvable. Deep modules
            // qualify even with few/no dynamic exports; this also avoids the
            // .push-on-undefined below when the mapping key would never be created.
            if(sslSurfaceResolvable){
                this.library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"]
            }
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        if (isSymbolAvailable(moduleName, "SSL_CTX_new")) {
            addModuleMethod(this.library_method_mapping, moduleName, "SSL_CTX_new");
        }

    
        // Check and add SSL_read_ex if available
        if (isSymbolAvailable(moduleName, "SSL_read_ex")) {
            addModuleMethod(this.library_method_mapping, moduleName, "SSL_read_ex");
            this.is_openssl = true;
        }else{
            this.is_openssl = false;
        }

        this.keylog_callback = new NativeCallback(function (ctxPtr: NativePointer, linePtr: NativePointer) {
            devlog("invoking keylog_callback from OpenSSL_BoringSSL ("+ moduleName +")");
            // Validate before dereferencing. On Apple platforms this callback is
            // installed by writing it into the SSL_CTX struct at a version-keyed
            // offset (see agent/legacy/tls/shared/apple_keylog_offset.ts). If that
            // offset is wrong the pointer can land on a DIFFERENT callback field —
            // e.g. info_callback, whose signature is (SSL*, int, int) — and then
            // `linePtr` holds a small integer rather than an address. Reading a
            // C string from it would SIGSEGV and take the whole target down, and a
            // JS try/catch cannot save a native fault. readKeylogLine() range-checks
            // first and returns null instead.
            const line = readKeylogLine(linePtr);
            if (line === null) return;
            if (!isNssKeylogLine(line)) {
                devlog_error("keylog_callback received a non-keylog payload from " + moduleName +
                    " — the installed callback is likely wired to the wrong SSL_CTX field; dropping it");
                return;
            }
            sendKeylog(line.toUpperCase());
        }, "void", ["pointer", "pointer"]);

        // Check and add SSL_write_ex if available
        if (isSymbolAvailable(moduleName, "SSL_write_ex")) {
            addModuleMethod(this.library_method_mapping, moduleName, "SSL_write_ex");
        }


        if(moduleName.includes("libconscrypt_jni")){
            this.is_openssl = false; // conscrypt is based on BoringSSL
            devlog("Conscrypt detected, assuming BoringSSL");
        }



        this.is_base_hook = is_base_hook;
        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        resolveOffsets(this.addresses, this.moduleName, socket_library, "openssl");

        if(moduleName.includes("libconscrypt_jni")){
            devlog("trying to load addtional functions for conscrypt");
        }



        // Plaintext hooks need the library's genuine SSL_get_fd. Apple's
        // libboringssl.dylib is the one library without it (BIO_get_fd semantics,
        // the "fd problem on iOS"), so it stays keys-only; genuine OpenSSL and
        // LibreSSL get the hooks on every platform, Apple included. Decided by
        // module identity — whether ObjC happens to be loaded says nothing about
        // which TLS library this is.
        if(!usesBioGetFd(moduleName) && sslSurfaceResolvable){
            this.bindSslFdAndSessionFunctions();
        }else{
            this.do_read_write_hooks = false; // we cannot hook read and write on Apple's libboringssl right now
        }

        if(moduleName.includes("libconscrypt_jni")){
            devlog("Conscrypt hooks initialized");
        }
        
    }

    /**
     * Fill in missing addresses using the hooking pipeline. Never overwrites
     * existing non-null addresses from readAddresses(). Awaits the non-blocking
     * pipeline so pattern resolution of ssl_log_secret on large stripped modules
     * cannot stall a gracefulDetach.
     */
    protected resolveWithPipelineAsync(requiredFunctions: string[]): Promise<void> {
        return sharedResolveWithPipelineAsync(this.addresses, this.module_name, "openssl", requiredFunctions);
    }

    /**
     * Initialize the singleton pipeline with available strategies.
     * Delegates to shared pipeline_utils — kept for backward compatibility
     * with existing platform agent call sites.
     * Idempotent — safe to call from every platform agent.
     *
     * @param patternData - Pattern data from fritap_agent.ts patterns global (or undefined)
     * @param experimentalMode - Whether --experimental flag is set
     */
    static initializePipeline(patternData?: any, experimentalMode?: boolean): void {
        sharedInitializePipeline(patternData, experimentalMode);
    }


    /**
     * Bind SSL_get_fd / SSL_get_session / SSL_SESSION_get_id and turn the
     * plaintext hooks on. Returns false — keys only — if a symbol is unresolved.
     */
    protected bindSslFdAndSessionFunctions(): boolean {
        try {
            this.SSL_SESSION_get_id = new NativeFunction(this.addresses[this.moduleName]["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
            this.SSL_get_fd = new NativeFunction(this.addresses[this.moduleName]["SSL_get_fd"], "int", ["pointer"]);
            this.SSL_get_session = new NativeFunction(this.addresses[this.moduleName]["SSL_get_session"], "pointer", ["pointer"]);
        } catch (e) {
            this.do_read_write_hooks = false;
            devlog_error("Error while loading additional hooks for OpenSSL/BoringSSL: "+ e);
            devlog_info("Only key extraction will be available for "+ this.moduleName);
            return false;
        }
        this.do_read_write_hooks = true;
        return true;
    }

    private _plaintextHooks?: SslPlaintextHooks;

    /** The plaintext SSL_read/SSL_write(_ex) hooks, with SSL-scoped fd attribution (shared/ssl_plaintext_hooks.ts). */
    protected get plaintextHooks(): SslPlaintextHooks {
        if (!this._plaintextHooks) {
            this._plaintextHooks = new SslPlaintextHooks(this, OpenSSL_BoringSSL.modReceiver, usesBioGetFd(this.module_name));
        }
        return this._plaintextHooks;
    }

    install_plaintext_read_hook(){
        if (!pcap_enabled || !this.do_read_write_hooks) return;
        this.plaintextHooks.installScopeHooks();
        this.plaintextHooks.attachRead(this.addresses[this.moduleName]["SSL_read"]);
    }

    install_plaintext_write_hook(){
        if (!pcap_enabled || !this.do_read_write_hooks) return;
        this.plaintextHooks.installScopeHooks();
        this.plaintextHooks.attachWrite(this.addresses[this.moduleName]["SSL_write"]);
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
                    devlog_error("[OpenSSL Dump Keys Error] Wrong offset for client_random, trying to read at offset 0x140 instead of 0x160");
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
        sendKeylog(labelStr+" "+client_random_str+" "+secret_key);
    }

    install_boringssl_key_extraction_hook(){
        log("Error: TLS key extraction not implemented yet.")
    }


    install_extended_hooks(){
        if (!pcap_enabled) return;
        // these functions (and its symbols) only available on OpenSSL
        if (!this.is_openssl) return;
        this.plaintextHooks.attachReadEx(this.addresses[this.moduleName]["SSL_read_ex"]);
        this.plaintextHooks.attachWriteEx(this.addresses[this.moduleName]["SSL_write_ex"]);
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



}