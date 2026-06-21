import { get_hex_string_from_byte_array, readAddresses, checkNumberOfExports, isSymbolAvailable, getPortsAndAddresses } from "../../shared/shared_functions.js";
import { sendKeylog, sendDatalog } from "../../shared/shared_structures.js";
import { devlog, devlog_debug, devlog_error, log } from "../../util/log.js";
import { safeKeyLenLogged } from "../../shared/keylog_length.js";
import { pcap_enabled, patterns as patternsJson, isPatternReplaced, enable_default_fd } from "../../fritap_agent.js";
import { hasUsablePatternsFor } from "../shared/cronet_patterns.js";
import { noteHandshakeLogged, observeHandshakeSecret } from "../../shared/tls13_secret_recovery.js";
import { openSslSessionIdDecoder } from "../definitions/openssl.js";
import { isWindows, isiOS, isMacOS } from "../../util/process_infos.js";




export class Cronet {
    

    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;
    is_base_hook: boolean;
    SSL_CTX_set_keylog_callback : any;
    keylog_callback: any;
    can_we_install_keylog_callback: boolean = false;
    // Symbol-resolved plaintext surface (BoringSSL exports). Set in the
    // constructor when the module exports the read/write/fd/session symbols.
    SSL_get_fd: any;
    SSL_get_session: any;
    SSL_SESSION_get_id: any;
    do_read_write_hooks: boolean = false;
    // Resolved {SSL_get_session, SSL_SESSION_get_id} passed to the shared
    // openSslSessionIdDecoder. Populated in the constructor when symbols resolve.
    private sessionFns: { [fn: string]: any } = {};
    // Pattern-resolved SSL_get_fd for stripped builds (see resolveSslGetFdPattern).
    private patternSslGetFd: any = null;
    // Platform-specific Schema-B family key used as the secondary lookup for a
    // user --patterns file (primary lookup is always this.module_name). linux/android
    // key under "libcronet.so"; ios/macos under "Cronet"; windows under "libcronet.dll".
    // Set once in the constructor.
    private cronetFallbackKey: string = "libcronet.so";


    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ){
        this.module_name = moduleName;
        this.is_base_hook = is_base_hook;

        if (isWindows()) this.cronetFallbackKey = "libcronet.dll";
        else if (isiOS() || isMacOS()) this.cronetFallbackKey = "Cronet";
        // else stays "libcronet.so" (linux/android)

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

        // Bind the symbol-resolved plaintext surface independently of keylog.
        // Only enable the symbol-based read/write hooks when every required
        // symbol resolved non-null (mirrors the legacy Cronet class). When these
        // symbols are absent (stripped Cronet) we fall through to the
        // pattern-based path + SSL_get_fd hook point in resolveSslGetFdPattern().
        try{
            const moduleAddresses = this.addresses ? this.addresses[this.module_name] : undefined;
            if (moduleAddresses
                && moduleAddresses["SSL_read"]
                && moduleAddresses["SSL_write"]
                && moduleAddresses["SSL_get_fd"]
                && moduleAddresses["SSL_get_session"]
                && moduleAddresses["SSL_SESSION_get_id"]) {
                this.SSL_get_fd = new NativeFunction(moduleAddresses["SSL_get_fd"], "int", ["pointer"]);
                this.SSL_get_session = new NativeFunction(moduleAddresses["SSL_get_session"], "pointer", ["pointer"]);
                this.SSL_SESSION_get_id = new NativeFunction(moduleAddresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
                this.sessionFns = { "SSL_get_session": this.SSL_get_session, "SSL_SESSION_get_id": this.SSL_SESSION_get_id };
                this.do_read_write_hooks = true;
            }else{
                this.do_read_write_hooks = false;
            }
        }catch(e){
            this.do_read_write_hooks = false;
            devlog_error("Error while binding plaintext read/write symbols for Cronet: "+ e);
        }

        // Try to wire a pattern-resolved SSL_get_fd for stripped builds (no-op
        // unless an SSL_get_fd byte-pattern is shipped for this module).
        this.resolveSslGetFdPattern();
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

        let secretU8: Uint8Array | null = null;
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
            if (keyData) secretU8 = new Uint8Array(keyData as ArrayBuffer);
        } else {
            devlog("[Error] Argument 'key' is NULL");
        }

        //devlog("invoking ssl_log_secret() from BoringSSL statically linked into Cronet");
        devlog("invoking shadow keylog_callback from Cronet (" + this.module_name + ")");
        sendKeylog(labelStr+" "+client_random+" "+secret_key);

        // M2 spike: libsignal's BoringSSL keys flow through THIS Cronet path
        // (not boringSslDumpKeys). Mark the SSL* as keyed, and learn where the
        // traffic secrets live in s3 (ground truth for attach-mode recovery).
        if (!sslStructPtr.isNull()) {
            noteHandshakeLogged(sslStructPtr);
            if (secretU8) {
                observeHandshakeSecret(this.module_name, sslStructPtr, labelStr, secretU8);
            }
        }
    }

    // Cronet plaintext capture. Two code paths:
    //   1. Symbol-bearing Cronet forks (e.g. libwarp_mobile.so) export
    //      SSL_read/SSL_write/SSL_get_fd/SSL_get_session/SSL_SESSION_get_id.
    //      We attach at those symbol addresses and resolve the fd via the
    //      symbol-resolved SSL_get_fd decoder — this is the legacy Cronet
    //      implementation, ported verbatim into the modern path.
    //   2. Stripped/static Cronet (libcronet.so, libmonochrome) inlines
    //      BoringSSL and exports nothing. The fd accessor then has to come from
    //      a byte-pattern — see resolveSslGetFdPattern() (the SSL_get_fd hook
    //      point). Until both the SSL_get_fd pattern and pattern-resolved
    //      SSL_read/SSL_write addresses are wired, this path emits a single
    //      precise notice instead of an empty/garbage PCAP.
    private static plaintextNoticeShown = new Set<string>();

    // Emit a single notice per (module, action, reason) explaining why stripped-Cronet
    // plaintext is unavailable: "missing" = no symbols and no byte-pattern at all;
    // "pending" = a byte-pattern exists but the SSL_get_fd hook point isn't wired yet.
    private noticePlaintext(action: "SSL_Read" | "SSL_Write", reason: "missing" | "pending"): void {
        const key = `${this.module_name}:${action}:${reason}`;
        if (Cronet.plaintextNoticeShown.has(key)) return;
        Cronet.plaintextNoticeShown.add(key);
        if (reason === "missing") {
            log(`[!] ${this.module_name}: plaintext PCAP requested but neither ${action} symbols nor byte-patterns are available for this module; plaintext capture unavailable.`);
        } else {
            log(`[!] ${this.module_name}: ${action} byte-pattern present but stripped-Cronet plaintext needs a pattern-resolved SSL_get_fd (see resolveSslGetFdPattern) + pattern-resolved ${action} address; not yet wired — only keylog will be emitted.`);
        }
    }

    // === Pattern-based SSL_get_fd hook point (stripped Cronet) ==============
    // Stripped Cronet exports no SSL_get_fd, so the symbol-resolved fd decoder
    // (this.SSL_get_fd) is null. To capture plaintext with correct src/dst
    // addressing on such builds, ship an "SSL_get_fd" byte-pattern (Schema-B,
    // alongside SSL_Read/SSL_Write) for the module. When that pattern is
    // present, scan it, wrap the match as SSL_get_fd(SSL*) -> int, and store it
    // in this.patternSslGetFd; resolveFd() then uses it automatically. Until a
    // pattern is shipped this is a no-op and the hook point stays open.
    private resolveSslGetFdPattern(): void {
        this.patternSslGetFd = null;
        if (!isPatternReplaced()) return;
        if (!hasUsablePatternsFor(patternsJson, this.module_name, this.cronetFallbackKey, "SSL_get_fd")) {
            // No SSL_get_fd pattern shipped for this module — hook point left open.
            return;
        }
        // FILL-IN POINT: an SSL_get_fd pattern exists for this module. Resolve it
        // to an address (see PatternStrategy.scanFirstMatchAsync for the scan
        // helper) and wrap it, e.g.:
        //   this.patternSslGetFd = new NativeFunction(matchedAddr, "int", ["pointer"]);
        devlog_debug(`[Cronet modern] SSL_get_fd byte-pattern present for ${this.module_name}; pattern->address scan + NativeFunction wiring is the remaining fill-in.`);
    }

    // Resolve the socket fd for an SSL*. Prefers the symbol-resolved SSL_get_fd
    // decoder; falls back to the pattern-resolved one (stripped builds). Returns
    // -1 when neither is available (getPortsAndAddresses then honours
    // enable_default_fd).
    private resolveFd(ssl: NativePointer): number {
        if (this.SSL_get_fd) {
            try { return this.SSL_get_fd(ssl) as number; } catch (e) { devlog_debug("[Cronet modern] SSL_get_fd(symbol) threw: " + e); return -1; }
        }
        if (this.patternSslGetFd) {
            try { return this.patternSslGetFd(ssl) as number; } catch (e) { devlog_debug("[Cronet modern] SSL_get_fd(pattern) threw: " + e); return -1; }
        }
        return -1;
    }

    // Attach the symbol-resolved SSL_read/SSL_write plaintext hook. Read and write
    // share everything except the buffer-length source: SSL_read learns the byte
    // count from retval (onLeave), SSL_write from the length arg (onEnter).
    private installPlaintextHook(symbol: "SSL_read" | "SSL_write", isRead: boolean): void {
        if (!pcap_enabled) return;
        if (!this.do_read_write_hooks) {
            // Stripped Cronet: symbol surface unavailable. Pattern-based capture is
            // the companion to the SSL_get_fd hook point and is not wired yet.
            const action = isRead ? "SSL_Read" : "SSL_Write";
            const reason = (isPatternReplaced() && hasUsablePatternsFor(patternsJson, this.module_name, this.cronetFallbackKey, action))
                ? "pending" : "missing";
            this.noticePlaintext(action, reason);
            return;
        }

        const lib_addresses = this.addresses;
        const instance = this;
        const current_module_name = this.module_name;

        Interceptor.attach(this.addresses[this.module_name][symbol], {
            onEnter: function (args: any) {
                this.fd = instance.resolveFd(args[0]);
                if (this.fd < 0 && !enable_default_fd) return;
                const message = getPortsAndAddresses(this.fd as number, isRead, lib_addresses[current_module_name], enable_default_fd);
                if (message === null) return;
                message["ssl_session_id"] = openSslSessionIdDecoder(args[0], instance.sessionFns as any);
                message["client_random"] = instance.get_client_random_from_ssl_struct(args[0]);
                message["function"] = symbol;
                if (isRead) {
                    // Plaintext lands in the buffer during the call; read it in onLeave.
                    this.message = message;
                    this.buf = args[1];
                } else {
                    // Write payload is already in args[1]; args[2] is the length.
                    sendDatalog(message, args[1].readByteArray(args[2].toInt32()));
                }
            },
            onLeave: function (retval: any) {
                if (!isRead) return;
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0 || (this.fd < 0 && !enable_default_fd)) return;
                if (this.message) {
                    sendDatalog(this.message, this.buf.readByteArray(retval));
                }
            }
        });
    }

    install_plaintext_read_hook(){
        this.installPlaintextHook("SSL_read", true);
    }

    install_plaintext_write_hook(){
        this.installPlaintextHook("SSL_write", false);
    }

    install_key_extraction_pattern_hook(){
        // needs to be setup for the specific plattform
    }
}