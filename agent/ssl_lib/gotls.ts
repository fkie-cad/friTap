import { readAddresses, get_hex_string_from_byte_array, getBaseAddress, isSymbolAvailable } from "../shared/shared_functions.js";
import { devlog, devlog_error, log } from "../util/log.js";
import { GoRuntimeParser } from "../util/go_runtime_parser.js";


interface KeyLogEntry {
    label: string;
    clientRandom: string;
    secret: string;
}

interface GoVersion {
    major: number;
    minor: number;
    patch: number;
}

export const symbol_writeKeyLog = 'crypto/tls.(*Config).writeKeyLog';
const symbol_tlsRead = 'crypto/tls.(*Conn).Read';
const symbol_tlsWrite = 'crypto/tls.(*Conn).Write';


export class GoTlsLogger {
    found_writeKeyLog: boolean;
    module: Module;
    no_hooking_success: boolean;

    constructor(module: Module, found_writeKeyLog: boolean, no_hooking_success: boolean) {
        this.found_writeKeyLog = found_writeKeyLog;
        this.module = module;
        this.no_hooking_success = no_hooking_success;
    }
}

export class GoTLS {
    module_name: string;
    library_method_mapping: { [key: string]: string[] } = {};
    addresses: { [lib: string]: { [fn: string]: NativePointer } } = {};
    is_base_hook: boolean;
    go_version: GoVersion | null = null;
    hooked_functions: Set<string> = new Set();
    runtime_parser: GoRuntimeParser;

    constructor(public moduleName:string, public socket_library:String,is_base_hook: boolean ,public passed_library_method_mapping?: { [key: string]: Array<string> } ) {
            this.module_name = moduleName;
            this.is_base_hook = is_base_hook;

            if(typeof passed_library_method_mapping !== 'undefined'){
                this.library_method_mapping = passed_library_method_mapping;
            }else{
                this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
            }

            

            let found_writeKeyLog = false;


            if (isSymbolAvailable(moduleName, symbol_writeKeyLog)) {
                        this.library_method_mapping[`*${moduleName}*`].push(symbol_writeKeyLog);
                        found_writeKeyLog = true;
            }else{
                devlog("[GoTLS] unable to find symbol: " + symbol_writeKeyLog + " in module: " + moduleName);
            }

            if (isSymbolAvailable(moduleName, symbol_tlsRead)) {
                        this.library_method_mapping[`*${moduleName}*`].push(symbol_tlsRead);
            }else{
                devlog("[GoTLS] unable to find symbol: " + symbol_tlsRead + " in module: " + moduleName);
            }

            if (isSymbolAvailable(moduleName, symbol_tlsWrite)) {
                        this.library_method_mapping[`*${moduleName}*`].push(symbol_tlsWrite);
            }else{
                devlog("[GoTLS] unable to find symbol: " + symbol_tlsWrite + " in module: " + moduleName);
            }

            this.addresses = readAddresses(moduleName,this.library_method_mapping);

            if(found_writeKeyLog === false){
                let writeKeyLog_Address = this.resolve_symbol_with_fallback(symbol_writeKeyLog);
                if(writeKeyLog_Address !== null){
                    this.library_method_mapping[`*${moduleName}*`].push(symbol_writeKeyLog);
                    this.addresses[moduleName][symbol_writeKeyLog] = writeKeyLog_Address;
                    devlog("[GoTLS] found writeKeyLog symbol: " + symbol_writeKeyLog + " at address: " + writeKeyLog_Address);      
                }
            }



            


            /*
             * Right now we are not using the Go version detection, as it is not working properly
             */
            // this.go_version = this.detect_go_version();
    }

    detect_go_version(): GoVersion | null {
        try {
            // Try to find Go build info in the binary
            const buildInfoSymbol = "runtime.buildVersion";
            const address = this.resolve_symbol_with_fallback(buildInfoSymbol);
            if (address) {
                // Read Go version string from runtime
                const versionStr = address.readCString();
                if (versionStr) {
                    const match = versionStr.match(/go(\d+)\.(\d+)(?:\.(\d+))?/);
                    if (match) {
                        return {
                            major: parseInt(match[1]),
                            minor: parseInt(match[2]),
                            patch: parseInt(match[3] || "0")
                        };
                    }
                }
            }
        } catch (err) {
            devlog(`[GoTLS] Failed to detect Go version: ${err}`);
        }
        return null;
    }

    // Convert Go symbol name to possible mangled variants
    getGoSymbolVariants(symbol: string): string[] {
        const variants: string[] = [symbol];
        
        // Common Go symbol mangling patterns
        const mangled1 = symbol
            .replace(/\//g, '_')           // crypto_tls -> crypto_tls
            .replace(/\(\*([^)]+)\)/g, '_ptr_$1')  // (*Config) -> _ptr_Config
            .replace(/\./g, '.');          // Keep dots in some cases
        variants.push(mangled1);
        
        // Alternative mangling: dots to underscores
        const mangled2 = symbol
            .replace(/\//g, '_')           // crypto_tls -> crypto_tls
            .replace(/\(\*([^)]+)\)/g, '_ptr_$1')  // (*Config) -> _ptr_Config
            .replace(/\./g, '_');          // . -> _
        variants.push(mangled2);
        
        // Unity/JNI specific mangling
        const mangled3 = symbol
            .replace(/crypto\_tls/g, 'crypto_tls')
            .replace(/\(\*Conn\)/g, '_ptr_Conn')
            .replace(/\(\*Config\)/g, '_ptr_Config')
            .replace(/\./g, '_');
        variants.push(mangled3);
        
        // Remove duplicates
        return [...new Set(variants)];
    }

    resolve_symbol_with_fallback(symbol: string): NativePointer | null {
        try {
            // Try exact symbol match first
            let address = Module.getGlobalExportByName(symbol);
            if (address) return address;

            // Try module-specific export
            try {
                address = Process.getModuleByName(this.module_name).getExportByName(symbol);
                if (address) return address;
            } catch (e) {
                // Module might not be loaded yet, continue
            }

            // Get all symbol variants (mangled names)
            const symbolVariants = this.getGoSymbolVariants(symbol);
            
            // Try each variant as exact export
            for (const variant of symbolVariants) {
                try {
                    address = Process.getModuleByName(this.module_name).getExportByName(variant);
                    if (address) {
                        devlog(`[GoTLS] Found symbol ${symbol} as ${variant}`);
                        return address;
                    }
                } catch (e) {
                    // Continue to next variant
                }
            }

            if (address === null) {
                return DebugSymbol.fromName(symbol).address;
            }

            // Try pattern-based fallback using symbol variants
            const exports = Process.getModuleByName(this.module_name).enumerateExports();
            for (const variant of symbolVariants) {
                for (const exp of exports) {
                    if (exp.name === variant || exp.name.includes(variant)) {
                        devlog(`[GoTLS] Found symbol ${symbol} via pattern match: ${exp.name}`);
                        return exp.address;
                    }
                }
            }
            
            // Last resort: fuzzy matching on export names
            const symbolBase = symbol.split('.').pop() || symbol;
            for (const exp of exports) {
                if (exp.name.toLowerCase().includes(symbolBase.toLowerCase())) {
                    devlog(`[GoTLS] Found symbol ${symbol} via fuzzy match: ${exp.name}`);
                    return exp.address;
                }
            }

        } catch (err) {
            devlog(`[GoTLS] Symbol resolution failed for ${symbol}: ${err}`);
        }
        
        devlog(`[GoTLS] Could not resolve symbol: ${symbol}`);
        return null;
    }

    /**
     * 
     * Hooking writeKeyLog function to extract TLS keys.
     * Details at source code from https://github.com/golang/go/blob/54c9d776302d53ab1907645cb67fa4a948e1500c/src/crypto/tls/common.go#L1540C10-L1540C16
     * 
     * @param labelPtr 
     * @param sslStructPtr 
     * @param keyPtr 
     */
    dumpKeys(labelPtr: NativePointer, labelLen: number, clientRandomPtr: NativePointer,clientRandomLength: number, keyPtr: NativePointer, keyLength: number): void {
            const MAX_KEY_LENGTH = 64;
    
            let labelStr = '';
            let client_random = '';
            let secret_key = '';
    
            // Read the label (the label pointer might contain a C string)
            if (!labelPtr.isNull()) {
               
                labelStr = labelPtr.readCString() ?? '';  // Read label as a C string
            } else {
                devlog_error("[GoTLS Error] Argument 'labelPtr' is NULL");
            }
    
            // Extract client_random from the SSL structure
            if (!clientRandomPtr.isNull()) {
                 if(clientRandomLength === 0){
                    clientRandomLength = 32;
                }
                const client_random_buffer = clientRandomPtr.readByteArray(clientRandomLength);
                            
                client_random = get_hex_string_from_byte_array(new Uint8Array(client_random_buffer as ArrayBuffer));
            }else {
                devlog_error("[GoTLS Error] Argument 'sslStructPtr' is NULL");
            }
    
            if (!keyPtr.isNull()) {
                let KEY_LENGTH = keyLength;
                if(KEY_LENGTH <= 0){
                    
                    let calculatedKeyLength = 0;
        
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
        
                    if (calculatedKeyLength > 24 && calculatedKeyLength <= 40) {
                        KEY_LENGTH = 32; // Closest match is 32 bytes
                    } else if (calculatedKeyLength >= 46 && calculatedKeyLength <=49) {
                        KEY_LENGTH = 48; // Closest match is 48 bytes
                    }else{
                        KEY_LENGTH = 32; // fall back size
                    }
                }
    
                const keyData = keyPtr.readByteArray(KEY_LENGTH); // Read the key data (KEY_LENGTH bytes)
    
                // Convert the byte array to a string of  hex values
                const hexKey = get_hex_string_from_byte_array(keyData);
        
                secret_key = hexKey;
            } else {
                devlog_error("[GoTLS Error] Argument 'key' is NULL");
            }
    
            //devlog("invoking writeKeyLog() from GoTLS");
            var message: { [key: string]: string | number | null } = {}
            message["contentType"] = "keylog"
            message["keylog"] = labelStr+" "+client_random+" "+secret_key;
            send(message)
        }
    
    
        install_key_extraction_hook(){
            // needs to be setup for the specific plattform
        }
    
    // Enhanced debug function to list all exports and runtime functions for troubleshooting
    debug_list_exports(): void {
        try {
            // Standard exports
            const exports = Process.getModuleByName(this.module_name).enumerateExports();
            const goExports = exports.filter(exp => 
                exp.name.includes('crypto') || 
                exp.name.includes('tls') || 
                exp.name.includes('Config') ||
                exp.name.includes('Conn') ||
                exp.name.includes('writeKeyLog') ||
                exp.name.includes('Read') ||
                exp.name.includes('Write')
            );
            
            devlog(`[GoTLS] Found ${goExports.length} potential Go TLS exports in ${this.module_name}:`);
            for (const exp of goExports.slice(0, 20)) { // Limit to first 20 for readability
                devlog(`[GoTLS]   ${exp.name} @ ${exp.address}`);
            }
            if (goExports.length > 20) {
                devlog(`[GoTLS]   ... and ${goExports.length - 20} more`);
            }


            /*
             * This needs more investigation, as it is not working properly right now
           
            
            // Runtime parser functions
            devlog(`[GoTLS] Runtime parser debug info:`);
            const debugInfo = this.runtime_parser.getDebugInfo();
            const stats = this.runtime_parser.getParsingStats();
            
            devlog(`[GoTLS]   Module: ${debugInfo.module_name}`);
            devlog(`[GoTLS]   Base address: ${debugInfo.baseAddress}`);
            devlog(`[GoTLS]   Functions found: ${debugInfo.functionsFound}`);
            devlog(`[GoTLS]   Go version: ${stats.goVersion}`);
            devlog(`[GoTLS]   Architecture: ${stats.architecture}`);
            devlog(`[GoTLS]   Parser initialized: ${stats.parsed}`);
            
            if (debugInfo.moduleData) {
                devlog(`[GoTLS]   Text section: ${debugInfo.moduleData.textStart} - ${debugInfo.moduleData.textEnd}`);
                devlog(`[GoTLS]   Pclntab: ${debugInfo.moduleData.pclntab}`);
                devlog(`[GoTLS]   Functab: ${debugInfo.moduleData.functab}`);
            }
            
            // If parser didn't initialize properly, try retry
            if (!this.runtime_parser.isInitialized()) {
                devlog(`[GoTLS] Runtime parser not properly initialized, attempting retry...`);
                if (this.runtime_parser.retryInitialization()) {
                    devlog(`[GoTLS] Runtime parser retry successful`);
                } else {
                    devlog(`[GoTLS] Runtime parser retry failed`);
                }
            }
            
            // List TLS functions found by runtime parser
            const tlsFunctions = this.runtime_parser.getTLSFunctions();
            devlog(`[GoTLS] Runtime parser found ${tlsFunctions.length} TLS-related functions:`);
            for (const func of tlsFunctions.slice(0, 15)) {
                devlog(`[GoTLS]   ${func.name} @ ${func.address}${func.size ? ` (size: ${func.size})` : ''}`);
            }
            */
            
        } catch (err) {
            devlog(`[GoTLS] Failed to list exports: ${err}`);
        }
    }

    install_tls_keys_callback_hook(): boolean {
        Interceptor.attach(this.addresses[this.module_name][symbol_writeKeyLog],
            {
                onEnter: function (args: any) {
                    try{
                        //instance.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback);
                        
                        /**
                         * GoTLS Key Extraction - Multi-Architecture Support
                         * 
                         * Go's crypto/tls package calls a key logging callback with TLS key material.
                         * The register mapping differs between architectures due to calling conventions:
                         * 
                         * x64 (System V ABI):
                         *   RBX: label string pointer
                         *   RCX: label string length
                         *   RDI: client_random pointer  
                         *   RSI: client_random length
                         *   R9:  secret key pointer
                         *   R10: secret key length
                         * 
                         * ARM64 (AAPCS64):
                         *   X1: label string pointer
                         *   X2: label string length
                         *   X3: client_random pointer
                         *   X4: client_random length
                         *   X5: secret key pointer
                         *   X6: secret key length
                         */
                        
                        let labelStr: string, client_random: string, secret_key: string;
                        
                        if (Process.arch === 'x64') {
                            // x64 calling convention: RBX, RCX, RDI, RSI, R9, R10
                            const ctx = this.context as X64CpuContext;
                            
                            // Validate pointers and lengths before reading
                            const labelLen = ctx.rcx.toInt32();
                            const randomLen = ctx.rsi.toInt32();
                            const secretLen = ctx.r10.toInt32();
                            
                            if (labelLen > 0 && labelLen < 1024 && !ctx.rbx.isNull()) {
                                labelStr = ctx.rbx.readUtf8String(labelLen);
                            } else {
                                throw new Error(`Invalid label parameters: ptr=${ctx.rbx}, len=${labelLen}`);
                            }
                            
                            if (randomLen > 0 && randomLen < 1024 && !ctx.rdi.isNull()) {
                                client_random = get_hex_string_from_byte_array(ctx.rdi.readByteArray(randomLen));
                            } else {
                                throw new Error(`Invalid client_random parameters: ptr=${ctx.rdi}, len=${randomLen}`);
                            }
                            
                            if (secretLen > 0 && secretLen < 1024 && !ctx.r9.isNull()) {
                                secret_key = get_hex_string_from_byte_array(ctx.r9.readByteArray(secretLen));
                            } else {
                                throw new Error(`Invalid secret parameters: ptr=${ctx.r9}, len=${secretLen}`);
                            }
                            
                        } else if (Process.arch === 'arm64') {
                            // ARM64 calling convention: X0-X7 for arguments, X19-X28 for callee-saved
                            const ctx = this.context as Arm64CpuContext;
                            
                            // Validate pointers and lengths before reading
                            const labelLen = ctx.x2.toInt32();
                            const randomLen = ctx.x4.toInt32();
                            const secretLen = ctx.x6.toInt32();
                            
                            if (labelLen > 0 && labelLen < 1024 && !ctx.x1.isNull()) {
                                labelStr = ctx.x1.readUtf8String(labelLen);
                            } else {
                                throw new Error(`Invalid label parameters: ptr=${ctx.x1}, len=${labelLen}`);
                            }
                            
                            if (randomLen > 0 && randomLen < 1024 && !ctx.x3.isNull()) {
                                client_random = get_hex_string_from_byte_array(ctx.x3.readByteArray(randomLen));
                            } else {
                                throw new Error(`Invalid client_random parameters: ptr=${ctx.x3}, len=${randomLen}`);
                            }
                            
                            if (secretLen > 0 && secretLen < 1024 && !ctx.x5.isNull()) {
                                secret_key = get_hex_string_from_byte_array(ctx.x5.readByteArray(secretLen));
                            } else {
                                throw new Error(`Invalid secret parameters: ptr=${ctx.x5}, len=${secretLen}`);
                            }
                            
                        } else {
                            devlog_error(`[GoTLS] Architecture ${Process.arch} not supported for register-based key extraction`);
                            devlog_error(`[GoTLS] Supported architectures: x64, arm64`);
                            devlog_error(`[GoTLS] Consider using function argument-based hooking for this platform`);
                            return false;
                        }
                        
                        // Send the extracted TLS key log message
                        const message: { [key: string]: string | number | null } = {
                            "contentType": "keylog",
                            "keylog": `${labelStr} ${client_random} ${secret_key}`
                        };
                        send(message);
                        devlog(`[GoTLS] Key extracted on ${Process.arch}: ${labelStr} ${client_random.substring(0, 16)}...`);
                        return true;
                    }catch (e) {
                        devlog_error(`Error in writeKeyLog hook: ${e}`);
                        return false
                    }
                    
                }
        
            });
        return false;
    }

    install_plaintext_write_hook(): void {
        const symbol = "crypto_tls.(*Conn).writeRecordLocked";
        try {
            const address = this.resolve_symbol_with_fallback(symbol);
            if (!address) {
                devlog(`[GoTLS] ${symbol} not found, skipping write hook`);
                return;
            }
            
            Interceptor.attach(address, {
                onEnter(args) {
                    const recordType = args[2].toInt32();
                    if (recordType !== 23) return; // Only application data

                    const dataPtr = args[3];
                    const len = args[4].toInt32();
                    if (len > 0) {
                        const buf = dataPtr.readByteArray(len);
                        devlog(`[GoTLS] write plaintext (${len} bytes): ${buf ? buf.toString() : "[unreadable]"}`);
                        
                        // Send plaintext data to friTap
                        send({
                            contentType: "datalog",
                            function: "SSL_write",
                            data: buf
                        });
                    }
                }
            });
            this.hooked_functions.add(symbol);
            log(`[GoTLS] Successfully hooked ${symbol}`);
        } catch (err) {
            devlog(`[GoTLS] Failed to hook writeRecordLocked: ${err}`);
        }
    }

    install_plaintext_read_hook(): void {
        const symbol = "crypto_tls.(*Conn).Read";
        try {
            const address = this.resolve_symbol_with_fallback(symbol);
            if (!address) {
                devlog(`[GoTLS] ${symbol} not found, skipping read hook`);
                return;
            }
            
            Interceptor.attach(address, {
                onEnter(args) {
                    this.x0 = args[0]; // Go slice pointer
                },
                onLeave(retval) {
                    const len = retval.toInt32();
                    if (len <= 0) return;
                    
                    const buf = this.x0.readByteArray(len);
                    devlog(`[GoTLS] read plaintext (${len} bytes): ${buf ? buf.toString() : "[unreadable]"}`);
                    
                    // Send plaintext data to friTap
                    send({
                        contentType: "datalog",
                        function: "SSL_read",
                        data: buf
                    });
                }
            });
            this.hooked_functions.add(symbol);
            log(`[GoTLS] Successfully hooked ${symbol}`);
        } catch (err) {
            devlog(`[GoTLS] Failed to hook Read: ${err}`);
        }
    }      
    
    // Enhanced runtime parser hook installation currently not used - needs further testing
    install_runtime_parser_hooks(): void {
        try {
            const tlsFunctions = this.runtime_parser.getTLSFunctions();
            devlog(`[GoTLS] Runtime parser found ${tlsFunctions.length} TLS functions to attempt hooking`);
            
            if (tlsFunctions.length === 0) {
                devlog(`[GoTLS] No TLS functions found by runtime parser, trying broader search...`);
                
                // Try to find specific function names we care about
                const targetFunctions = [
                    'crypto_tls.(*Config).writeKeyLog',
                    'crypto_tls.(*Conn).Read',
                    'crypto_tls.(*Conn).Write',
                    'crypto_tls.(*Conn).writeRecordLocked',
                    'writeKeyLog', 'Read', 'Write', 'writeRecordLocked'
                ];
                
                for (const target of targetFunctions) {
                    const found = this.runtime_parser.findFunction(target);
                    if (found) {
                        devlog(`[GoTLS] Found specific target function: ${found.name}`);
                        tlsFunctions.push(found);
                    }
                }
            }
            
            
            
        }catch (err) {
            devlog_error(`[GoTLS] Failed to install runtime parser hooks: ${err}`);
        }
    } 
    
    
}


