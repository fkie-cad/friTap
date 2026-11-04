import { readAddresses, get_hex_string_from_byte_array, getBaseAddress, isSymbolAvailable } from "../../shared/shared_functions.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import {
    GO_WRITE_KEYLOG_PATTERNS,
    GoKeyLogArchPatterns,
    GoKeyLogPatternHooker,
    installGoKeyLogHook,
    installGoKeylogByPattern,
} from "../shared/go_keylog_hook.js";
import { installBoringSSLSymbolHook, makeBoringSslDumpKeys } from "../../shared/boringssl_symbol_hook.js";
import { devlog, devlog_error } from "../../util/log.js";
import { GoRuntimeParser } from "../../util/go_runtime_parser.js";
import { keylog_enabled } from "../../fritap_agent.js";


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
            // The Go symbols found below are pushed onto this entry: without it every found
            // symbol threw (undefined.push) and aborted the whole Go executor.
            this.library_method_mapping[`*${moduleName}*`] ??= [];

            

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
                }else{
                    devlog("[GoTLS] unable to find writeKeyLog symbol even with alternative symbol resolutions: " + symbol_writeKeyLog + " in module: " + moduleName);
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
            // Exact export first. The find* lookups return null when the name is missing;
            // the get* variants THROW, which (caught below) skipped every fallback.
            let address: NativePointer | null = Module.findGlobalExportByName(symbol);
            if (address) return address;

            // Module-specific export (the module might not be loaded yet: findModuleByName -> null)
            const module = Process.findModuleByName(this.module_name);
            address = module?.findExportByName(symbol) ?? null;
            if (address) return address;

            // Get all symbol variants (mangled names)
            const symbolVariants = this.getGoSymbolVariants(symbol);
            
            // Try each variant as exact export
            for (const variant of symbolVariants) {
                address = module?.findExportByName(variant) ?? null;
                if (address) {
                    devlog(`[GoTLS] Found symbol ${symbol} as ${variant}`);
                    return address;
                }
            }

            // Try DebugSymbol lookup
            try {
                const debugAddr = DebugSymbol.fromName(symbol).address;
                if (!debugAddr.isNull()) {
                    devlog(`[GoTLS] Found symbol ${symbol} via DebugSymbol`);
                    return debugAddr;
                }
            } catch (e) {
                // DebugSymbol lookup failed, continue to pattern-based fallback
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

            // Last resort: an export whose method name is this symbol's (".Read", "_Read").
            // Only the method-name boundary counts: a substring match ("read" in "pthread_*")
            // would hook an unrelated function now that this fallback is actually reached.
            const symbolBase = symbol.split('.').pop() || symbol;
            for (const exp of exports) {
                if (exp.name.endsWith(`.${symbolBase}`) || exp.name.endsWith(`_${symbolBase}`)) {
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
            sendKeylog(labelStr+" "+client_random+" "+secret_key);
        }
    
    
    /** The name a module is loaded under when `module_name` is a path ("/x/y/libgojni.so"). */
    getSoName(modulePath: string): string {
        const m = modulePath.match(/([^\/\\]+\.so)$/);
        return m ? m[1] : modulePath;
    }

    /**
     * Keylog hook on crypto/tls.(*Config).writeKeyLog: by symbol when resolved, else (stripped
     * binary) by the per-arch writeKeyLog entry patterns (go_keylog_hook.ts; the Android
     * --experimental gate lives there). Nothing is hooked unless keys were requested (-k).
     * Returns a GoTlsLogger (symbol path), the scanning hooker (pattern path) or undefined.
     */
    install_key_extraction_hook(archPatterns: GoKeyLogArchPatterns = GO_WRITE_KEYLOG_PATTERNS): GoTlsLogger | GoKeyLogPatternHooker | null | undefined {
        if (!keylog_enabled) return undefined;
        let soName = this.module_name;
        let goTLSModule = Process.findModuleByName(soName);
        if (goTLSModule === null) {
            soName = this.getSoName(this.module_name);
            goTLSModule = Process.findModuleByName(soName);
            if (goTLSModule === null) {
                devlog("[-] GoTLS Error: Unable to find module: " + this.module_name);
                return undefined;
            }
        }
        const writeKeyLog = this.addresses[this.module_name]?.[symbol_writeKeyLog];
        if (writeKeyLog === undefined || writeKeyLog === null) {
            return installGoKeylogByPattern(this.module_name, archPatterns, { soName, module: goTLSModule });
        }
        devlog("[GoTLS] writeKeyLog symbol available");
        return new GoTlsLogger(goTLSModule, true, this.install_tls_keys_callback_hook());
    }

    /**
     * Last resort when the writeKeyLog pattern scan found nothing: the cgo-linked C BoringSSL
     * bssl::ssl_log_secret (C ABI), via the shared BoringSSL symbol hook. No Go function is
     * named "ssl_log". `hooker` is what install_key_extraction_hook returned.
     */
    execute_symbol_based_hooking(hooker: any): void {
        if (!keylog_enabled) return;
        if (hooker === undefined || hooker === null) {
            devlog("[-] Error: Hooker is undefined.");
            return;
        }
        if (!hooker.no_hooking_success) return;
        installBoringSSLSymbolHook(this.module_name, makeBoringSslDumpKeys(this.module_name));
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
        if (!keylog_enabled) return false;
        // Shared Go keylog hook (go_keylog_hook.ts): Go registers, onEnter-only, on arm64
        // possibly after the Go stack check. Same hook as the pattern-based fallback.
        installGoKeyLogHook(this.addresses[this.module_name][symbol_writeKeyLog]);
        return false;
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

/**
 * Class-based Go keylog executor of the modern path (the fallback of gotls_execute_modern when
 * the data-driven definition fails): symbol resolution with the GoTLS fallback cascade, the
 * writeKeyLog byte patterns for stripped binaries, then the cgo BoringSSL last resort.
 * Keys only; Go plaintext is installed by the definition (go_plaintext.ts) alone.
 */
export function gotls_execute_class_based(moduleName: string, socketLibrary: string, isBaseHook: boolean,
                                          archPatterns: GoKeyLogArchPatterns = GO_WRITE_KEYLOG_PATTERNS): GoTLS {
    const gotls = new GoTLS(moduleName, socketLibrary, isBaseHook);
    try {
        const hooker = gotls.install_key_extraction_hook(archPatterns);
        // The pattern scan reports no_hooking_success asynchronously; check it after the scan.
        setTimeout(() => {
            try {
                gotls.execute_symbol_based_hooking(hooker);
            } catch (e) {
                devlog("[-] Error in gotls.execute_symbol_based_hooking: " + e);
            }
        }, 1500);
    } catch (e) {
        devlog(`gotls_execute_class_based error: ${e}`);
    }
    if (isBaseHook) {
        const initAddresses = gotls.addresses[moduleName];
        if (initAddresses && Object.keys(initAddresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = initAddresses;
        }
    }
    return gotls;
}
