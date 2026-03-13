import { log, devlog, devlog_error } from "../util/log.js";
import { AF_INET, AF_INET6, AddressFamilyMapping, unwantedFDs, Platform } from "./shared_structures.js";
import { HookRegistration, HookRegistry } from "./registry.js";
import { Java, JavaWrapper } from "./javalib.js";
import { offsets } from "../fritap_agent.js";
import { isModuleHooked, markModuleHooked } from "./library_scanner.js";

function wait_for_library_loaded(module_name: string){
    let timeout_library = 5;
    let module_adress = Process.getModuleByName(module_name).base;
    if(module_adress === NULL || module_adress === null){
        log("[*] Waiting "+timeout_library+" milliseconds for the loading of "+module_name);
        setTimeout(wait_for_library_loaded,timeout_library)
    }
}

/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */

/**
 * Loader that uses HookRegistry to find and invoke hooks for loaded modules.
 * Queries the registry for hooks matching each module name and invokes them.
 *
 * @param platform Target platform (e.g., "linux", "android", "ios")
 * @param hookRegistry The HookRegistry singleton instance
 * @param moduleNames Array of loaded module names to check against
 * @param platformOs Human-readable platform OS name for logging
 * @param is_base_hook Boolean indicating if this is a base hook or dynamic load
 */
export function ssl_library_loader(platform: Platform, hookRegistry: HookRegistry, moduleNames: Array<string>, platformOs: string, is_base_hook: boolean, protocol?: string): void {
    for (let module_name of moduleNames) {
        // Get module info for path filtering
        let modulePath: string | undefined;
        try {
            const module = Process.getModuleByName(module_name);
            modulePath = module.path;
        } catch (error) {
            // Module might not be loaded yet, continue without path
        }

        if (isModuleHooked(module_name)) {
            devlog(`${module_name} already hooked, skipping`);
            continue;
        }

        // Find all hooks matching this module name (filtered by protocol if provided)
        const matches = hookRegistry.findAllMatches(platform, module_name, modulePath, protocol);

        for (let match of matches) {
            try {
                log(`${module_name} found & will be hooked on ${platformOs}!`)

                try {
                    Process.getModuleByName(module_name).ensureInitialized();
                } catch (error) {
                    wait_for_library_loaded(module_name);
                }

                // Invoke the hook function
                match.hookFn(module_name, is_base_hook);
                markModuleHooked(module_name);

                // Notify host that a library was detected
                send({contentType: "library_detected", library: module_name, path: modulePath || "", protocol: protocol || "tls"});

            } catch (error) {
                if (checkNumberOfExports(module_name) > 3) {
                    devlog_error(`error: skipping module ${module_name}`)
                    devlog_error("Loader error: " + error)
                }
            }
        }
    }
}



// ---------------------------------------------------------------------------
// Dynamic Loader Hooking
// ---------------------------------------------------------------------------

export interface DynamicLoaderConfig {
    /** Platform identifier for registry queries */
    platform: Platform;
    /** Human-readable label for log messages (e.g., "Android", "Linux", "iOS") */
    platformLabel: string;
    /** Regex pattern to find the loader module among loaded modules (not needed when resolveViaApi is set) */
    loaderLibrary?: string | RegExp;
    /** Primary function name to hook (e.g., "dlopen", "LoadLibraryExW") */
    functionName: string;
    /** If set, use ApiResolver instead of module export lookup (e.g., "exports:KERNELBASE.dll!*LoadLibraryExW") */
    resolveViaApi?: string;
    /** Check for this export first; fall back to functionName if not found (e.g., "android_dlopen_ext") */
    preferFunction?: string;
    /** If true, resolve modulePath from loaded module in onLeave (for path-based registry filtering) */
    extractModulePath?: boolean;
    /** If true, derive module name from ModuleMap(retval) instead of args[0].readCString() (Windows) */
    moduleFromRetval?: boolean;
    /** Optional callback invoked for each matched module (e.g., Windows lsass log) */
    onMatchExtra?: (moduleName: string) => void;
}

/**
 * Hook a platform's dynamic loader to intercept library loads and apply registry hooks.
 *
 * Replaces the per-platform hook_<Platform>_Dynamic_Loader() functions with a single
 * configurable implementation.
 *
 * @param config       Platform-specific loader configuration
 * @param hookRegistry The HookRegistry singleton
 * @param moduleNames  Array of currently loaded module names
 * @param is_base_hook Whether this is a base hook or dynamic load
 * @param protocol     Active protocol filter (e.g., "tls", "ssh", "auto")
 */
export function hookDynamicLoader(
    config: DynamicLoaderConfig,
    hookRegistry: HookRegistry,
    moduleNames: Array<string>,
    is_base_hook: boolean,
    protocol?: string
): void {
    try {
        let hookAddress: NativePointer;

        if (config.resolveViaApi) {
            // Windows-style: use ApiResolver to find the function
            const resolver: ApiResolver = new ApiResolver('module');
            const matches = resolver.enumerateMatches(config.resolveViaApi);
            if (matches.length === 0) {
                log(`[-] Missing ${config.platformLabel} dynamic loader!`);
                return;
            }
            hookAddress = matches[0].address;
        } else {
            // Unix-style: find the loader module, then get export
            const loaderRegex = config.loaderLibrary instanceof RegExp
                ? config.loaderLibrary
                : new RegExp(config.loaderLibrary);
            const loaderModule = moduleNames.find(element => element.match(loaderRegex));
            if (loaderModule === undefined) {
                throw `${config.platformLabel} Dynamic loader not found!`;
            }

            // Determine which function to hook (prefer alternative if available)
            let funcName = config.functionName;
            if (config.preferFunction) {
                const exports = Process.getModuleByName(loaderModule).enumerateExports();
                for (const ex of exports) {
                    if (ex.name === config.preferFunction) {
                        funcName = config.preferFunction;
                        break;
                    }
                }
            }

            hookAddress = Process.getModuleByName(loaderModule).getExportByName(funcName);
        }

        Interceptor.attach(hookAddress, {
            onEnter: function (args) {
                if (!config.moduleFromRetval) {
                    this.moduleName = args[0].readCString();
                }
            },
            onLeave: function (retval: any) {
                let moduleName: string | undefined;

                if (config.moduleFromRetval) {
                    // Windows: derive name from return value via ModuleMap
                    const map = new ModuleMap();
                    moduleName = map.findName(retval);
                    if (moduleName === null) return;
                } else {
                    moduleName = this.moduleName;
                }

                if (moduleName != undefined) {
                    // Optionally resolve module path for registry filtering
                    let modulePath: string | undefined;
                    if (config.extractModulePath) {
                        try {
                            const mod = Process.getModuleByName(moduleName);
                            modulePath = mod.path;
                        } catch (_) {
                            // Module not yet loaded, continue without path
                        }
                    }

                    if (isModuleHooked(moduleName)) {
                        devlog(`${moduleName} already hooked, skipping (dynamic loader)`);
                        return;
                    }

                    const matches = hookRegistry.findAllMatches(config.platform, moduleName, modulePath, protocol);
                    for (let match of matches) {
                        log(`${moduleName} was loaded & will be hooked on ${config.platformLabel}!`);
                        try {
                            match.hookFn(moduleName, is_base_hook);
                            markModuleHooked(moduleName);

                            // Notify host that a library was detected
                            send({contentType: "library_detected", library: moduleName, path: modulePath || "", protocol: protocol || "tls"});
                        } catch (error_msg) {
                            devlog(`${config.platformLabel} dynamic loader error: ${error_msg}`);
                        }
                        if (config.onMatchExtra) {
                            config.onMatchExtra(moduleName);
                        }
                    }
                }
            }
        });

        log(`[*] ${config.platformLabel} dynamic loader hooked.`);
    } catch (error) {
        devlog("Dynamic loader error: " + error);
        log(`No dynamic loader present for hooking on ${config.platformLabel}.`);
    }
}

export function getSocketLibrary(){
    var moduleNames: Array<String> = getModuleNames()
    switch(Process.platform){
        case "linux":
            return moduleNames.find(element => element.match(/libc.*\.so/))
        case "windows":
            return "WS2_32.dll"
        case "darwin":
            return "libSystem.B.dylib"
        default:
            log(`Platform "${Process.platform} currently not supported!`)
            return ""
    }
}

export function getModuleNames(){
    var moduleNames: Array<string> = []
    Process.enumerateModules().forEach(item => moduleNames.push(item.name))
    return moduleNames;
}

export function checkNumberOfExports(moduleName: string): number {
    try {
        // Get the module by name
        const module = Process.getModuleByName(moduleName);

        // Enumerate exports of the module
        const exports = module.enumerateExports();

        // Get the number of exports
        const numberOfExports = exports.length;

        // Log the result
        devlog(`The module "${moduleName}" has ${numberOfExports} exports.`);

        return numberOfExports;
    } catch (error) {
        devlog(`Error checking exports for module "${moduleName}": ${error}`);
        return -1;
    }
}

export function readAddresses(moduleName: string, library_method_mapping: { [key: string]: Array<string> }): { [library_name: string]: { [functionName: string]: NativePointer } } {
    const resolver = new ApiResolver("module");
    const addresses: { [library_name: string]: { [functionName: string]: NativePointer } } = {};

    addresses[moduleName] = {};

    for (const library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            const matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);
            let match_number = 0;
            let method_name = method.toString();

            if (method_name.endsWith("*")) { // this is for the temporary iOS bug using Frida's ApiResolver
                method_name = method_name.substring(0, method_name.length - 1);
            }
            
            if(!matches || matches === null){
                devlog(`Unable to retrieve any matches for statement: exports: ${library_name}!${method}`);
                return
            }

            if (matches.length == 0) {
                devlog(`[readAddresses] Could not find ${library_name}!${method} (deferring to pipeline)`);
                return;
            } else if (matches.length == 1) {
                devlog("Found " + method + " " + matches[0].address);
            } else {
                // Sometimes Frida returns duplicates or it finds more than one result.
                for (let k = 0; k < matches.length; k++) {
                    if (matches[k].name.endsWith(method_name)) {
                        match_number = k;
                        devlog("Found " + method + " " + matches[match_number].address);
                        break;
                    }
                }
            }

            addresses[moduleName][method_name] = matches[match_number].address;
        });
    }

    return addresses;
}






/**
 * Returns the base address of a given module
 * @param {string} moduleName Name of module to return base address from
 * @returns
 */
 export function getBaseAddress(moduleName: String): NativePointer | null {
    devlog("Module to find: "+moduleName);
    try {
        return Process.getModuleByName(moduleName as string).base;
    } catch (e) {
        return null;
    }
}


// Cache for NativeFunction wrappers (created once, reused per call)
let _cachedSocketFns: {
    getpeername: NativeFunction<number, [number, NativePointer, NativePointer]>;
    getsockname: NativeFunction<number, [number, NativePointer, NativePointer]>;
    ntohs: NativeFunction<number, [number]>;
    ntohl: NativeFunction<number, [number]>;
} | null = null;
let _cachedAddrBuf: NativePointer | null = null;
let _cachedAddrLenBuf: NativePointer | null = null;

/**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {int} sockfd The file descriptor of the socket to inspect.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".
*/
export function getPortsAndAddresses(sockfd: number, isRead: boolean, methodAddresses: { [key: string]: NativePointer }, enable_default_fd : boolean): { [key: string]: string | number } {

    var message: { [key: string]: string | number } = {}
    if (enable_default_fd && (sockfd < 0)){

        message["src" + "_port"] = 1234
        message["src" + "_addr"] = 0x7F000001
        message["dst" + "_port"] = 2345
        message["dst" + "_addr"] = 0x7F000001
        message["ss_family"] = "AF_INET"

        return message
    }

    // Check if this fd is already marked as unwanted
    if (unwantedFDs.has(sockfd)) {
        return null; // Skip further processing
    }

    if (!_cachedSocketFns) {
        _cachedSocketFns = {
            getpeername: new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"]),
            getsockname: new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"]),
            ntohs: new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]),
            ntohl: new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]),
        };
        _cachedAddrLenBuf = Memory.alloc(4);
        _cachedAddrBuf = Memory.alloc(128);
    }
    var getpeername = _cachedSocketFns.getpeername;
    var getsockname = _cachedSocketFns.getsockname;
    var ntohs = _cachedSocketFns.ntohs;
    var ntohl = _cachedSocketFns.ntohl;
    var addrlen = _cachedAddrLenBuf;
    var addr = _cachedAddrBuf;
    var src_dst = ["src", "dst"]
    for (let i = 0; i < src_dst.length; i++) {
        addrlen.writeU32(128)
        if ((src_dst[i] == "src") !== isRead) {
            devlog("src")
            getsockname(sockfd, addr, addrlen)
        }
        else {
            devlog("dst")
            getpeername(sockfd, addr, addrlen)
        }

        var family = addr.readU16();
        const familyName = AddressFamilyMapping[family] || `UNKNOWN`;


        if (family == AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16()) as number
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32()) as number
            message["ss_family"] = "AF_INET"
        } else if (family == AF_INET6) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16()) as number
            message[src_dst[i] + "_addr"] = ""
            var ipv6_addr = addr.add(8)
            for (var offset = 0; offset < 16; offset += 1) {
                message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2)
            }
            if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32()) as number
                message["ss_family"] = "AF_INET"
            }
            else {
                message["ss_family"] = "AF_INET6"
            }
        } else {
            // only uncomment this if you really need to debug this
            //devlog("[-] getPortsAndAddresses resolving error: Only supporting IPv4/6");
            //devlog(`[-] Inspecting fd: ${sockfd}, Address family: ${family} (${familyName})`);
            //throw "Only supporting IPv4/6"
            
            if (!unwantedFDs.has(sockfd)) {
                //devlog(`Skipping unsupported address family: ${family}:${familyName} (fd: ${sockfd})`);
            }
            unwantedFDs.add(sockfd); // Mark this fd as unwanted
            return null;
        }
    }

    return message
}



/**
 * Resolve offset-based addresses for both socket and library offsets.
 * Replaces the duplicated offset resolution block found in every SSL library constructor.
 *
 * @param addresses The addresses dictionary to populate (modified in place)
 * @param moduleName The module name key in the addresses dictionary
 * @param socket_library The socket library name (e.g., libc)
 * @param offsetKey The key in the offsets object for this library (e.g., "gnutls", "wolfssl", "openssl")
 */
export function resolveOffsets(
    addresses: { [key: string]: { [functionName: string]: NativePointer } },
    moduleName: string,
    socket_library: String,
    offsetKey: string
): void {
    // @ts-ignore
    if (offsets == "{OFFSETS}" || offsets[offsetKey] == null) {
        return;
    }

    if ((offsets as any).sockets != null) {
        const socketBaseAddress = getBaseAddress(socket_library);
        for (const method of Object.keys((offsets as any).sockets)) {
            const methodOffset = (offsets as any).sockets[method];
            const methodAddress = ptr(methodOffset.address);
            if (methodOffset.absolute || socketBaseAddress == null) {
                addresses[moduleName][method] = methodAddress;
            } else {
                addresses[moduleName][method] = socketBaseAddress.add(methodAddress);
            }
        }
    }

    const libraryBaseAddress = getBaseAddress(moduleName);
    if (libraryBaseAddress == null) {
        log("Unable to find library base address! Given address values will be interpreted as absolute ones!");
    }

    const libraryOffsets = (offsets as any)[offsetKey];
    for (const method of Object.keys(libraryOffsets)) {
        const methodOffset = libraryOffsets[method];
        const methodAddress = ptr(methodOffset.address);
        if (methodOffset.absolute || libraryBaseAddress == null) {
            addresses[moduleName][method] = methodAddress;
        } else {
            addresses[moduleName][method] = libraryBaseAddress.add(methodAddress);
        }
    }
}


/**
 * Convert a Java byte array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
export function byteArrayToString(byteArray: any) {
    return Array.from(byteArray, function (byte: number) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

// Pre-built lookup table: byte value -> two-char hex string (built once at module load)
const byteToHex: string[] = [];
for (let n = 0; n <= 0xff; ++n) {
    byteToHex.push(n.toString(16).padStart(2, "0"));
}

export function toHexString (byteArray: any) {
    return Array.prototype.map.call(
        new Uint8Array(byteArray),
        n => byteToHex[n]
    ).join("");
  }

/**
 * Convert a Java Reflection array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
export function reflectionByteArrayToString(byteArray: any) {
    var result = ""
    var arrayReflect = Java.use("java.lang.reflect.Array")
    for (var i = 0; i < arrayReflect.getLength(byteArray); i++) {
        result += ('0' + (arrayReflect.get(byteArray, i) & 0xFF).toString(16)).slice(-2);
    }
    return result
}

/**
 * Convert a Java byte arry to number (Big Endian)
 * @param byteArray The array to convert
 * @returns {number} The resulting number
 */
export function byteArrayToNumber(byteArray: any) {
    var value = 0;
    for (var i = 0; i < byteArray.length; i++) {
        value = (value * 256) + (byteArray[i] & 0xFF);
    }
    return value;
}
/**
 * Access an attribute of a Java Class
 * @param Instance The instace you want to access
 * @param fieldName The name of the attribute
 * @returns The value of the attribute of the requested field
 */
export function getAttribute(Instance: JavaWrapper, fieldName: string) {
    var clazz = Java.use("java.lang.Class")
    var field = Java.cast(Instance.getClass(), clazz).getDeclaredField(fieldName)
    field.setAccessible(true)
    return field.get(Instance)
}

/**
 * 
 * @param moduleName String of the name of the module e.g. libssl.so
 * @param symbolName the symbol where we do our check e.g. SSL_write_ex
 * @returns 
 */
export function isSymbolAvailable(moduleName: string, symbolName: string): boolean {
    const resolver = new ApiResolver("module");
    const matches = resolver.enumerateMatches("exports:" + moduleName + "!" + symbolName);
    //devlog(`Matches content: ${matches}`);

    if(matches){
        return matches.length > 0;
    }else{
        return false;
    }

    
}


export function get_hex_string_from_byte_array(keyData: ArrayBuffer | Uint8Array): string{
    return toHexString(keyData).toUpperCase();
}


export function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        devlog("[!] dumping memory at address: "+ptrValue);

        var data = ptrValue.readByteArray(size);
        devlog(hexdump(data));
        return data;
    } catch (error) {
        devlog("Error dumping memory at: " + ptrValue + " - " + error);
        return null;
    }
}

export function calculateZeroBytePercentage(hexStr: string): number {
    if (hexStr.length % 2 !== 0) {
        devlog_error("Hex string length must be even.");
        return -1; // Invalid hex string
    }

    const totalBytes = hexStr.length / 2;
    let zeroCount = 0;

    for (let i = 0; i < hexStr.length; i += 2) {
        if (hexStr.substring(i, i + 2) === "00") {
            zeroCount++;
        }
    }

    return Math.round((zeroCount / totalBytes) * 100);
}