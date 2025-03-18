import { log, devlog, devlog_error } from "../util/log.js";
import { AF_INET, AF_INET6, AddressFamilyMapping, unwantedFDs, ModuleHookingType } from "./shared_structures.js";


function wait_for_library_loaded(module_name: string){
    let timeout_library = 5;
    let module_adress = Module.findBaseAddress(module_name);
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

export function ssl_library_loader(plattform_name: string, module_library_mapping: { [key: string]: Array<[any, ModuleHookingType]> }, moduleNames: Array<string> , plattform_os: string, is_base_hook: boolean): void{
    for(let map of module_library_mapping[plattform_name]){
        let regex = new RegExp(map[0])
        let func = map[1]
        for(let module of moduleNames){
            if (regex.test(module)){
                try{
                    log(`${module} found & will be hooked on ${plattform_os}!`)
                    try {
                        Module.ensureInitialized(module);
                    }catch(error){
                        wait_for_library_loaded(module);
                    }
                    
                    // on some Android Apps we encounterd the problem of multiple SSL libraries but only one is used for the SSL encryption/decryption
                    func(module, is_base_hook); 
                    
                }catch (error) {

                    if(checkNumberOfExports(module) > 3){
                        devlog_error(`error: skipping module ${module}`)
                        // when we enable the logging of devlogs we can print the error message as well for further improving this part
                        devlog_error("Loader error: "+error)
                        //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                    }
                }
                
            } 
        }
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

export function hasMoreThanFiveExports(moduleName: string): boolean {
    // Get the target module
    const targetModule = Process.getModuleByName(moduleName);
    
    // Return false if module doesn't exist
    if (!targetModule) {
        devlog(`Module ${moduleName} not found`);
        return false;
    }

    try {
        // Enumerate exports from the module
        const exports = targetModule.enumerateExports();
        
        // Return true if there are more than 5 exports
        return exports.length > 5;
    } catch (error) {
        devlog(`Error enumerating exports for ${moduleName}:`+ error);
        return false;
    }
}

export function readAddresses(moduleName: string, library_method_mapping: { [key: string]: Array<string> }): { [library_name: string]: { [functionName: string]: NativePointer } } {
    const resolver = new ApiResolver("module");
    const addresses: { [library_name: string]: { [functionName: string]: NativePointer } } = {};

    // Initialize addresses[moduleName] as an empty object if not already initialized
    if (!addresses[moduleName]) {
        addresses[moduleName] = {};
    }

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
                throw "Could not find " + library_name + "!" + method;
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
 * Read the addresses for the given methods from the given modules
 * @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
 * @param is_base_hook a boolean value to indicate if this hooks are done on the start or during dynamic library loading
 * @return {{[key: string]: { [functionName: string]: NativePointer } }} A string indexed list of NativePointers, which point to the respective methods
 */
 export function readAddresses2(moduleName: string, library_method_mapping: { [key: string]: Array<string> }): { [library_name: string]: { [functionName: string]: NativePointer } } {
    var resolver = new ApiResolver("module");
    var addresses: { [library_name: string]: { [functionName: string]: NativePointer } } = {};
    

    // Initialize addresses[library_name] as an empty object if not already initialized
    if (!addresses[moduleName]) {
        addresses[moduleName] = {};
    }

    for (let library_name in library_method_mapping) {

        library_method_mapping[library_name].forEach(function (method) {
            var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);
            var match_number = 0;
            var method_name = method.toString();

            if (method_name.endsWith("*")) { // this is for the temporary iOS bug using Frida's ApiResolver
                method_name = method_name.substring(0, method_name.length - 1);
            }

            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            } else if (matches.length == 1) {
                devlog("Found " + method + " " + matches[0].address);
            } else {
                // Sometimes Frida returns duplicates or it finds more than one result.
                for (var k = 0; k < matches.length; k++) {
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
    const modules = Process.enumerateModules()

    for(const module of modules){
        if(module.name == moduleName){
            return module.base;
        }
    }

    return null;
}


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
        message["src" + "_addr"] = "127.0.0.1"
        message["dst" + "_port"] = 2345
        message["dst" + "_addr"] = "127.0.0.1"
        message["ss_family"] = "AF_INET"

        return message
    }

    // Check if this fd is already marked as unwanted
    if (unwantedFDs.has(sockfd)) {
        return null; // Skip further processing
    }

    var getpeername = new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"])
    var getsockname = new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"])
    var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"])
    var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"])

    var addrlen = Memory.alloc(4)
    var addr = Memory.alloc(128)
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


        if (addr.readU16() == AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16()) as number
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32()) as number
            message["ss_family"] = "AF_INET"
        } else if (addr.readU16() == AF_INET6) {
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
 * Convert a Java byte array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
export function byteArrayToString(byteArray: any) {
    return Array.from(byteArray, function (byte: number) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

export function toHexString (byteArray: any) {
    const byteToHex: any = [];

    for (let n = 0; n <= 0xff; ++n){
        const hexOctet = n.toString(16).padStart(2, "0");
        byteToHex.push(hexOctet);
    }
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
export function getAttribute(Instance: Java.Wrapper, fieldName: string) {
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


// Wrapper function to ensure all execute functions conform to the required signature
export function invokeHookingFunction(func: (moduleName: string, is_base_hook: boolean) => void): (moduleName: string, is_base_hook: boolean) => void {
    return (moduleName: string, is_base_hook: boolean) => {
        func(moduleName, is_base_hook);
    };
}


export function get_hex_string_from_byte_array(keyData: ArrayBuffer | Uint8Array): string{
    return Array
        .from(new Uint8Array(keyData)) // Convert byte array to Uint8Array and then to Array
        .map(byte => byte.toString(16).padStart(2, '0').toUpperCase()) // Convert each byte to a 2-digit hex string
        .join(''); // Join all the hex values with a space
}


export function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        console.log("[!] dumping memory at address: "+ptrValue);
        //@ts-ignore
        var data = Memory.readByteArray(ptrValue, size);
        console.log(hexdump(data));
        return data;
        // console.log(hexdump(data, { offset: 0, length: size, header: true, ansi: true }));
    } catch (error) {
        console.log("Error dumping memory at: " + ptrValue + " - " + error);
        console.log("\n")
        return null;
    }
}