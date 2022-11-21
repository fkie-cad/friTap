import { log, devlog } from "../util/log.js"
import { AF_INET, AF_INET6 } from "./shared_structures.js"


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

export function ssl_library_loader(plattform_name: string, module_library_mapping: { [key: string]: Array<[any, (moduleName: string)=>void]> }, moduleNames: Array<string> , plattform_os: string): void{
    for(let map of module_library_mapping[plattform_name]){
        let regex = map[0]
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
                    
                    func(module) // on some Android Apps we encounterd the problem of multiple SSL libraries but only one is used for the SSL encryption/decryption
                }catch (error) {
                    log(`error: skipping module ${module}`)
                    // when we enable the logging of devlogs we can print the error message as well for further improving this part
                    devlog("Loader error: "+error)
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }
                
            } 
        }
    }

}


//TODO: 
export function getSocketLibrary(){
    var moduleNames: Array<String> = getModuleNames()
    var socket_library_name = ""
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

/**
 * Read the addresses for the given methods from the given modules
 * @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
 * @return {{[key: string]: NativePointer }} A string indexed list of NativePointers, which point to the respective methods
 */
export function readAddresses(library_method_mapping: { [key: string]: Array<String> }): { [key: string]: NativePointer } {
    var resolver = new ApiResolver("module")
    var addresses: { [key: string]: NativePointer } = {}
    for (let library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method)
            var match_number = 0;
            var method_name = method.toString();

            if(method_name.endsWith("*")){ // this is for the temporary iOS bug using fridas ApiResolver
                method_name = method_name.substring(0,method_name.length-1)
            }

            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method
            }
            else if (matches.length == 1){
                
                devlog("Found " + method + " " + matches[0].address)
            }else{
                // Sometimes Frida returns duplicates or it finds more than one result.
                for (var k = 0; k < matches.length; k++) {
                    if(matches[k].name.endsWith(method_name)){
                        match_number = k;
                        devlog("Found " + method + " " + matches[match_number].address)
                        break;
                    }
                   
                }
     
            }
            addresses[method_name] = matches[match_number].address;
        })
    }
    return addresses
}



/**
 * Returns the base address of a given module
 * @param {string} moduleName Name of module to return base address from
 * @returns
 */
 export function getBaseAddress(moduleName: String): NativePointer | null {
    console.log("Module to find:",moduleName)
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
export function getPortsAndAddresses(sockfd: number, isRead: boolean, methodAddresses: { [key: string]: NativePointer }): { [key: string]: string | number } {

    var getpeername = new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"])
    var getsockname = new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"])
    var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"])
    var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"])

    var message: { [key: string]: string | number } = {}
    var addrlen = Memory.alloc(4)
    var addr = Memory.alloc(128)
    var src_dst = ["src", "dst"]
    for (var i = 0; i < src_dst.length; i++) {
        addrlen.writeU32(128)
        if ((src_dst[i] == "src") !== isRead) {
            devlog("src")
            getsockname(sockfd, addr, addrlen)
        }
        else {
            devlog("dst")
            getpeername(sockfd, addr, addrlen)
        }
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
            devlog("[-] getPortsAndAddresses resolving error:"+addr.readU16())
            throw "Only supporting IPv4/6"
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