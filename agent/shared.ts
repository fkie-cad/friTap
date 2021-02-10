import { log } from "./log"

/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */


//GLOBALS
const AF_INET = 2
const AF_INET6 = 10

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
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method
            }
            else {
                send("Found " + library_name + "!" + method)
            }
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method
            }
            else if (matches.length != 1) {
                // Sometimes Frida returns duplicates.
                var address = null
                var s = ""
                var duplicates_only = true
                for (var k = 0; k < matches.length; k++) {
                    if (s.length != 0) {
                        s += ", "
                    }
                    s += matches[k].name + "@" + matches[k].address
                    if (address == null) {
                        address = matches[k].address
                    }
                    else if (!address.equals(matches[k].address)) {
                        duplicates_only = false
                    }
                }
                if (!duplicates_only) {
                    throw "More than one match found for " + library_name + "!" + method + ": " +
                    s
                }
            }
            addresses[method.toString()] = matches[0].address
        })
    }
    return addresses
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
            getsockname(sockfd, addr, addrlen)
        }
        else {
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