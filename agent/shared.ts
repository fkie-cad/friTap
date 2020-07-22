/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries
 */

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