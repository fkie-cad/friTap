import { off } from "process"

const AF_INET = 2
const AF_INET6 = 10


var modules = Process.enumerateModules()

var library_method_mapping: { [key: string]: Array<String> } = {}
library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"]
library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"]
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
var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"])
var SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"])
var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"])
var getpeername = new NativeFunction(addresses["getpeername"], "int", ["int", "pointer", "pointer"])
var getsockname = new NativeFunction(addresses["getsockname"], "int", ["int", "pointer", "pointer"])
var ntohs = new NativeFunction(addresses["ntohs"], "uint16", ["uint16"])
var ntohl = new NativeFunction(addresses["ntohl"], "uint32", ["uint32"])
var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])
var SSL_get_SSL_CTX = new NativeFunction(addresses["SSL_get_SSL_CTX"], "pointer", ["pointer"])

/**
   * Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
   * "dst_port".
   * @param {int} sockfd The file descriptor of the socket to inspect.
   * @param {boolean} isRead If true, the context is an SSL_read call. If
   *     false, the context is an SSL_write call.
   * @return {dict} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
   *     and "dst_port".
   */
function getPortsAndAddresses(sockfd: number, isRead: boolean) {
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
            message["ss_family"] = "AF_INET6"
        } else {
            throw "Only supporting IPv4/6"
        }
    }
    return message
}

/**
   * Get the session_id of SSL object and return it as a hex string.
   * @param {!NativePointer} ssl A pointer to an SSL object.
   * @return {dict} A string representing the session_id of the SSL object's
   *     SSL_SESSION. For example,
   *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
   */
function getSslSessionId(ssl: NativePointer) {
    var session = SSL_get_session(ssl) as NativePointer
    if (session.isNull()) {
        console.log("Session is null")
        return 0
    }
    var len_pointer = Memory.alloc(4)
    var p = SSL_SESSION_get_id(session, len_pointer) as NativePointer
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

Interceptor.attach(addresses["SSL_read"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, true)
            message["ssl_session_id"] = getSslSessionId(args[0])
            message["function"] = "SSL_read"
            this.message = message
            this.buf = args[1]
        },
        onLeave: function (retval: any) {
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            this.message["contentType"] = "datalog"
            send(this.message, this.buf.readByteArray(retval))
        }
    })
Interceptor.attach(addresses["SSL_write"],
    {
        onEnter: function (args: any) {
            var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, false)
            message["ssl_session_id"] = getSslSessionId(args[0])
            message["function"] = "SSL_write"
            message["contentType"] = "datalog"
            send(message, args[1].readByteArray(parseInt(args[2])))
        },
        onLeave: function (retval: any) {
        }
    })
Interceptor.attach(addresses["SSL_new"],
    {
        onEnter: function (args: any) {
            var keylog_callback = new NativeCallback(function (ctxPtr, linePtr: NativePointer) {
                var message: { [key: string]: string | number | null } = {}
                message["contentType"] = "keylog"
                message["keylog"] = linePtr.readCString()
                send(message)
            }, "void", ["pointer", "pointer"])
            SSL_CTX_set_keylog_callback(args[0], keylog_callback)
        }

    })