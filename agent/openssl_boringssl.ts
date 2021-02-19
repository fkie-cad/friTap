import { readAddresses, getPortsAndAddresses } from "./shared"
import { log } from "./log"

export function execute() {
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"]
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"]

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    const SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"])
    const SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"])
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"])
    const SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])

    const keylog_callback = new NativeCallback(function (ctxPtr, linePtr: NativePointer) {
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"
        message["keylog"] = linePtr.readCString()
        send(message)
    }, "void", ["pointer", "pointer"])

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
            log("Session is null")
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
                var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, true, addresses)
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
                var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, false, addresses)
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

                SSL_CTX_set_keylog_callback(args[0], keylog_callback)
            }

        })
}