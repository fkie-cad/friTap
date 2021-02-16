import { readAddresses, getPortsAndAddresses } from "./shared"
import { log } from "./log"

export function execute() {
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping["*libgnutls*"] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id"]
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"]

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    var gnutls_transport_get_int = new NativeFunction(addresses["gnutls_transport_get_int"], "int", ["pointer"])
    var gnutls_session_get_id = new NativeFunction(addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"])
    var gnutls_session_set_keylog_function = new NativeFunction(addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"])


    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(session: NativePointer) {

        var len_pointer = Memory.alloc(4)
        var err = gnutls_session_get_id(session, NULL, len_pointer)
        if (err != 0) {
            return ""
        }
        var len = len_pointer.readU32()
        var p = Memory.alloc(len)
        err = gnutls_session_get_id(session, p, len_pointer)
        if (err != 0) {
            return ""
        }
        var session_id = ""
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return session_id
    }

    Interceptor.attach(addresses["gnutls_record_recv"],
        {
            onEnter: function (args: any) {
                var message = getPortsAndAddresses(gnutls_transport_get_int(args[0]) as number, true, addresses)
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
    Interceptor.attach(addresses["gnutls_record_send"],
        {
            onEnter: function (args: any) {
                var message = getPortsAndAddresses(gnutls_transport_get_int(args[0]) as number, false, addresses)
                message["ssl_session_id"] = getSslSessionId(args[0])
                message["function"] = "SSL_write"
                message["contentType"] = "datalog"
                send(message, args[1].readByteArray(parseInt(args[2])))
            },
            onLeave: function (retval: any) {
            }
        })

}