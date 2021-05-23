import { readAddresses, getPortsAndAddresses } from "./shared"
import { log } from "./log"



export function execute(moduleName: string) {

    var socket_library:string =""
    switch(Process.platform){
        case "linux":
            socket_library = "libc"
            break
        case "windows":
            socket_library = "WS2_32.dll"
            break
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            log(`Platform "${Process.platform} currently not supported!`)
    }

    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"]
    
    //? Just in case darwin methods are different to linux and windows ones
    if(socket_library === "libc" || socket_library === "WS2_32.dll"){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    const gnutls_transport_get_int = new NativeFunction(addresses["gnutls_transport_get_int"], "int", ["pointer"])
    const gnutls_session_get_id = new NativeFunction(addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"])
    const gnutls_session_set_keylog_function = new NativeFunction(addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"])
    const gnutls_session_get_random = new NativeFunction(addresses["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"])

    const keylog_callback = new NativeCallback(function (session: NativePointer, label: NativePointer, secret: NativePointer) {
        var message: { [key: string]: string | number | null } = {}
        message["contentType"] = "keylog"

        var secret_len = secret.add(Process.pointerSize).readUInt()
        var secret_str = ""
        var p = secret.readPointer()

        for (var i = 0; i < secret_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to secret_str.

            secret_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        var server_random_ptr = Memory.alloc(Process.pointerSize + 4)
        var client_random_ptr = Memory.alloc(Process.pointerSize + 4)
        gnutls_session_get_random(session, client_random_ptr, server_random_ptr)
        var client_random_str = ""
        var client_random_len = 32
        p = client_random_ptr.readPointer()
        for (i = 0; i < client_random_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to client_random_str.

            client_random_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        message["keylog"] = label.readCString() + " " + client_random_str + " " + secret_str
        send(message)
        return 0
    }, "int", ["pointer", "pointer", "pointer"])

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

    Interceptor.attach(addresses["gnutls_init"],
        {
            onEnter: function (args: any) {
                this.session = args[0]
            },
            onLeave: function (retval: any) {
                gnutls_session_set_keylog_function(this.session.readPointer(), keylog_callback)

            }
        })

}
