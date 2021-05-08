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
    library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays"]
    
    //? Just in case darwin methods are different to linux and windows ones
    if(socket_library === "libc" || socket_library === "WS2_32.dll"){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    const wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"])
    const wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"])
    //const wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])
    //const wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "uint"])
    const wolfSSL_KeepArrays = new NativeFunction(addresses["wolfSSL_KeepArrays"], "void", ["pointer"])

    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */

    function getSslSessionId(ssl: NativePointer) {
        var session = wolfSSL_get_session(ssl) as NativePointer
        if (session.isNull()) {
            log("Session is null")
            return 0
        }
        var p = session.add(8)
        var len = 32 // This comes from internals.h. It is untested!
        var session_id = ""
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return session_id
    }

    /**
       * Get the masterKey of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the masterKey of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getMasterKey(wolfSslPtr: NativePointer) {
        var session = wolfSSL_get_session(wolfSslPtr)
        var nullPtr = ptr(0)
        var masterKeySize = wolfSSL_SESSION_get_master_key(session, nullPtr, 0) as number
        var buffer = Memory.alloc(masterKeySize)
        wolfSSL_SESSION_get_master_key(session, buffer, masterKeySize)

        var masterKey = ""
        for (var i = 0; i < masterKeySize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            masterKey +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return masterKey;
    }

    /**
       * Get the clientRandom of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the clientRandom of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getClientRandom(wolfSslPtr: NativePointer) {
        var nullPtr = ptr(0)
        var clientRandomSize = wolfSSL_get_client_random(wolfSslPtr, nullPtr, 0) as number
        var buffer = Memory.alloc(clientRandomSize)
        //console.log(wolfSSL_get_client_random(wolfSslPtr, buffer, clientRandomSize))

        var clientRandom = ""
        for (var i = 0; i < clientRandomSize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            clientRandom +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return clientRandom;
    }


    Interceptor.attach(addresses["wolfSSL_read"],
        {
            onEnter: function (args: any) {
                var message = getPortsAndAddresses(wolfSSL_get_fd(args[0]) as number, true, addresses)
                message["ssl_session_id"] = getSslSessionId(args[0])
                message["function"] = "wolfSSL_read"
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
    Interceptor.attach(addresses["wolfSSL_write"],
        {
            onEnter: function (args: any) {
                var message = getPortsAndAddresses(wolfSSL_get_fd(args[0]) as number, false, addresses)
                message["ssl_session_id"] = getSslSessionId(args[0])
                message["function"] = "wolfSSL_write"
                message["contentType"] = "datalog"
                send(message, args[1].readByteArray(parseInt(args[2])))
            },
            onLeave: function (retval: any) {
            }
        })


    Interceptor.attach(addresses["wolfSSL_connect"],
        {
            onEnter: function (args: any) {

                this.wolfSslPtr = args[0]
                wolfSSL_KeepArrays(this.wolfSslPtr)
            },
            onLeave: function (retval: any) {
                var clientRandom = getClientRandom(this.wolfSslPtr)
                var masterKey = getMasterKey(this.wolfSslPtr)
                var message: { [key: string]: any } = {}
                message["contentType"] = "keylog"
                message["keylog"] = "CLIENT_RANDOM " + clientRandom + " " + masterKey
                send(message)

            }
        })


}