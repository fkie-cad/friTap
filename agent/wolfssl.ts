import { readAddresses, getPortsAndAddresses } from "./shared"
import { log } from "./log"

export function execute() {
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping["*libwolfssl*"] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_SESSION_get_master_key"] //, "wolfSSL_SESSION_get_id", "wolfSSL_new", "wolfSSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"]
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"]

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    var wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"])
    var wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"])
    var wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])

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
        log("Size of master key: " + masterKeySize)
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
        //get handle to the Arrays struct
        var Arrays = wolfSslPtr.add(2).readPointer()
        //Check if wolfSSL_get_psk_identity is defined. By this, we can see if NO_PSK has been defined.
        //The structure of the Arrays struct depends on this
        var pskEnabled = (null != Module.findExportByName("libwolfssl.so", "wolfSSL_get_psk_identity"))
        //Check if wolfSSL_connect_TLSv13 or wolfSSL_accept_TLSv13 are defined. By this, we can see if TLS_13 has been defined.
        //The structure of the Arrays struct depends on this
        var tls13Enbaled = (null != Module.findExportByName("libwolfssl.so", "wolfSSL_connect_TLSv13 ")) || (null != Module.findExportByName("libwolfssl.so", "wolfSSL_accept_TLSv13 "))
        log("Psk: " + pskEnabled + " TLS13: " + tls13Enbaled)
        var clientRandomPtr: NativePointer
        if (!pskEnabled) {
            clientRandomPtr = Arrays.add(5)
        } else {
            log(String(Arrays.add(2).readU32()))
            if (tls13Enbaled) {
                clientRandomPtr = Arrays.add(5).add(1).add(257).add(257).add(64)
            }
            else {
                clientRandomPtr = Arrays.add(5).add(1).add(129).add(129).add(64)
            }
        }
        var clientRandom = ""
        for (var i = 0; i < 32; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            clientRandom +=
                ("0" + clientRandomPtr.add(i).readU8().toString(16).toUpperCase()).substr(-2)
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
            },
            onLeave: function (retval: any) {
                //var clientRandom = getClientRandom(this.wolfSslPtr)
                var masterKey = getMasterKey(this.wolfSslPtr)
                //log("Client Random: " + clientRandom)
                log("master key: " + masterKey)
            }
        })


}