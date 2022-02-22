import { readAddresses, getPortsAndAddresses, toHexString } from "./shared"
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
    library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays", "wolfSSL_SESSION_get_master_key", "wolfSSL_get_client_random", "wolfSSL_get_server_random"]
    
    //? Just in case darwin methods are different to linux and windows ones
    if(socket_library === "libc" || socket_library === "WS2_32.dll"){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    const wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"])
    const wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"])
    const wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"],"int", ["pointer", "pointer", "int"] )
    const wolfSSL_get_server_random = new NativeFunction(addresses["wolfSSL_get_server_random"],"int", ["pointer", "pointer", "int"] )

    //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
    const wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])
    
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

    Interceptor.attach(addresses["wolfSSL_read"],
        {
            onEnter: function (args: any) {
                
                var message = getPortsAndAddresses(wolfSSL_get_fd(args[0]) as number, true, addresses)
                
                message["function"] = "wolfSSL_read"
                message["ssl_session_id"] = getSslSessionId(args[0])
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


    Interceptor.attach(addresses["wolfSSL_connect"],{
        onEnter: function(args: any){
            this.ssl = args[0]
        },
        onLeave: function(retval: any){
            this.session = wolfSSL_get_session(this.ssl) as NativePointer

            var keysString = "";
            
            //https://www.wolfssl.com/doxygen/group__Setup.html#ga927e37dc840c228532efa0aa9bbec451
            var requiredClientRandomLength = wolfSSL_get_client_random(this.session, NULL, 0) as number
            
            var clientBuffer = Memory.alloc(requiredClientRandomLength)
            wolfSSL_get_client_random(this.ssl, clientBuffer, requiredClientRandomLength)
            var clientBytes = clientBuffer.readByteArray(requiredClientRandomLength)
            keysString = `${keysString}CLIENT_RANDOM: ${toHexString(clientBytes)}\n`
            
            //https://www.wolfssl.com/doxygen/group__Setup.html#ga987035fc600ba9e3b02e2b2718a16a6c
            var requiredServerRandomLength = wolfSSL_get_server_random(this.session, NULL, 0) as number
            var serverBuffer = Memory.alloc(requiredServerRandomLength)
            wolfSSL_get_server_random(this.ssl, serverBuffer, requiredServerRandomLength)
            var serverBytes = serverBuffer.readByteArray(requiredServerRandomLength)
            keysString = `${keysString}SERVER_RANDOM: ${toHexString(serverBytes)}\n`
            
            //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
            var requiredMasterKeyLength = wolfSSL_SESSION_get_master_key(this.session, NULL, 0) as number
            var masterBuffer = Memory.alloc(requiredMasterKeyLength)
            wolfSSL_SESSION_get_master_key(this.session, masterBuffer, requiredMasterKeyLength)
            var masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength)
            keysString = `${keysString}MASTER_KEY: ${toHexString(masterBytes)}\n`

            
            var message: { [key: string]: string | number | null } = {}
            message["contentType"] = "keylog"
            message["keylog"] = keysString
            send(message)
            
        }
    })
}