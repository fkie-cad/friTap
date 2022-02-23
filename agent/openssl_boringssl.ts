import { readAddresses, getPortsAndAddresses } from "./shared"
import { log } from "./log"

/**
 * 
 * ToDO
 *  We need to find a way to calculate the offsets in a automated manner.
 */

export function execute(moduleName:string) {
    
    var socket_library:string =""
    switch(Process.platform){
        case "linux":
            socket_library = "libc"
            break
        case "windows":
            socket_library = "WS2_32.dll"
            break
        case "darwin":
            socket_library = "libSystem.B.dylib"
            break;
        default:
            log(`Platform "${Process.platform} currently not supported!`)
    }
    
    var library_method_mapping: { [key: string]: Array<String> } = {}
    if(ObjC.available){
        // the follwoing functions are avaible SSL_read SSL_write SSL_new SSL_get_session SSL_SESSION_get_id SSL_SESSION_get_id

        /*
        dont now what these functions are doingß
        BIO_write/read, boringssl_session_read/write BIO_get_fd

         */

        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"] // currently those
    }else{
        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }
    
    
    // the socket methods are in all systems the same
    
    
    



    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    
    const SSL_get_fd = ObjC.available ? new NativeFunction(addresses["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"])
    const SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"])
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"])
    
	//SSL_CTX_set_keylog_callback not exported by default on windows. 
	//Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
	
    const SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])

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
                if (!ObjC.available){
                var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, true, addresses)
                message["ssl_session_id"] = getSslSessionId(args[0])
                /* var my_Bio = args[0] as NativePointer
                my_Bio.readPointer*/
                message["function"] = "SSL_read"
                this.message = message
                this.buf = args[1]
                }  // this is a temporary workaround for the fd problem on iOS
            },
            onLeave: function (retval: any) {
                if (!ObjC.available){
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }
                this.message["contentType"] = "datalog"
                send(this.message, this.buf.readByteArray(retval))
                }  // this is a temporary workaround for the fd problem on iOS
            }
        })
    Interceptor.attach(addresses["SSL_write"],
        {
            onEnter: function (args: any) {
                if (!ObjC.available){
                var message = getPortsAndAddresses(SSL_get_fd(args[0]) as number, false, addresses)
                message["ssl_session_id"] = getSslSessionId(args[0])
                message["function"] = "SSL_write"
                message["contentType"] = "datalog"
                send(message, args[1].readByteArray(parseInt(args[2])))
                } // this is a temporary workaround for the fd problem on iOS
            },
            onLeave: function (retval: any) {
            }
        })
		
		
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            var CALLBACK_OFFSET = 0x2A8;

            var foundationNumber = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber')?.readDouble();
            if(foundationNumber == undefined){
                CALLBACK_OFFSET = 0x2A8;
            }else if (foundationNumber >= 1751.108) {
                CALLBACK_OFFSET = 0x2B8; // >= iOS 14.x 
            }
            Interceptor.attach(addresses["SSL_CTX_set_info_callback"], {
              onEnter: function (args : any) {
                log("found boringSSL TLS key");
                ptr(args[0]).add(CALLBACK_OFFSET).writePointer(keylog_callback);
              }
            });
          
          }

    Interceptor.attach(addresses["SSL_new"],
        {
            onEnter: function (args: any) {
                if(!ObjC.available){
                    SSL_CTX_set_keylog_callback(args[0], keylog_callback)
                }
            }

        })
}