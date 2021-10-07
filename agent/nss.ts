import { readAddresses, getPortsAndAddresses, getSocketLibrary, getModuleNames } from "./shared"
import { log } from "./log"




//GLOBALS
const AF_INET = 2
const AF_INET6 = 100


export function execute(moduleName:string) {

    var socket_library = getSocketLibrary()    

    
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_SetEnv", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName"]
    library_method_mapping[Process.platform === "linux" ? "*libssl*.so" : "*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID"]

    //? Just in case darwin methods are different to linux and windows ones
    if(Process.platform === "linux" || Process.platform === "windows" ){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    const SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"])
    
    const getsockname = new NativeFunction(addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);



    /**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {pointer} sockfd The file descriptor of the socket to inspect as PRFileDesc.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".
*/
    function getPortsAndAddressesFromNSS(sockfd: NativePointer, isRead: boolean, methodAddresses: { [key: string]: NativePointer }): { [key: string]: string | number } {
        var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"])
        var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"])
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"])
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"])

        var message: { [key: string]: string | number } = {}
       

        //var prNetAddr = Memory.alloc(Process.pointerSize)
        var addrlen = Memory.alloc(4)
        var addr = Memory.alloc(128)
        var src_dst = ["src", "dst"]
        for (var i = 0; i < src_dst.length; i++) {
            addrlen.writeU32(128)
            if ((src_dst[i] == "src") !== isRead) {
                getsockname(sockfd, addr)
            }
            else {
                getpeername(sockfd, addr)
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
                //FIXME: Sometimes addr.readU16() will be 0, thus this error will be thrown. Why isnt this the case on linux? Something windows specific?
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
    function getSslSessionId(sslSessionIdSECItem: NativePointer) {
        if (sslSessionIdSECItem == null) {
            log("Session is null")
            return 0
        }
        var session_id = ""
        var session_id_ptr = sslSessionIdSECItem.add(8).readPointer()
        var len_tmp = sslSessionIdSECItem.add(16).readU32()
        var len = (len_tmp > 32) ? 32 : len_tmp;
        var session_id = ""
        
        for (var i = 8; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }



        return session_id
    }

    Interceptor.attach(addresses["PR_Read"],
        {
            onEnter: function (args: any) {
                this.fd = ptr(args[0])
                this.buf = ptr(args[1])
            },
            onLeave: function (retval: any) {
                if (retval.toInt32() <= 0) {
                        return
                }                    
                
                var addr = Memory.alloc(128);
               

                if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                    var message = getPortsAndAddressesFromNSS(this.fd as NativePointer, true, addresses)
                    
                    message["ssl_session_id"] = getSslSessionId(this.fd)
                    message["function"] = "NSS_read"
                    this.message = message

                    this.message["contentType"] = "datalog"
                    var data = this.buf.readByteArray((new Uint32Array([retval]))[0])
                    send(this.message, data)
                }else{
                    var temp = this.buf.readByteArray((new Uint32Array([retval]))[0])
                    console.log(temp)
                }
                
            }
        })
    Interceptor.attach(addresses["PR_Write"],
        {
            onEnter: function (args: any) {
                var addr = Memory.alloc(128); 

                getsockname(args[0], addr);
                
                if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                    var message = getPortsAndAddressesFromNSS(args[0] as NativePointer, false, addresses)
                    message["ssl_session_id"] = getSslSessionId(args[0])
                    message["function"] = "NSS_write"
                    message["contentType"] = "datalog"
                    send(message, args[1].readByteArray(parseInt(args[2])))
                }
                
            }
        })
    
 
    Interceptor.attach(addresses["SSL_ImportFD"],
        {
            onEnter: function (args: any) {
                //TODO: Keylogfile path must be set according to -k parameter
                var keylog = Memory.allocUtf8String("SSLKEYLOGFILE=keylogfile")
                SET_NSS_ENV(keylog)
            }

        })
}