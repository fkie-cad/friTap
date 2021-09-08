import { readAddresses, getPortsAndAddresses, getSocketLibrary, getModuleNames } from "./shared"


var getSocketDescriptor = function (sslcontext: NativePointer){
    console.log(`Pointersize: ${Process.pointerSize}`)
    var bioOffset = 48;//Documentation not valid (8 Bytes less)Process.pointerSize + 4 * 6 +  Process.pointerSize *3
    console.log(sslcontext.readByteArray(100))
    var p_bio = sslcontext.add(bioOffset).readPointer()
    console.log(`Pointer BIO: ${p_bio}`)
    var bio_value = p_bio.readS32();
    console.log(`BIO Value: ${bio_value}`)
    return bio_value
    //console.log(p_bio)
}

var getSessionId = function(sslcontext: NativePointer){
    
    var offsetSession = Process.pointerSize * 7 + 4 +4 + 4+ +4 +4 + 4
    var sessionPointer = sslcontext.add(offsetSession).readPointer();
    var offsetSessionId = 8 + 4 + 4 +4 
    var offsetSessionLength = 8 + 4 + 4
    var idLength = sessionPointer.add(offsetSessionLength).readU32();
    
    var idData = sessionPointer.add(offsetSessionId)
    var session_id = ""
    
    for (var byteCounter = 0; byteCounter < idLength; byteCounter++){
        
        session_id = `${session_id}${idData.add(byteCounter).readU8().toString(16).toUpperCase()}`
    }

    return session_id
}

export function execute(moduleName:string) {

    var socket_library = getSocketLibrary() 
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping[`*${moduleName}*`] = ["mbedtls_ssl_read", "mbedtls_ssl_write"]

    //? Just in case darwin methods are different to linux and windows ones
    if(Process.platform === "linux" || Process.platform === "windows" ){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping);

    //https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
    Interceptor.attach(addresses["mbedtls_ssl_read"], {
        onEnter: function(args){
            this.buffer = args[1];
            this.len = args[2];
            this.sslContext = args[0];

            var message = getPortsAndAddresses(getSocketDescriptor(args[0]) as number, true, addresses)
            message["function"] = "mbedtls_ssl_read"
            this.message = message
        },
        onLeave: function(retval: any){
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            
            var data = this.buffer.readByteArray(retval);
            this.message["contentType"] = "datalog"
            send(this.message, data)
            
            /* var message: { [key: string]: string | number } = {}
            //TODO:Following options could be obtained by having a look at the bio attribute.
            //There we can find the fd of the socket
            message["ss_family"] = "AF_INET"
            message["src_port"] = 444;
            message["src_addr"] = 222;
            message["dst_port"] = 443;
            message["dst_addr"] = 222;
            message["function"] = "DecryptMessage"
            message["contentType"] = "datalog"
            //Obtaining the session id seems to be hard. Parsing the ssl_context object. The session
            //object holds the id in the form of a char array?
            //https://tls.mbed.org/api/structmbedtls__ssl__session.html
            message["ssl_session_id"] = getSessionId(this.sslContext);
            send(message, data) */
                    
            
        }
        
    });

    //https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
    Interceptor.attach(addresses["mbedtls_ssl_write"], {
        
        onEnter: function(args){
            var buffer = args[1];
            var len: any = args[2];
            len |= 0 // Cast retval to 32-bit integer.
            if (len <= 0) {
                return
            }
            var data = buffer.readByteArray(len);
            var message = getPortsAndAddresses(getSocketDescriptor(args[0]) as number, false, addresses)
            message["ssl_session_id"] = getSessionId(args[0])
            message["function"] = "mbedtls_ssl_write"
            message["contentType"] = "datalog"
            send(message, data)
            /* var message: { [key: string]: string | number } = {}
            message["ss_family"] = "AF_INET"
            message["src_port"] = 444;
            message["src_addr"] = 222;
            message["dst_port"] = 443;
            message["dst_addr"] = 222;
            message["function"] = "DecryptMessage"
            message["contentType"] = "datalog"
            message["ssl_session_id"] = 10
            send(message, data) */
        }
    });


}