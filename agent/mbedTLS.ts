import { readAddresses, getPortsAndAddresses, getSocketLibrary, getModuleNames } from "./shared"

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
        },
        onLeave: function(retval: any){
            retval |= 0 // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return
            }
            
            var data = this.buffer.readByteArray(retval);

            var message: { [key: string]: string | number } = {}
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
            message["ssl_session_id"] = 10
            send(message, data)
                    
            
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

            var message: { [key: string]: string | number } = {}
            message["ss_family"] = "AF_INET"
            message["src_port"] = 444;
            message["src_addr"] = 222;
            message["dst_port"] = 443;
            message["dst_addr"] = 222;
            message["function"] = "DecryptMessage"
            message["contentType"] = "datalog"
            message["ssl_session_id"] = 10
            send(message, data)
        }
    });


}