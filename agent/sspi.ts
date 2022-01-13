import { readAddresses, getPortsAndAddresses, getSocketLibrary, getModuleNames } from "./shared"
import { log } from "./log"
/*
SspiCli.dll!DecryptMessage called!
ncrypt.dll!SslDecryptPacket called!
bcrypt.dll!BCryptDecrypt called!
*/

export function execute(moduleName:string) {

    var socket_library = getSocketLibrary()    

    
    var library_method_mapping: { [key: string]: Array<String> } = {}
    library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage"]

    //? Just in case darwin methods are different to linux and windows ones
    if(Process.platform === "linux" || Process.platform === "windows" ){
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    }else{
        //TODO: Darwin implementation pending
    }

    var addresses: { [key: string]: NativePointer } = readAddresses(library_method_mapping)

    Interceptor.attach(addresses["DecryptMessage"], {
        onEnter: function(args){
            this.pMessage = args[1];
        },
        onLeave: function(){
            this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
            this.pBuffers = this.pMessage.add(8).readPointer() //PSecBuffer  pBuffers (Pointer to array of secBuffers)
    
            //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
            //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
            //--> Bytes to read: cBuffers + 16 Bytes
            this.secBuffers = [] //Addresses of all secBuffers
            for (let i = 0; i < this.cBuffers; i++){
                var secBuffer = this.pBuffers.add(i * 16)
                this.secBuffers.push(secBuffer);
            }
                    
                    
            for (let i = 0; i < this.secBuffers.length; i++){
                var size = this.secBuffers[i].add(0).readULong();
                var type = this.secBuffers[i].add(4).readULong();
                var bufferPointer = this.secBuffers[i].add(8).readPointer();
                if (type == 1){
                    //TODO: Obtain information from the running process       
                    var bytes = bufferPointer.readByteArray(size);
                    var message: { [key: string]: string | number } = {}
                    message["ss_family"] = "AF_INET"
                    message["src_port"] = 444;
                    message["src_addr"] = 222;
                    message["dst_port"] = 443;
                    message["dst_addr"] = 222;
                    message["function"] = "DecryptMessage"
                    message["contentType"] = "datalog"
                    message["ssl_session_id"] = 10
                    console.log(bytes)
                    send(message, bytes)
                }
            }
        }
        
    });

    Interceptor.attach(addresses["EncryptMessage"], {
        
        onEnter: function(args){
                    this.pMessage = args[2]; //PSecBufferDesc pMessage (https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc)
                    this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
                    this.pBuffers = this.pMessage.add(8).readPointer() //PSecBuffer  pBuffers (Pointer to array of secBuffers)
    
                    //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
                    //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
                    //--> Bytes to read: cBuffers + 16 Bytes
                    this.secBuffers = [] //Addresses of all secBuffers
                    for (let i = 0; i < this.cBuffers; i++){
                        var secBuffer = this.pBuffers.add(i * 16)
                        this.secBuffers.push(secBuffer);
                    }
                    
                    
                    for (let i = 0; i < this.secBuffers.length; i++){
                        var size = this.secBuffers[i].add(0).readULong();
                        var type = this.secBuffers[i].add(4).readULong();
                        var bufferPointer = this.secBuffers[i].add(8).readPointer();
                        if (type == 1){
                            //TODO: Obtain information from the running process
                            var bytes = bufferPointer.readByteArray(size);
                            var message: { [key: string]: string | number } = {}
                            message["ss_family"] = "AF_INET"
                            message["src_port"] = 443;
                            message["src_addr"] = 222;
                            message["dst_port"] = 444;
                            message["dst_addr"] = 222;
                            message["function"] = "EncryptMessage"
                            message["contentType"] = "datalog"
                            message["ssl_session_id"] = 10
                            send(message, bytes)
                        }
                    }
        }
    });

}