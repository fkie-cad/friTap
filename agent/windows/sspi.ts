import { readAddresses, getPortsAndAddresses, getSocketLibrary, getModuleNames } from "../shared/shared"
import { socket_library } from "./windows_agent";

/*

ToDo:

- Write Test Client for ground truth and test everything
- Obtain information from the running process to get the socket information instead of using default values

SspiCli.dll!DecryptMessage called!
ncrypt.dll!SslDecryptPacket called!
bcrypt.dll!BCryptDecrypt called!
*/


// This library is only existend under Windows therefore there is no Superclass
export class SSPI_Windows {

    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };

    constructor(public moduleName:String, public socket_library:String){

        this.library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage"];
        this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    
        this.addresses = readAddresses(this.library_method_mapping);
        
    }

    install_plaintext_read_hook(){
        Interceptor.attach(this.addresses["DecryptMessage"], {
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
                        //TODO: Obtain information from the running process to get the socket information
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

    }

    install_plaintext_write_hook(){
        Interceptor.attach(this.addresses["EncryptMessage"], {
        
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

    
    install_tls_keys_callback_hook(){
        // TBD
    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }

}


export function sspi_execute(moduleName:String){
    var sspi_ssl = new SSPI_Windows(moduleName,socket_library);
    sspi_ssl.execute_hooks();


}