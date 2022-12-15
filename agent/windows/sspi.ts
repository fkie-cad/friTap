import { readAddresses, getBaseAddress } from "../shared/shared_functions.js"
import { socket_library } from "./windows_agent.js";
import { devlog, log } from "../util/log.js"
import { experimental, offsets } from "../ssl_log.js";

/*
ToDo:
- Write Test Client for ground truth and test everything
- Obtain information from the running process to get the socket information instead of using default values
*/

var keylog = (key: string, tlsVersion: TLSVersion) =>{

    devlog(`Exporting TLS 1.${tlsVersion} handshake keying material`);

    var message: { [key: string]: string | number } = {}
    message["contentType"] = "keylog";
    message["keylog"] = key;
    send(message);
}

const enum TLSVersion{
    ONE_TWO = 2,
    ONE_THREE = 3
}

// This library is only existend under Windows therefore there is no Superclass
export class SSPI_Windows {

    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };

    constructor(public moduleName:String, public socket_library:String){

        this.library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage"];
        if(experimental){
            // ncrypt is used for the TLS keys
            log(`ncrypt.dll was loaded & will be hooked on Windows!`)
            this.library_method_mapping["*ncrypt*.dll"] = ["SslHashHandshake", "SslGenerateMasterKey", "SslImportMasterKey","SslGenerateSessionKeys","SslExpandExporterMasterKey","SslExpandTrafficKeys"]
        }
        this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
    
        this.addresses = readAddresses(this.library_method_mapping);

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.sspi != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            }

            
            for (const method of Object.keys(offsets.sspi)){
                //@ts-ignore
                this.addresses[`${method}`] = offsets.sspi[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.sspi[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.sspi[`${method}`].address));
            }


        }
        
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

    
    install_tls_keys_hook(){

        /* Most of the following code fragments were copied from
         * https://github.com/ngo/win-frida-scripts/tree/master/lsasslkeylog-easy
        */

        var client_randoms:any = {};
        var buf2hex = function (buffer:any) {
            return Array.prototype.map.call(new Uint8Array(buffer), function(x){ return ('00' + x.toString(16)).slice(-2)} ).join('');
        }

        /* ----- TLS1.2-specific ----- */

        var parse_h_master_key = function(pMasterKey: any){
            var NcryptSslKey_ptr = pMasterKey // NcryptSslKey
            var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
            var master_key = ssl5_ptr.add(28).readByteArray(48);
            return buf2hex(master_key);
        }

        var parse_parameter_list = function(pParameterList: any, calling_func: any){
            /*
                typedef struct _NCryptBufferDesc {
                    ULONG         ulVersion;
                    ULONG         cBuffers;
                    PNCryptBuffer pBuffers;
                } NCryptBufferDesc, *PNCryptBufferDesc;
                typedef struct _NCryptBuffer {
                    ULONG cbBuffer;
                    ULONG BufferType;
                    PVOID pvBuffer;
                } NCryptBuffer, *PNCryptBuffer;
             */
            var buffer_count = pParameterList.add(4).readU32();
            var buffers = pParameterList.add(8).readPointer();
            for(var i = 0 ; i < buffer_count ; i ++){
                var buf = buffers.add(16*i);
                var buf_size = buf.readU32();
                var buf_type = buf.add(4).readU32();
                var buf_buf = buf.add(8).readPointer().readByteArray(buf_size);
                // For buf_type values see NCRYPTBUFFER_SSL_* constans in ncrypt.h
                if (buf_type == 20){ // NCRYPTBUFFER_SSL_CLIENT_RANDOM
                   devlog("Got client random from " + calling_func+ "'s pParameterList: " + buf2hex(buf_buf));
                    return buf2hex(buf_buf);
                }
                //console.log("buf_type " + buf_type);
            }
            
            return null;
        }

        
        if(this.addresses["SslHashHandshake"] != null)
            Interceptor.attach(this.addresses["SslHashHandshake"], {
                onEnter: function (args: any) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslhashhandshake
                    var buf = ptr(args[2]);
                    var len = args[3].toInt32();
                    var mem = buf.readByteArray(len);
                    var msg_type = buf.readU8();
                    var version = buf.add(4).readU16();
                    if (msg_type == 1 && version == 0x0303){
                        // If we have client random, save it tied to current thread
                        var crandom = buf2hex(buf.add(6).readByteArray(32));
                        devlog("Got client random from SslHashHandshake: " + crandom);
                        client_randoms[this.threadId] = crandom;
                    }       
                },
                onLeave: function (retval) {
                }
            });

        if(this.addresses["SslGenerateMasterKey"] != null)
            Interceptor.attach(this.addresses["SslGenerateMasterKey"], {
                onEnter: function (args: any) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
                    this.phMasterKey = ptr(args[3]);
                    this.hSslProvider = ptr(args[0]);
                    this.pParameterList = ptr(args[6]);
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateMasterKey') || client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                    devlog("Got masterkey from SslGenerateMasterKey");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, TLSVersion.ONE_TWO);
                }
            });

        if(this.addresses["SslImportMasterKey"] != null)
            Interceptor.attach(this.addresses["SslImportMasterKey"], {
                onEnter: function (args: any) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslimportmasterkey
                    this.phMasterKey = ptr(args[2]);
                    this.pParameterList = ptr(args[5]);
                    // Get client random from the pParameterList, and if that fails - from the value saved by SslHashHandshake handler
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslImportMasterKey') || client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var master_key = parse_h_master_key(this.phMasterKey.readPointer());
                    devlog("[*] Got masterkey from SslImportMasterKey");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, TLSVersion.ONE_TWO)
                }
            });

        if(this.addresses["SslGenerateSessionKeys"] != null)
            Interceptor.attach(this.addresses["SslGenerateSessionKeys"], {
                onEnter: function (args: any) {
                    // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratesessionkeys
                    this.hMasterKey = ptr(args[1]);
                    this.hSslProvider = ptr(args[0]);
                    this.pParameterList = ptr(args[4]);
                    this.client_random = parse_parameter_list(this.pParameterList, 'SslGenerateSessionKeys') || client_randoms[this.threadId] || "???";
                    var master_key = parse_h_master_key(this.hMasterKey);
                    devlog("Got masterkey from SslGenerateSessionKeys");
                    keylog("CLIENT_RANDOM " + this.client_random + " " + master_key, TLSVersion.ONE_TWO);
                },
                onLeave: function (retval) {
                }
            });

        /* ----- TLS1.3-specific ----- */

        var stages: any = {};
        var get_secret_from_BDDD = function(struct_BDDD: any){
            var struct_3lss = struct_BDDD.add(0x10).readPointer();
            var struct_RUUU = struct_3lss.add(0x20).readPointer();
            var struct_YKSM = struct_RUUU.add(0x10).readPointer();
            var secret_ptr = struct_YKSM.add(0x18).readPointer();
                var size = struct_YKSM.add(0x10).readU32();
            return secret_ptr.readByteArray(size);
        }

        if(this.addresses["SslExpandTrafficKeys"] != null)
            Interceptor.attach(this.addresses["SslExpandTrafficKeys"], {
                onEnter: function (args: any) {
                    this.retkey1 = ptr(args[3]);
                    this.retkey2 = ptr(args[4]);
                    this.client_random = client_randoms[this.threadId] || "???";
                    if(stages[this.threadId]){
                        stages[this.threadId] = null;           
                        this.suffix = "TRAFFIC_SECRET_0";
                    }else{
                        stages[this.threadId] = "handshake";
                        this.suffix = "HANDSHAKE_TRAFFIC_SECRET";
                    }
                },
                onLeave: function (retval) {
                    var key1 = get_secret_from_BDDD(this.retkey1.readPointer());
                    var key2 = get_secret_from_BDDD(this.retkey2.readPointer());
                    keylog("CLIENT_" + this.suffix + " " + this.client_random + " " + buf2hex(key1), TLSVersion.ONE_THREE);
                    keylog("SERVER_" + this.suffix + " " + this.client_random + " " + buf2hex(key2), TLSVersion.ONE_THREE);
                }
            });

        if(this.addresses["SslExpandExporterMasterKey"] != null)
            Interceptor.attach(this.addresses["SslExpandExporterMasterKey"], {
                onEnter: function (args: any) {
                    this.retkey = ptr(args[3]);
                    this.client_random = client_randoms[this.threadId] || "???";
                },
                onLeave: function (retval) {
                    var key = this.retkey.readPointer().add(0x10).readPointer().add(0x20).readPointer().add(0x10).readPointer().add(0x18).readPointer().readByteArray(48);
                    keylog("EXPORTER_SECRET " + this.client_random + " " + buf2hex(key), TLSVersion.ONE_THREE);
                }
            });

    }

    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        if(experimental){
            this.install_tls_keys_hook();
        }
    }

}


export function sspi_execute(moduleName:String){
    var sspi_ssl = new SSPI_Windows(moduleName,socket_library);
    sspi_ssl.execute_hooks();


}