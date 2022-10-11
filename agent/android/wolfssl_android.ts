
import {WolfSSL } from "../ssl_lib/wolfssl.js";
import { socket_library } from "./android_agent.js";
import { toHexString } from "../shared/shared_functions.js"

export class WolfSSL_Android extends WolfSSL {

    constructor(public moduleName:String, public socket_library:String){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        WolfSSL.wolfSSL_get_client_random = new NativeFunction(this.addresses["wolfSSL_get_client_random"],"int", ["pointer", "pointer", "int"] )
        WolfSSL.wolfSSL_get_server_random = new NativeFunction(this.addresses["wolfSSL_get_server_random"],"int", ["pointer", "pointer", "int"] )
        //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
        WolfSSL.wolfSSL_SESSION_get_master_key = new NativeFunction(this.addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])
        
        Interceptor.attach(this.addresses["wolfSSL_connect"],{
            onEnter: function(args: any){
                this.ssl = args[0]
            },
            onLeave: function(retval: any){
                this.session = WolfSSL.wolfSSL_get_session(this.ssl) as NativePointer
    
                var keysString = "";
                
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga927e37dc840c228532efa0aa9bbec451
                var requiredClientRandomLength = WolfSSL.wolfSSL_get_client_random(this.session, NULL, 0) as number
                
                var clientBuffer = Memory.alloc(requiredClientRandomLength)
                WolfSSL.wolfSSL_get_client_random(this.ssl, clientBuffer, requiredClientRandomLength)
                var clientBytes = clientBuffer.readByteArray(requiredClientRandomLength)
                keysString = `${keysString}CLIENT_RANDOM: ${toHexString(clientBytes)}\n`
                
                //https://www.wolfssl.com/doxygen/group__Setup.html#ga987035fc600ba9e3b02e2b2718a16a6c
                var requiredServerRandomLength = WolfSSL.wolfSSL_get_server_random(this.session, NULL, 0) as number
                var serverBuffer = Memory.alloc(requiredServerRandomLength)
                WolfSSL.wolfSSL_get_server_random(this.ssl, serverBuffer, requiredServerRandomLength)
                var serverBytes = serverBuffer.readByteArray(requiredServerRandomLength)
                keysString = `${keysString}SERVER_RANDOM: ${toHexString(serverBytes)}\n`
                
                //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
                var requiredMasterKeyLength = WolfSSL.wolfSSL_SESSION_get_master_key(this.session, NULL, 0) as number
                var masterBuffer = Memory.alloc(requiredMasterKeyLength)
                WolfSSL.wolfSSL_SESSION_get_master_key(this.session, masterBuffer, requiredMasterKeyLength)
                var masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength)
                keysString = `${keysString}MASTER_KEY: ${toHexString(masterBytes)}\n`
    
                
                var message: { [key: string]: string | number | null } = {}
                message["contentType"] = "keylog"
                message["keylog"] = keysString
                send(message)
                
            }
        })
    }


}


export function wolfssl_execute(moduleName:String){
    var wolf_ssl = new WolfSSL_Android(moduleName,socket_library);
    wolf_ssl.execute_hooks();


}