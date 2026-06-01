
import {WolfSSL } from "../../../../tls/libs/wolfssl.js";
import { socket_library } from "../../../../platforms/linux.js";
import { toHexString } from "../../../../shared/shared_functions.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { devlog } from "../../../../util/log.js";

export class WolfSSL_Linux extends WolfSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library);
    }


    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    install_tls_keys_callback_hook(){
        devlog("[wolfssl] note: client/server random and master secret are only retained if wolfSSL_KeepArrays() was called before the handshake. Without it, wolfSSL frees these arrays after the handshake and the extracted values may be zeroed.")

        // These getters are only present when wolfSSL is built with OPENSSL_EXTRA.
        // On stripped/minimal builds the address is undefined; creating a
        // NativeFunction from it would throw at install time, so guard each one.
        var clientRandomAddr = this.addresses[this.module_name]["wolfSSL_get_client_random"]
        if (clientRandomAddr && !clientRandomAddr.isNull()) {
            WolfSSL.wolfSSL_get_client_random = new NativeFunction(clientRandomAddr,"int", ["pointer", "pointer", "int"] )
        } else {
            devlog("[wolfssl] wolfSSL_get_client_random unavailable; skipping")
        }

        var serverRandomAddr = this.addresses[this.module_name]["wolfSSL_get_server_random"]
        if (serverRandomAddr && !serverRandomAddr.isNull()) {
            WolfSSL.wolfSSL_get_server_random = new NativeFunction(serverRandomAddr,"int", ["pointer", "pointer", "int"] )
        } else {
            devlog("[wolfssl] wolfSSL_get_server_random unavailable; skipping")
        }

        //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
        var masterKeyAddr = this.addresses[this.module_name]["wolfSSL_SESSION_get_master_key"]
        if (masterKeyAddr && !masterKeyAddr.isNull()) {
            WolfSSL.wolfSSL_SESSION_get_master_key = new NativeFunction(masterKeyAddr, "int", ["pointer", "pointer", "int"])
        } else {
            devlog("[wolfssl] wolfSSL_SESSION_get_master_key unavailable; skipping")
        }

        Interceptor.attach(this.addresses[this.module_name]["wolfSSL_connect"],{
            onEnter: function(args: any){
                this.ssl = args[0]
            },
            onLeave: function(retval: any){
                this.session = WolfSSL.wolfSSL_get_session(this.ssl) as NativePointer
                if (this.session.isNull()) {
                    devlog("[wolfssl] session is null; cannot extract keys")
                    return
                }

                var keysString = "";

                //https://www.wolfssl.com/doxygen/group__Setup.html#ga927e37dc840c228532efa0aa9bbec451
                if (WolfSSL.wolfSSL_get_client_random) {
                    var requiredClientRandomLength = WolfSSL.wolfSSL_get_client_random(this.session, NULL, 0) as number
                    var clientBuffer = Memory.alloc(requiredClientRandomLength)
                    WolfSSL.wolfSSL_get_client_random(this.ssl, clientBuffer, requiredClientRandomLength)
                    var clientBytes = clientBuffer.readByteArray(requiredClientRandomLength)
                    keysString = `${keysString}CLIENT_RANDOM: ${toHexString(clientBytes)}\n`
                }

                //https://www.wolfssl.com/doxygen/group__Setup.html#ga987035fc600ba9e3b02e2b2718a16a6c
                if (WolfSSL.wolfSSL_get_server_random) {
                    var requiredServerRandomLength = WolfSSL.wolfSSL_get_server_random(this.session, NULL, 0) as number
                    var serverBuffer = Memory.alloc(requiredServerRandomLength)
                    WolfSSL.wolfSSL_get_server_random(this.ssl, serverBuffer, requiredServerRandomLength)
                    var serverBytes = serverBuffer.readByteArray(requiredServerRandomLength)
                    keysString = `${keysString}SERVER_RANDOM: ${toHexString(serverBytes)}\n`
                }

                //https://www.wolfssl.com/doxygen/group__Setup.html#gaf18a029cfeb3150bc245ce66b0a44758
                if (WolfSSL.wolfSSL_SESSION_get_master_key) {
                    var requiredMasterKeyLength = WolfSSL.wolfSSL_SESSION_get_master_key(this.session, NULL, 0) as number
                    var masterBuffer = Memory.alloc(requiredMasterKeyLength)
                    WolfSSL.wolfSSL_SESSION_get_master_key(this.session, masterBuffer, requiredMasterKeyLength)
                    var masterBytes = masterBuffer.readByteArray(requiredMasterKeyLength)
                    keysString = `${keysString}MASTER_KEY: ${toHexString(masterBytes)}\n`
                }

                if (keysString.length === 0) {
                    devlog("[wolfssl] no key material extracted (export functions unavailable)")
                    return
                }

                sendKeylog(keysString)

            }
        })
    }

}


export function wolfssl_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(WolfSSL_Linux, moduleName, socket_library, is_base_hook);
}
