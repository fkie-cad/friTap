
import {NSS } from "../ssl_lib/nss.js"
import { socket_library } from "./linux_agent.js";
import { log, devlog } from "../util/log.js"

export class NSS_Linux extends NSS {

    constructor(public moduleName:String, public socket_library:String){
        var library_method_mapping : { [key: string]: Array<String> }= {};
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"]
        library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
        library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

        super(moduleName,socket_library,library_method_mapping);
    }

    
    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook()
    }

    install_tls_keys_callback_hook() {

        NSS.getDescType = new NativeFunction(this.addresses['PR_GetDescType'], "int", ["pointer"]);
        
        // SSL Handshake Functions:
        NSS.PR_GetNameForIdentity = new NativeFunction(this.addresses['PR_GetNameForIdentity'], "pointer", ["pointer"]);
        /*
                SECStatus SSL_HandshakeCallback(PRFileDesc *fd, SSLHandshakeCallback cb, void *client_data);
                more at https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc#1112702
        */
        NSS.get_SSL_Callback = new NativeFunction(this.addresses["SSL_HandshakeCallback"], "int", ["pointer", "pointer", "pointer"]);


        // SSL Key helper Functions 
        NSS.PK11_ExtractKeyValue = new NativeFunction(this.addresses["PK11_ExtractKeyValue"], "int", ["pointer"]);
        NSS.PK11_GetKeyData = new NativeFunction(this.addresses["PK11_GetKeyData"], "pointer", ["pointer"]);

        Interceptor.attach(this.addresses["SSL_ImportFD"],
            {
                onEnter(args: any) {
                    this.fd = args[1];
                },
                onLeave(retval: any) {

                    if (retval.isNull()) {
                        devlog("[-] SSL_ImportFD error: unknow null")
                        return
                    }


                    var retValue = NSS.get_SSL_Callback(retval, NSS.keylog_callback, NULL);
                    NSS.register_secret_callback(retval);




                    // typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;
                    if (retValue < 0) {
                        devlog("Callback Error")
                        var getErrorText = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetErrorText'), "int", ["pointer"])
                        var outbuffer = Memory.alloc(200); // max out size
                        console.log("typeof outbuffer: " + typeof outbuffer);
                        console.log("outbuffer: " + outbuffer); // should be a pointer
                        getErrorText(outbuffer.readPointer())
                        devlog("Error msg: " + outbuffer)
                    } else {
                        devlog("[*] keylog callback successfull installed")
                    }

                }

            });





        /*
            SECStatus SSL_HandshakeCallback(
                PRFileDesc *fd,
                SSLHandshakeCallback cb,
                void *client_data
            );
         */
        Interceptor.attach(this.addresses["SSL_HandshakeCallback"],
            {
                onEnter(args: any) {

                    this.originalCallback = args[1];

                    Interceptor.attach(ptr(this.originalCallback),
                        {
                            onEnter(args: any) {
                                var sslSocketFD = args[0];
                                devlog("[*] keylog callback successfull installed via applications callback function");
                                NSS.ssl_RecordKeyLog(sslSocketFD);
                            },
                            onLeave(retval: any) {
                            }
                        });

                },
                onLeave(retval: any) {
                }

            });


    }

}


export function nss_execute(moduleName:String){
    var nss_ssl = new NSS_Linux(moduleName,socket_library);
    nss_ssl.execute_hooks();


}