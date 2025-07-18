
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { socket_library } from "./macos_agent.js";
import { devlog, log, devlog_error } from "../util/log.js";
import { ObjC } from "../shared/objclib.js";

export class OpenSSL_BoringSSL_MacOS extends OpenSSL_BoringSSL {

    install_tls_keys_callback_hook(){
        //console.log(this.addresses) // currently only for debugging purposes will be removed in future releases
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            var CALLBACK_OFFSET = 0x2A8;

            var foundationNumber = Process.getModuleByName('CoreFoundation').getExportByName('kCFCoreFoundationVersionNumber')?.readDouble();
            devlog("Calculating offset to keylog callback based on the FoundationVersionNumber on MacOS: "+foundationNumber)
            if(foundationNumber == undefined){
                CALLBACK_OFFSET = 0x2A8;
                devlog("Installing callback for MacOS < 14 using callback offset: "+CALLBACK_OFFSET);
            } else if (foundationNumber >= 1751.108 && foundationNumber < 1854) {
                CALLBACK_OFFSET = 0x2B8; // >= iOS 14.x 
                devlog("Installing callback for MacOS >= 14 using callback offset: "+CALLBACK_OFFSET);
            } else if (foundationNumber >= 1854 && foundationNumber < 1946.102) {
                CALLBACK_OFFSET = 0x2F8; // >= iOS 15.x 
                devlog("Installing callback for MacOS >= 15 using callback offset: "+CALLBACK_OFFSET);
            } else if (foundationNumber >= 1946.102 && foundationNumber <= 1979.1) {
                CALLBACK_OFFSET = 0x300; // >= iOS 16.x 
                devlog("Installing callback for MacOS >= 16 using callback offset: "+CALLBACK_OFFSET);
            } else if (foundationNumber > 1979.1) {
                CALLBACK_OFFSET = 0x2F8; // >= iOS 17.x
                devlog("Installing callback for MacOS >= 17 using callback offset: "+CALLBACK_OFFSET); 
            }
            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_info_callback"], {
              onEnter: function (args : any) {
                ptr(args[0]).add(CALLBACK_OFFSET).writePointer(OpenSSL_BoringSSL.keylog_callback);
              }
            });
          
          }

    }

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){

        var library_method_mapping: { [key: string]: Array<string> } = {}

        // the MacOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        //library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"]
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_set_info_callback"]
        //library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"] // currently those functions gets only identified if we at an asterisk at the end 

        super(moduleName, socket_library, is_base_hook, library_method_mapping);
    }

    execute_hooks(){

        /*
        currently these function hooks aren't implemented
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        */

        this.install_tls_keys_callback_hook();
    }

    

}


export class OpenSSL_From_Python_MacOS extends OpenSSL_BoringSSL {

    
    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){

        var library_method_mapping: { [key: string]: Array<string> } = {}

        // the MacOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_set_keylog_callback", "SSL_CTX_new", "SSL_new", "SSL_get_SSL_CTX"] 

        super(moduleName, socket_library, is_base_hook, library_method_mapping);
    }

    install_openssl_keys_callback_hook(){
        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;

        try {

            const ssl_new_ptr = this.addresses[this.module_name]["SSL_new"];
            const ssl_get_ctx_ptr = this.addresses[this.module_name]["SSL_get_SSL_CTX"];
            const set_keylog_cb_ptr = this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"];

            if (!ssl_new_ptr || !ssl_get_ctx_ptr || !set_keylog_cb_ptr) {
                devlog_error(`Required functions not found in ${this.module_name}`);
                return;
            }
            const SSL_get_SSL_CTX = new NativeFunction(ssl_get_ctx_ptr,'pointer', ['pointer']) as (ssl: NativePointer) => NativePointer;

            Interceptor.attach(ssl_new_ptr, {
                onEnter(args: InvocationArguments): void {
                    //devlog(`SSL_new called in ${instance.module_name}`);
                },
                onLeave(retval: InvocationReturnValue): void {
                    if (retval.isNull()) {
                        devlog_error("SSL_new returned NULL");
                        return;
                    }

                    const ssl_ptr = retval as NativePointer;
                    const ctx_ptr = SSL_get_SSL_CTX(ssl_ptr);

                    if (ctx_ptr.isNull()) {
                        devlog_error("SSL_get_SSL_CTX returned NULL");
                        return;
                    }

                    //devlog(`Installing keylog callback on ctx: ${ctx_ptr}`); // Uncomment for debugging

                    try {
                        devlog("Installing callback for OpenSSL_From_Python for module: " + instance.module_name);
                        instance.SSL_CTX_set_keylog_callback(ctx_ptr, OpenSSL_BoringSSL.keylog_callback);
                    } catch (e) {
                        devlog_error(`Failed to set keylog callback: ${e}`);
                    }
                }
            });

        } catch (e) {
            devlog_error(`Error hooking ${instance.module_name}: ${e}`);
        }

        

        // In case a callback is set by the application, we attach to this callback instead
        // Only succeeds if SSL_CTX_new is available
        Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], {
            onEnter: function (args: any) {
                let callback_func = args[1];

                Interceptor.attach(callback_func, {
                    onEnter: function (args: any) {
                        var message: { [key: string]: string | number | null } = {};
                        message["contentType"] = "keylog";
                        message["keylog"] = args[1].readCString();
                        send(message);
                    }
                });
            }
        });
    }

    

    execute_hooks(){
        /*
        currently these function hooks aren't implemented
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        */

        this.install_openssl_keys_callback_hook();
    }

    

}


export function boring_execute(moduleName:string, is_base_hook: boolean){
    var boring_ssl = new OpenSSL_BoringSSL_MacOS(moduleName,socket_library, is_base_hook);
    boring_ssl.execute_hooks();
    
    if (is_base_hook) {
        const init_addresses = boring_ssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}

export function ssl_python_execute(moduleName:string, is_base_hook: boolean){
    var openssl = new OpenSSL_From_Python_MacOS(moduleName,socket_library, is_base_hook);
    openssl.execute_hooks();
    
    if (is_base_hook) {
        const init_addresses = openssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}