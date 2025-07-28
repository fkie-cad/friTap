
import {OpenSSL_BoringSSL } from "../ssl_lib/openssl_boringssl.js";
import { socket_library } from "./linux_agent.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import {PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { devlog, devlog_error } from "../util/log.js";

export class OpenSSL_BoringSSL_Linux extends OpenSSL_BoringSSL {
    private default_pattern: { [arch: string]: { primary: string; fallback: string, second_fallback?: string; } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": {
                primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84", // Primary pattern
                fallback: "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84" // Fallback pattern
            },
            "x86": {
                primary: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34", // Primary pattern
                fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60" // Fallback pattern
            },
            "arm64": {
                primary: "3F 23 03 D5 FD 7B BF A9 E4 03 01 AA FD 03 00 91 FD 7B C1 A8 BF 23 03 D5 E1 03 00 AA E5 03 03 AA E0 03 04 AA 03 04 80 D2 E4 03 02 AA 22 80 05 91", // Primary pattern
                fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4" // Fallback pattern
            },  

            "arm": {
                primary: "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };
    }

    install_tls_keys_callback_hook (){

        this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
        var instance = this;
        let callback_already_set = false;
        
        
        Interceptor.attach(this.addresses[this.module_name]["SSL_new"],
            {
                onEnter: function (args: any) {
                    try{
                        callback_already_set = true;
                        instance.SSL_CTX_set_keylog_callback(args[0], OpenSSL_BoringSSL.keylog_callback);
                    }catch (e) {
                        callback_already_set = false;
                        devlog_error(`Error in SSL_new hook: ${e}`);
                    }
                    
                }
        
            });
         if (this.addresses[this.module_name]["SSL_CTX_new"] !== null && callback_already_set === false) {
            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"],
                {
                    onLeave: function (retval: any) {
                        try {
                            if (retval.isNull()) {
                                devlog_error("SSL_CTX_new returned NULL");
                                return;
                            }
                            instance.SSL_CTX_set_keylog_callback(retval, OpenSSL_BoringSSL.keylog_callback);
                        }catch (e) {
                            devlog_error(`Error in SSL_CTX_new hook: ${e}`);
                        }
                    }
            
                });
        }

        // In case a callback is set by the appliction, we attach to this callback instead 
        // Only succeeds if SSL_CTX_new is available
        let setter_address = "SSL_CTX_set_keylog_callback";
        Interceptor.attach(this.addresses[this.module_name][setter_address], {
            onEnter: function(args: any) {
                let callback_func = args[1];
                //devlog("args[1]: " + callback_func);

                Interceptor.attach(callback_func, {
                    onEnter: function(args: any) {
                        var message: { [key: string]: string | number | null } = {}
                        message["contentType"] = "keylog"
                        message["keylog"] = args[1].readCString()
                        send(message)
                    }
                });
            }
        });
        
    }

    install_openssl_key_extraction_hook(): PatternBasedHooking {
        let opensslModule = Process.findModuleByName(this.module_name);

        const hooker = new PatternBasedHooking(opensslModule);

        if (isPatternReplaced()){
            devlog("Hooking libssl functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libssl.so3",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns.");
                // this.dump_keys_openssl(labelptr, clientptr, keyptr, keyLength);
                this.dump_keys_openssl(args[1], args[0], args[2], args[3]);  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in OpenSSL
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    devlog("Installed ssl_log_secret() hooks using byte patterns.");
                    this.dump_keys_openssl(args[1], args[0], args[2], args[3]);  // Hook args passed to dumpKeys
                }
            );
        }

        return hooker
        
    }



    execute_hooks(){
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        let hooker_instance = this.install_openssl_key_extraction_hook();
        if (hooker_instance !== undefined || hooker_instance !== null) {
            devlog("Installed OpenSSL key extraction function hooks using patterns: "+hooker_instance.no_hooking_success);
        }
        this.install_tls_keys_callback_hook();
        this.install_extended_hooks();
    }

}


export class OpenSSL_From_Python_Linux extends OpenSSL_BoringSSL {

    
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
    var boring_ssl = new OpenSSL_BoringSSL_Linux(moduleName,socket_library, is_base_hook);
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
    var openssl = new OpenSSL_From_Python_Linux(moduleName,socket_library, is_base_hook);
    openssl.execute_hooks();
    
    if (is_base_hook) {
        const init_addresses = openssl.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}