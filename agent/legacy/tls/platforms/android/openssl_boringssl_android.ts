
import {OpenSSL_BoringSSL } from "../../../tls/libs/openssl_boringssl.js";
import { devlog, devlog_debug, devlog_error } from "../../../../util/log.js";
import { socket_library } from "../../../../platforms/android.js";
import { patterns, isPatternReplaced, experimental, enable_default_fd } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { installBoringSSLSymbolHook, boringSslDumpKeys, isResolvedSymbol } from "../../../../shared/boringssl_symbol_hook.js";


export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
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
                        instance.SSL_CTX_set_keylog_callback(args[0], instance.keylog_callback);
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
                            instance.SSL_CTX_set_keylog_callback(retval, instance.keylog_callback);
                        }catch (e) {
                            devlog_error(`Error in SSL_CTX_new hook: ${e}`);
                        }
                    }

                });
        }

        // In case a callback is set by the application, we attach to this callback instead
        // Only succeeds if SSL_CTX_new is available
        Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], {
            onEnter: function (args: any) {
                let callback_func = args[1];

                Interceptor.attach(callback_func, {
                    onEnter: function (args: any) {
                        sendKeylog(args[1].readCString());
                    }
                });
            }
        });
    }

    install_conscrypt_tls_keys_callback_hook (){
        try{
            this.SSL_CTX_set_keylog_callback = new NativeFunction(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
            var instance = this;

            Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"], {
                onLeave: function(retval) {
                    const ssl = new NativePointer(retval);
                    if (!ssl.isNull()) {
                        instance.SSL_CTX_set_keylog_callback(ssl, instance.keylog_callback)
                    }
                }
            });
        }catch(e){
            // right now this will sillently fail
        }

    }

    execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        this.resolveWithPipeline([
            "SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
            "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback",
        ]);

        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
        this.install_conscrypt_tls_keys_callback_hook();
        this.install_extended_hooks();
    }

    execute_conscrypt_hooks(){
        this.install_conscrypt_tls_keys_callback_hook();
    }

}


export function boring_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(OpenSSL_BoringSSL_Android, moduleName, socket_library, is_base_hook, { tryCatch: true });

    // Universal BoringSSL fallback: if the public keylog API can't be resolved
    // for this module, the primary install above couldn't have hooked it. Try
    // bssl::ssl_log_secret via the shared symbol resolver instead. The check
    // uses init_addresses (populated by executeSSLLibrary on base hooks), so
    // it skips when the primary resolved the address successfully and only
    // fires when there's nothing to lose.
    if (is_base_hook) {
        try {
            const klc = (globalThis as any).init_addresses?.[moduleName]?.["SSL_CTX_set_keylog_callback"];
            if (!isResolvedSymbol(klc)) {
                devlog_debug(`[boring_execute] SSL_CTX_set_keylog_callback unresolved for ${moduleName}, trying ssl_log_secret symbol fallback`);
                installBoringSSLSymbolHook(moduleName, boringSslDumpKeys);
            }
        } catch (e) {
            devlog_debug(`[boring_execute] fallback check threw: ${e}`);
        }
    }
}
