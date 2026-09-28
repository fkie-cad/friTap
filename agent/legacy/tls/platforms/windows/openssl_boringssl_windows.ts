
import {OpenSSL_BoringSSL } from "../../../../tls/libs/openssl_boringssl.js";
import { socket_library } from "../../../../platforms/windows.js";
import { devlog, devlog_error } from "../../../../util/log.js";
import { patterns, isPatternReplaced, experimental } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";
import { createKeylogCallbackTracker } from "../../../../shared/keylog_callback_tracker.js";

export class OpenSSL_BoringSSL_Windows extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        let mapping:{ [key: string]: Array<string> } = {};
        mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new"]
        mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        super(moduleName,socket_library, is_base_hook, mapping);
    }

    /*
    SSL_CTX_set_keylog_callback not exported by default on windows.

    We need to find a way to install the callback function for doing that

	Alternatives?:SSL_export_keying_material, SSL_SESSION_get_master_key
    */
    install_tls_keys_callback_hook(){
        // install hooking for windows
    }

    async execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        await this.resolveWithPipelineAsync([
            "SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
            "SSL_SESSION_get_id", "SSL_new",
        ]);

        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
    }

}

export class OpenSSL_From_Python_Windows extends OpenSSL_BoringSSL {


    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){

        var library_method_mapping: { [key: string]: Array<string> } = {}

        // the MacOS implementation needs some further improvements - currently we are not able to get the sockfd from an SSL_read/write invocation
        library_method_mapping[`*${moduleName}*`] = ["SSL_CTX_set_keylog_callback", "SSL_CTX_new", "SSL_new", "SSL_get_SSL_CTX"]

        super(moduleName, socket_library, is_base_hook, library_method_mapping);
    }

    install_openssl_keys_callback_hook(){
        var instance = this;

        const ssl_new_ptr = this.addresses[this.module_name]["SSL_new"];
        const ssl_get_ctx_ptr = this.addresses[this.module_name]["SSL_get_SSL_CTX"];
        const set_keylog_cb_ptr = this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"];

        // Checked BEFORE any NativeFunction is built: new NativeFunction(undefined)
        // throws, so building the keylog setter above this guard made the guard
        // dead code and turned a diagnosable "not found" into an exception
        // swallowed by execute_hooks()'s caller -- no hooks, no message.
        if (!ssl_new_ptr || !ssl_get_ctx_ptr || !set_keylog_cb_ptr) {
            devlog_error(`Required functions not found in ${this.module_name}`);
            return;
        }

        this.SSL_CTX_set_keylog_callback = new NativeFunction(set_keylog_cb_ptr, "void", ["pointer", "pointer"]);
        // Records every SSL_CTX we point at our script-owned keylog callback so
        // releaseAgentHooks can undo it (see shared/keylog_callback_tracker.ts).
        const tracker = createKeylogCallbackTracker(this.module_name, set_keylog_cb_ptr, instance.keylog_callback, true);

        try {
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
                        tracker.install(ctx_ptr);
                    } catch (e) {
                        devlog_error(`Failed to set keylog callback: ${e}`);
                    }
                }
            });

        } catch (e) {
            devlog_error(`Error hooking ${instance.module_name}: ${e}`);
        }



        // In case a callback is set by the application, we attach to this callback instead.
        // Wrapped: this sits outside the try above, so a failure here used to
        // propagate out of the whole hook installation.
        try {
            Interceptor.attach(set_keylog_cb_ptr, {
                onEnter: function (args: any) {
                    let callback_func = args[1];
                    if (callback_func.isNull() || tracker.sealed) return;
                    tracker.noteAppCallback(args[0], callback_func);

                    Interceptor.attach(callback_func, {
                        onEnter: function (args: any) {
                            sendKeylog(args[1].readCString());
                        }
                    });
                }
            });
        } catch (e) {
            devlog_error(`Failed to attach to SSL_CTX_set_keylog_callback in ${instance.module_name}: ${e}`);
        }
    }



    async execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        await this.resolveWithPipelineAsync([
            "SSL_CTX_set_keylog_callback", "SSL_CTX_new", "SSL_new", "SSL_get_SSL_CTX",
        ]);

        this.install_openssl_keys_callback_hook();
    }



}


// A libssl/libcrypto DLL that was linked statically into the host EXE keeps the
// SSL_* surface out of the PE export directory, where friTap's exports-only
// lookup cannot see it, while the debug/COFF symbol table still names it. Opting
// the module into deep symbol resolution lets readAddresses / isSymbolAvailable
// fall back to enumerateSymbols() for exactly the symbols the exports pass
// MISSED, so SSL_read/SSL_write still resolve on such a host. No-op when the DLL
// exports them normally. Mirrors boring_execute_modern
// (agent/tls/platforms/windows/openssl_boringssl_windows.ts).
export function boring_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_BoringSSL_Windows, moduleName, socket_library, is_base_hook);
}

// Same reasoning as boring_execute: a Python whose _ssl module statically links
// OpenSSL exposes SSL_CTX_set_keylog_callback only in the symbol table, and
// without it this executor has no keylog path at all.
export function ssl_python_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_From_Python_Windows, moduleName, socket_library, is_base_hook);
}
