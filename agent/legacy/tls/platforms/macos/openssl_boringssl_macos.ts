
import {OpenSSL_BoringSSL } from "../../../../tls/libs/openssl_boringssl.js";
import { socket_library } from "../../../../platforms/macos.js";
import { devlog, log, devlog_error } from "../../../../util/log.js";
import { ObjC } from "../../../../shared/objclib.js";
import { patterns, isPatternReplaced, experimental } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { installKeylogCallbackViaCtxWrite } from "../../shared/apple_keylog_offset.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";
import { createKeylogCallbackTracker } from "../../../../shared/keylog_callback_tracker.js";

export class OpenSSL_BoringSSL_MacOS extends OpenSSL_BoringSSL {

    install_tls_keys_callback_hook(){
        //console.log(this.addresses) // currently only for debugging purposes will be removed in future releases
        if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
            // Same mechanism as iOS: Apple does not export
            // SSL_CTX_set_keylog_callback, so the callback is written into the
            // SSL_CTX struct. The offset table and the write-time validation are
            // shared with the iOS path (apple_keylog_offset.ts). The previous
            // macOS-local table disagreed with its iOS twin for the same OS era.
            const setInfoCallback = this.addresses[this.module_name]["SSL_CTX_set_info_callback"];
            if (setInfoCallback === undefined || setInfoCallback === null || setInfoCallback.isNull()) {
                devlog("[MacOS] SSL_CTX_set_info_callback unresolved — cannot install the keylog callback");
                return;
            }
            installKeylogCallbackViaCtxWrite(setInfoCallback, this.keylog_callback, "MacOS", this.module_name);
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

    async execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        await this.resolveWithPipelineAsync(["SSL_CTX_set_info_callback"]);

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
        var instance = this;

        const ssl_new_ptr = this.addresses[this.module_name]["SSL_new"];
        const ssl_get_ctx_ptr = this.addresses[this.module_name]["SSL_get_SSL_CTX"];
        const set_keylog_cb_ptr = this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"];

        // Checked BEFORE any NativeFunction is built. new NativeFunction(undefined)
        // throws, so constructing the keylog setter above this guard made the
        // guard dead code: a module that lacks SSL_CTX_set_keylog_callback -- a
        // bundled libssl.1.0.0.dylib, or pre-3.5 LibreSSL, both of which now
        // route here -- threw out of the async execute_hooks(), where the
        // caller's .catch reduced it to a single devlog. Net effect was a module
        // with no hooks and no user-visible message.
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
        // Wrapped: this sits outside the try above, so an Interceptor failure here
        // used to propagate out of the whole hook installation.
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


// Opts libboringssl.dylib into exports -> enumerateSymbols() fallback resolution,
// for parity with every other platform executor. On Apple this is INERT by
// construction, and deliberately so — this is the struct-write keylog path of
// fkie-cad/friTap#65 and it must not change behaviour here:
//   - the library_method_mapping above requests exactly one symbol,
//     SSL_CTX_set_info_callback, and Apple EXPORTS it ('T _SSL_CTX_set_info_callback'
//     in nm on the iOS 17.0 / 17.5 / 18.6 / 26.2 simulator runtimes, which ship the
//     same libboringssl revision as the macOS release of the same year), so
//     readAddresses resolves it in the exports pass. The symbol-table fallback only
//     fills entries the exports pass MISSED and never overwrites an export hit.
//   - the base constructor's isSymbolAvailable() probes cannot flip either:
//     SSL_CTX_new is exported ('T') on all four runtimes, and SSL_read_ex /
//     SSL_write_ex do not exist in BoringSSL at all (absent from nm entirely), so
//     is_openssl stays false — and install_extended_hooks(), its only consumer, is
//     not called by this executor anyway.
//   - the keylog offset derivation in apple_keylog_offset.ts calls
//     Module.enumerateSymbols() directly for the LOCAL ('t')
//     _SSL_CTX_set_keylog_callback; it does not go through this opt-in.
// Adding SSL_CTX_set_keylog_callback to the mapping, i.e. calling Apple's setter
// instead of writing the struct field, is a separate deferred change.
export function boring_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_BoringSSL_MacOS, moduleName, socket_library, is_base_hook);
}

// Unlike boring_execute above, this one genuinely gains something: the mapping
// requests SSL_CTX_set_keylog_callback, and a Python linked against a static
// libssl keeps that symbol in .symtab rather than the export table. Today an
// unresolved setter here means no keylog at all, so the fallback is purely
// additive. Mirrors ssl_python_execute_modern
// (agent/tls/platforms/macos/openssl_boringssl_macos.ts).
export function ssl_python_execute(moduleName:string, is_base_hook: boolean){
    enableDeepSymbolResolution(moduleName);
    executeSSLLibrary(OpenSSL_From_Python_MacOS, moduleName, socket_library, is_base_hook);
}
