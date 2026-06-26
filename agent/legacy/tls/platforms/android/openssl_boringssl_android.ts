
import {OpenSSL_BoringSSL } from "../../../tls/libs/openssl_boringssl.js";
import { devlog, devlog_debug, devlog_error, log } from "../../../../util/log.js";
import { socket_library } from "../../../../platforms/android.js";
import { patterns, isPatternReplaced, experimental, enable_default_fd, keylog_enabled, pairip_safe } from "../../../../fritap_agent.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { registerBlinkTarget, PAIRIP_BLINK_ENABLED } from "../../../../shared/pairip_blink.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";
import { installBoringSSLSymbolHook, boringSslDumpKeys, isResolvedSymbol } from "../../../../shared/boringssl_symbol_hook.js";
import { installBoringSSLPatternHook } from "../../../../shared/boringssl_pattern_hook.js";
import { enableDeepSymbolResolution } from "../../../../shared/deep_symbol_resolution.js";


export class OpenSSL_BoringSSL_Android extends OpenSSL_BoringSSL {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_tls_keys_callback_hook (): boolean {

        // Guard before constructing the NativeFunction: under --pairip-safe (symbol+offset
        // only) a lib like libjavacrypto.so (Conscrypt, no exported SSL_* surface) leaves
        // SSL_CTX_set_keylog_callback unresolved. new NativeFunction(undefined, …) would throw
        // Frida's "missing argument" and abort execute_hooks. Degrade to "no callback hook"
        // and let boring_execute's ssl_log_secret symbol fallback cover the module instead.
        const setKeylogAddr = this.addresses[this.module_name]?.["SSL_CTX_set_keylog_callback"];
        if (!setKeylogAddr || setKeylogAddr.isNull()) {
            devlog(`[*] ${this.module_name}: SSL_CTX_set_keylog_callback not resolved — skipping callback keylog (BoringSSL ssl_log_secret fallback still applies)`);
            return false;
        }

        this.SSL_CTX_set_keylog_callback = new NativeFunction(setKeylogAddr, "void", ["pointer", "pointer"]);
        var instance = this;
        const sslNewAddr = this.addresses[this.module_name]["SSL_new"];
        const ctxNewAddr = this.addresses[this.module_name]["SSL_CTX_new"];

        // (Re-)attach the inline keylog hooks; returns the listeners so the
        // pairip-safe blink loop can detach/re-attach them while the heap-resident
        // keylog callback keeps firing. In normal mode this just attaches once.
        const attachAll = (): InvocationListener[] => {
            const ls: InvocationListener[] = [];
            if (sslNewAddr) {
                ls.push(Interceptor.attach(sslNewAddr, {
                    onEnter: function (args: any) {
                        try { instance.SSL_CTX_set_keylog_callback(args[0], instance.keylog_callback); }
                        catch (e) { devlog_error(`Error in SSL_new hook: ${e}`); }
                    }
                }));
            }
            if (ctxNewAddr !== null) {
                ls.push(Interceptor.attach(ctxNewAddr, {
                    onLeave: function (retval: any) {
                        try {
                            if (retval.isNull()) { devlog_error("SSL_CTX_new returned NULL"); return; }
                            instance.SSL_CTX_set_keylog_callback(retval, instance.keylog_callback);
                        } catch (e) { devlog_error(`Error in SSL_CTX_new hook: ${e}`); }
                    }
                }));
            }
            // If the app installs its OWN keylog callback, capture from it too.
            ls.push(Interceptor.attach(setKeylogAddr, {
                onEnter: function (args: any) {
                    let callback_func = args[1];
                    if (callback_func.isNull()) return;
                    Interceptor.attach(callback_func, {
                        onEnter: function (args: any) { sendKeylog(args[1].readCString()); }
                    });
                }
            }));
            return ls;
        };

        if (pairip_safe && PAIRIP_BLINK_ENABLED) {
            // Blink: roots keylog_callback, first BRIGHT attach, schedules toggling.
            registerBlinkTarget(this.module_name, instance.keylog_callback, attachAll);
        } else {
            attachAll();
        }
        return true;
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

    async execute_hooks(){
        OpenSSL_BoringSSL.initializePipeline(
            isPatternReplaced() ? patterns : undefined,
            experimental
        );
        await this.resolveWithPipelineAsync([
            "SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session",
            "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback",
        ]);

        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        // Install-time keylog gate: in plaintext-only mode (no -k) the host sets
        // keylog_enabled=false, and the agent must skip every key-extraction path
        // — otherwise it installs the SSL_CTX_set_keylog_callback interception
        // (overwriting the app's own callback) and floods the debug log with
        // "invoking keylog_callback" lines even though sendKeylog() would drop
        // every secret downstream. This mirrors the gates already present in
        // cronet_android (cronet_android.ts:188) and the dynamic loader
        // (loader.ts:119); the base BoringSSL class was previously missing it.
        if (keylog_enabled) {
            // Unified install banner — `log()` so default-verbosity stdout shows it.
            // install_tls_keys_callback_hook() now returns whether the callback hook was
            // actually installed (false when SSL_CTX_set_keylog_callback is unresolved), so
            // the banner is truthful: we only claim "installed" when it really happened, and
            // otherwise note that the ssl_log_secret fallback (boring_execute) takes over.
            const installed = this.install_tls_keys_callback_hook();
            if (installed) {
                log(`[*] ${this.module_name}: keylog hooks installed via callback (SSL_CTX_set_keylog_callback)`);
            } else {
                devlog(`[*] ${this.module_name}: callback keylog unavailable; relying on ssl_log_secret fallback`);
            }
            this.install_conscrypt_tls_keys_callback_hook();
        } else {
            devlog(`[*] ${this.module_name}: keylog install skipped (keylog_enabled=false, plaintext-only mode)`);
        }
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
                const symOk = installBoringSSLSymbolHook(moduleName, boringSslDumpKeys);
                // Tier 3: byte-pattern scan, mirroring the modern chain
                // (boringssl_hook_chain.ts). With no --patterns JSON,
                // installBoringSSLPatternHook falls through its sub-tiers to the
                // bundled openssl.<arch>.ssl_log_secret floor (3d), so a stripped
                // BoringSSL host is still covered. Family auto-derives to
                // generic_boringssl.
                if (!symOk && pairip_safe) {
                    // --pairip-safe: HARD-DISABLE the byte-pattern (Memory.scan)
                    // tier. PairIP SIGSEGVs on a scan of a protected lib, so an
                    // unresolved boring lib degrades to "no hook" here too (legacy
                    // counterpart of the guard in boringssl_hook_chain.ts).
                    devlog_debug(`[boring_execute] ${moduleName}: pattern tier disabled (--pairip-safe); exports/offsets only`);
                } else if (!symOk) {
                    devlog_debug(`[boring_execute] ssl_log_secret symbol fallback failed for ${moduleName}, trying byte-pattern scan`);
                    installBoringSSLPatternHook(
                        moduleName,
                        isPatternReplaced() ? patterns : undefined,
                        boringSslDumpKeys,
                        "libcronet.so",
                        { libraryType: "boringssl" },
                    );
                }
            }
        } catch (e) {
            devlog_debug(`[boring_execute] fallback check threw: ${e}`);
        }
    }
}

// libhttpengine.so statically links BoringSSL and exports the standard SSL_*
// surface, but may keep those symbols in .symtab rather than .dynsym. Opting the
// module into deep symbol resolution lets readAddresses / isSymbolAvailable fall
// back to enumerateSymbols(), so the stealthy SSL_CTX_set_keylog_callback
// (heap-write) keylog path resolves and installs. The tier-1 callback / tier-2
// ssl_log_secret / tier-3 pattern chain is inherited unchanged from
// boring_execute.
export function httpengine_execute(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    boring_execute(moduleName, is_base_hook);
}
