
import {Cronet } from "../../../../tls/libs/cronet.js";
import { socket_library } from "../../../../platforms/windows.js";
import {PatternBasedHooking, get_CPU_specific_pattern, hasModulePatterns } from "../../../../tls/shared/pattern_based_hooking.js";
import { CRONET_X64_PATTERNS, CRONET_X86_PATTERNS } from "../../../../tls/shared/cronet_patterns.js";
import { patterns, isPatternReplaced } from "../../../../fritap_agent.js"
import { devlog, devlog_error, devlog_info, devlog_warn, devlog_debug, log } from "../../../../util/log.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { scheduleBoringSSLSymbolFallback, installBoringSSLSymbolHook } from "../../../../shared/boringssl_symbol_hook.js";

export type HookingResult = [success: boolean, handle: PatternBasedHooking | null];
const EXCLUDED_MODULE_SUFFIXES = ["_backup.dll", "_old.dll"]; // extensible list for problematic modules
const EXCLUDED_MODULE_PREFIXES = ["test_"]; // extensible list

export class Cronet_Windows extends Cronet {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": CRONET_X64_PATTERNS,
            "x86": CRONET_X86_PATTERNS
        };
    }

    getDllName(modulePath: string): string {
        // Match the last segment ending in ".dll"
        const m = modulePath.match(/([^\/\\]+\.dll)$/i);
        return m ? m[1] : modulePath;
    }

    install_key_extraction_pattern_hook(){
        let cronetModule = Process.findModuleByName(this.module_name);
        if(cronetModule === null){
            const dllName = this.getDllName(this.module_name);
            cronetModule = Process.findModuleByName(dllName);
            if(cronetModule === null){
                devlog_error("Cronet Error: Unable to find module: " + this.module_name);
                return null;
            }
        }
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced() && hasModulePatterns(patterns, this.module_name, "libcronet.dll")){
            devlog("Hooking libcronet functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libcronet.dll",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns for module "+this.module_name+".");
                this.dumpKeys(args[1], args[0], args[2], Number(args[3]));  // Unpack args into dumpKeys
            });
        }else{
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    devlog("Installed ssl_log_secret() hooks using byte patterns for module "+this.module_name+".");
                    this.dumpKeys(args[1], args[0], args[2], Number(args[3]));
                }
            );
        }

        return hooker;
    }

    // Symbol-based fallback for ssl_log_secret. Runs only after pattern-based
    // hooking failed (gated on hooker.no_hooking_success). Delegates to the
    // shared multi-strategy resolver so Windows uses the same logic and the
    // same correct (label, ssl, data, len) interceptor signature as Android.
    execute_symbol_based_hooking(hooker: PatternBasedHooking){
        if (!hooker.no_hooking_success) return;

        devlog_debug("Trying symbol based hooking in "+ this.module_name);
        installBoringSSLSymbolHook(
            this.module_name,
            (label, ssl, data, len) => this.dumpKeys(label, ssl, data, len)
        );
    }

    install_tls_keys_callback_hook(){
        try {
            this.SSL_CTX_set_keylog_callback = new NativeFunction(
                this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"],
                "void",
                ["pointer", "pointer"]
            );
        } catch(e) {
            devlog_error(`Failed to create SSL_CTX_set_keylog_callback function: ${e}`);
            return;
        }

        var instance = this;
        let callback_already_set = false;

        try {
            if (this.addresses[this.module_name]["SSL_new"]) {
                Interceptor.attach(this.addresses[this.module_name]["SSL_new"], {
                    onEnter: function (args: any) {
                        try{
                            callback_already_set = true;
                            instance.SSL_CTX_set_keylog_callback(args[0], instance.keylog_callback);
                        } catch (e) {
                            callback_already_set = false;
                            devlog_error(`Error in SSL_new hook: ${e}`);
                        }
                    }
                });
            }

            if (this.addresses[this.module_name]["SSL_CTX_new"] !== null && callback_already_set === false) {
                Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_new"], {
                    onLeave: function (retval: any) {
                        try {
                            if (retval.isNull()) {
                                devlog_error("SSL_CTX_new returned NULL");
                                return;
                            }
                            instance.SSL_CTX_set_keylog_callback(retval, instance.keylog_callback);
                        } catch (e) {
                            devlog_error(`Error in SSL_CTX_new hook: ${e}`);
                        }
                    }
                });
            }

            // In case a callback is set by the application, we attach to this callback instead
            if (this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"]) {
                Interceptor.attach(this.addresses[this.module_name]["SSL_CTX_set_keylog_callback"], {
                    onEnter: function (args: any) {
                        let callback_func = args[1];
                        try {
                            Interceptor.attach(callback_func, {
                                onEnter: function (args: any) {
                                    sendKeylog(args[1].readCString());
                                }
                            });
                        } catch(e) {
                            devlog_error(`Error attaching to application's keylog callback: ${e}`);
                        }
                    }
                });
            }
        } catch(e) {
            devlog_error(`Error in install_tls_keys_callback_hook: ${e}`);
        }
    }

    execute_hooks(): HookingResult{
        let hooker_instance = null;

        // Strategy 1: Try SSL_CTX_set_keylog_callback if available
        if(this.are_callbacks_symbols_available()){
            try {
                this.install_tls_keys_callback_hook();
                // Unified install banner — `log()` so default-verbosity stdout shows it.
                log(`[*] ${this.module_name}: keylog hooks installed via callback (SSL_CTX_set_keylog_callback)`);
                return [true, null];
            } catch(e) {
                devlog_warn(`SSL_CTX_set_keylog_callback hooking failed, falling back to pattern-based: ${e}`);
            }
        } else {
            devlog_debug("SSL_CTX_set_keylog_callback not available in "+ this.module_name);
        }

        // Strategy 2: Pattern-based hooking
        try {
            hooker_instance = this.install_key_extraction_pattern_hook();
            if(hooker_instance === undefined || hooker_instance === null){
                devlog_warn("Pattern-based hooking returned null/undefined for " + this.module_name);
                return [false, null];
            }
        } catch(e) {
            devlog_error(`Pattern-based hooking failed: ${e}`);
            return [false, null];
        }

        // PatternBasedHooking sets no_hooking_success = true on initialisation
        // and flips it to false the moment any pattern variant matches. The
        // outer cronet_execute() reads the first tuple element as `success`
        // and does `if (!success)` to enter the symbol-fallback branch, so we
        // must return `true` when patterns succeeded (i.e. !no_hooking_success).
        return [!hooker_instance.no_hooking_success, hooker_instance];
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    // Check if the moduleName ends with any of the excluded suffixes or starts with excluded prefixes
    if (EXCLUDED_MODULE_SUFFIXES.some(suffix => moduleName.toLowerCase().endsWith(suffix.toLowerCase())) ||
        EXCLUDED_MODULE_PREFIXES.some(prefix => moduleName.toLowerCase().startsWith(prefix.toLowerCase()))) {
        devlog_debug(`Skipping module ${moduleName} due to excluded suffix/prefix.`);
        return;
    }

    let cronet: Cronet_Windows;
    try {
        cronet = new Cronet_Windows(moduleName, socket_library, is_base_hook);
    } catch (error_msg) {
        devlog_error(`cronet_execute constructor error for module ${moduleName}: ${error_msg}`);
        return;
    }

    // Capture execute_hooks result while keeping the symbol-fallback scheduling
    // OUTSIDE the try/catch — see cronet_android.ts for the rationale (a throw
    // in execute_hooks would otherwise bypass the fallback setTimeout).
    let success = false;
    let hooker: PatternBasedHooking | null = null;
    try {
        [success, hooker] = cronet.execute_hooks();
    } catch (error_msg) {
        devlog_error(`cronet_execute error for module ${moduleName}: ${error_msg}`);
    }

    // Strategy 3: Delayed symbol-based hooking fallback
    if (!success) {
        scheduleBoringSSLSymbolFallback(
            moduleName,
            hooker,
            () => cronet.execute_symbol_based_hooking(hooker!),
            (label, ssl, data, len) => cronet.dumpKeys(label, ssl, data, len),
        );
    }

    if (is_base_hook) {
        try {
            const init_addresses = cronet.addresses[moduleName];
            if (init_addresses && Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            } else {
                devlog_debug(`No addresses to store for base hook in module ${moduleName}`);
            }
        } catch(error_msg){
            devlog_error(`cronet_execute base-hook error: ${error_msg}`);
        }
    }
}
