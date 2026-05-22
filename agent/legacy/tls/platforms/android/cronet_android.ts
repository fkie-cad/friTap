
import {Cronet } from "../../../tls/libs/cronet.js";
import { socket_library } from "../../../../platforms/android.js";
import {PatternBasedHooking, get_CPU_specific_pattern, hasModulePatterns } from "../../../tls/shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced, keylog_enabled } from "../../../../fritap_agent.js"
import { devlog, devlog_debug, devlog_error, devlog_info, log } from "../../../../util/log.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { scheduleBoringSSLSymbolFallback, installBoringSSLSymbolHook } from "../../../../shared/boringssl_symbol_hook.js";

export type HookingResult = [success: boolean, handle: PatternBasedHooking | null];
const EXCLUDED_MODULE_SUFFIXES = ["_libpki.so", "_libcrypto.so", "libsignal_jni_testing.so", "_vr_partition.so"]; // extensible list

interface PatternSet {
  primary:  string;
  fallback: string;
  second_fallback?: string;
}

interface Patterns {
  [arch: string]: PatternSet;
}

const STABLE_CRONET_PATTERNS = {
    "arm64": {
        primary:  "FF 83 02 D1 FD 7B 05 A9 F9 33 00 F9 F8 5F 07 A9 F6 57 08 A9 F4 4F 09 A9 FD 43 01 91 58 D0 3B D5 08 17 40 F9 A8 83 1F F8 08 34 40 F9 08 21 41 F9 28 11", // Primary pattern
        fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4" // Fallback pattern
    }
};

const LIBSIGNAL_PATTERNS = {
    "arm64": {
        //primary:  "FF 43 02 D1 FD 7B 05 A9 F8 5F 06 A9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 58 D0 3B D5 08 17 40 F9 A8 83 1F F8 08 34 40 F9 08 11 41 F9 A8 0A 00 B4", // old Primary pattern
        primary:  "FF 43 02 D1 FD 7B 05 A9 F? ?? 0? ?9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 5? D0 3B D5 ?8 1? 40 F9 A8 83 1F F8 08 34 40 F9 08 11 41 F9 ?8 0? 00 B4", // Primary pattern
        fallback: "3F 23 03 D5 FF 43 02 D1 FD 7B 05 A9 F8 5F 06 A9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 08 34 40 F9 08 21 41 F9 C8 11 00 B4" // Fallback pattern
    }
};

export class Cronet_Android extends Cronet {
    private default_pattern: { [arch: string]: { primary: string; fallback: string, second_fallback?: string; } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean, patterns?: Patterns){
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
                primary: "3F 23 03 D5 FF ?3 01 D1 FD 7B 0? A9 F6 57 0? A9 F4 4F 0? A9 FD ?3 0? 91 08 34 40 F9 08 1? 41 F9 ?8 0? 00 B4", // Primary pattern
                //fallback: "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 ?? 41 F9 ?8 0? 00 B4",  // old Fallback pattern
                fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4", // Fallback pattern
                second_fallback: "3F 23 03 D5 FF C3 05 D1 FD 7B 14 A9 FC 57 15 A9 F4 4F 16 A9 FD 03 05 91 54 D0 3B D5 88 16 40 F9 40 00 80 52 F3",
            },

            "arm": {
                primary: "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };

        if(patterns){
            //devlog_debug("Using provided patterns for Cronet_Android for mudule "+ moduleName);
            // If patterns are provided, use them instead of the default ones
            this.default_pattern = patterns;
        }
    }

    getSoName(modulePath: string): string {
        // Match the last segment ending in ".so"
        const m = modulePath.match(/([^\/\\]+\.so)$/);
        return m ? m[1] : modulePath;
      }




    install_key_extraction_pattern_hook(){
        let cronetModule = Process.findModuleByName(this.module_name);
        if(cronetModule === null){
            const soName   = this.getSoName(this.module_name);
            cronetModule = Process.findModuleByName(soName);
            if(cronetModule === null){
                devlog_error("Cronet Error: Unable to find module: " + this.module_name);
                return;
            }
        }
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced() && hasModulePatterns(patterns, this.module_name, "libcronet.so")){
            devlog("Hooking libcronet functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns for module "+this.module_name+".");
                this.dumpKeys(args[1], args[0], args[2], Number(args[3]));  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Cronet
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    devlog("Installed ssl_log_secret() hooks using byte patterns for module "+this.module_name+".");
                    this.dumpKeys(args[1], args[0], args[2], Number(args[3]));  // Hook args passed to dumpKeys
                }
            );
        }

        return hooker;

    }

    // Symbol-based fallback for ssl_log_secret. Runs only after pattern-based
    // hooking failed (gated on hooker.no_hooking_success, set by
    // PatternBasedHooking when no pattern variant matched). Delegates to the
    // shared resolver chain in agent/shared/boringssl_symbol_hook.ts so every
    // BoringSSL-tagged lib uses the same logic and the same correct
    // (label, ssl, data, len) interceptor signature.
    execute_symbol_based_hooking(hooker: PatternBasedHooking){
        if (!hooker.no_hooking_success) return;

        devlog_debug("Trying symbol based hooking in "+ this.module_name);
        installBoringSSLSymbolHook(
            this.module_name,
            (label, ssl, data, len) => this.dumpKeys(label, ssl, data, len)
        );
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

    execute_hooks(): HookingResult{
        let hooker_instance = null;
        // [true, null] matches the "callback succeeded, no hooker" shape so the
        // outer cronet_execute() skips the symbol-fallback scheduler.
        if (!keylog_enabled) {
            devlog_debug(`[cronet_android] ${this.module_name}: keylog skipped (keylog_enabled=false)`);
            this.install_plaintext_read_hook();
            this.install_plaintext_write_hook();
            return [true, null];
        }
        if(this.are_callbacks_symbols_available()){
            this.install_tls_keys_callback_hook();
            // Unified install banner — `log()` so default-verbosity stdout shows it.
            log(`[*] ${this.module_name}: keylog hooks installed via callback (SSL_CTX_set_keylog_callback)`);
            this.install_plaintext_read_hook();
            this.install_plaintext_write_hook();
            return [true, null];
        }else{
            //devlog_debug("SSL_CTX_set_keylog_callback not available in "+ this.module_name);
            // hooking ssl_log_secret() from BoringSSL
            hooker_instance = this.install_key_extraction_pattern_hook();
            if(hooker_instance === undefined || hooker_instance === null){
                return [false, null];
            }
            this.install_plaintext_read_hook();
            this.install_plaintext_write_hook();


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
    // Check if the moduleName ends with any of the excluded suffixes
    if (EXCLUDED_MODULE_SUFFIXES.some(suffix => moduleName.endsWith(suffix))) {
        devlog_debug(`Skipping excluded module ${moduleName}.`);
        return;
    }

    let cronet: Cronet_Android;
    if(moduleName.startsWith("stable_cronet")){
        cronet = new Cronet_Android(moduleName,socket_library,is_base_hook, STABLE_CRONET_PATTERNS);
    }else if(moduleName.includes("libsignal_jni") || moduleName.includes("libringrtc_rffi") || moduleName.includes("libwarp_mobile")){
        cronet = new Cronet_Android(moduleName,socket_library,is_base_hook, LIBSIGNAL_PATTERNS);
    }else{
        cronet = new Cronet_Android(moduleName,socket_library,is_base_hook);
    }

    // Capture execute_hooks result while keeping the symbol-fallback scheduling
    // OUTSIDE the try/catch — a throw inside execute_hooks (e.g. Frida rejecting
    // an Interceptor.attach on a stripped pattern hit) would otherwise bypass
    // the setTimeout, leaving the user with no keylog rescue. By treating a
    // throw as "primary failed" we still schedule the symbol fallback.
    let success = false;
    let hooker: PatternBasedHooking | null = null;
    try {
        [success, hooker] = cronet.execute_hooks();
    } catch (error_msg) {
        devlog_error(`cronet_execute error: ${error_msg}`);
    }

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
            // ensure that we only add it to global when we are not
            if (Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        }catch(error_msg){
            devlog_error(`cronet_execute base-hook error: ${error_msg}`)
        }
    }

}
