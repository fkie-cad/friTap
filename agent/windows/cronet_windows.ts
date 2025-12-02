
import {Cronet } from "../ssl_lib/cronet.js";
import { socket_library } from "./windows_agent.js";
import {PatternBasedHooking } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog, devlog_error, devlog_info, devlog_warn, devlog_debug } from "../util/log.js";

export type HookingResult = [success: boolean, handle: PatternBasedHooking | null];
const EXCLUDED_MODULE_SUFFIXES = ["_backup.dll", "_old.dll"]; // extensible list for problematic modules
const EXCLUDED_MODULE_PREFIXES = ["test_"]; // extensible list

export class Cronet_Windows extends Cronet {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
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

        if (isPatternReplaced()){
            devlog("Hooking libcronet functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libcronet.dll",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns for module "+this.module_name+".");
                this.dumpKeys(args[1], args[0], args[2], Number(args[3]));  // Unpack args into dumpKeys
            });
        }

        return hooker;
    }

    // Symbol-based hooking fallback for stripped libraries
    execute_symbol_based_hooking(hooker: PatternBasedHooking){
        devlog_debug("Trying symbol based hooking in "+ this.module_name);
        // Capture the dumpKeys function with the correct 'this'
        let dumpKeysFunc = this.dumpKeys.bind(this);

        if(hooker.no_hooking_success){
            try {
                let symbols = Process.getModuleByName(this.module_name).enumerateSymbols().filter(exports =>
                    exports.name.toLowerCase().includes("ssl_log")
                );
                if(symbols.length > 0){
                    devlog_info("Installed ssl_log_secret() hooks using symbols for "+ this.module_name);
                    Interceptor.attach(symbols[0].address, {
                        onEnter: function(args) {
                            dumpKeysFunc(args[1], args[0], args[2], Number(args[3]));
                        }
                    });
                } else {
                    devlog_debug("No ssl_log symbols found in " + this.module_name);
                }
            } catch(e) {
                devlog_error("Error in execute_symbol_based_hooking: "+ e);
            }
        }
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
                                    var message: { [key: string]: string | number | null } = {};
                                    message["contentType"] = "keylog";
                                    message["keylog"] = args[1].readCString();
                                    send(message);
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
                devlog_info("Installed SSL_CTX_set_keylog_callback hooks using symbols for "+ this.module_name);
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

        return [hooker_instance.no_hooking_success, hooker_instance];
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    // Check if the moduleName ends with any of the excluded suffixes or starts with excluded prefixes
    if (EXCLUDED_MODULE_SUFFIXES.some(suffix => moduleName.toLowerCase().endsWith(suffix.toLowerCase())) ||
        EXCLUDED_MODULE_PREFIXES.some(prefix => moduleName.toLowerCase().startsWith(prefix.toLowerCase()))) {
        devlog_debug(`Skipping module ${moduleName} due to excluded suffix/prefix.`);
        return;
    }

    try {
        var cronet = new Cronet_Windows(moduleName, socket_library, is_base_hook);

        const [success, hooker] = cronet.execute_hooks();

        // Strategy 3: Delayed symbol-based hooking fallback
        if(!success){
            if(hooker === null){
                devlog_warn("Hooker is null for module "+ moduleName + ", symbol-based fallback not available");
            } else {
                // Wait 1 sec before we continue with symbol-based fallback
                setTimeout(function() {
                    try{
                        cronet.execute_symbol_based_hooking(hooker);
                    } catch(e){
                        devlog_error("Error in cronet.execute_symbol_based_hooking: "+ e);
                    }
                }, 1000);
            }
        }

        if (is_base_hook) {
            try {
                const init_addresses = cronet.addresses[moduleName];
                // ensure that we only add it to global when we are not
                if (init_addresses && Object.keys(init_addresses).length > 0) {
                    (globalThis as any).init_addresses[moduleName] = init_addresses;
                } else {
                    devlog_debug(`No addresses to store for base hook in module ${moduleName}`);
                }
            } catch(error_msg){
                devlog_error(`cronet_execute base-hook error: ${error_msg}`);
            }
        }
    } catch(error_msg){
        devlog_error(`cronet_execute error for module ${moduleName}: ${error_msg}`);
    }
}