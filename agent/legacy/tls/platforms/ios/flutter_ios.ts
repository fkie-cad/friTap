
import { Flutter } from "../../../../tls/libs/flutter.js";
import { socket_library } from "../../../../platforms/ios.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../../../../tls/shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../../../../fritap_agent.js"
import { devlog, devlog_debug, devlog_error } from "../../../../util/log.js";
import { installBoringSSLSymbolHook } from "../../../../shared/boringssl_symbol_hook.js";


export class Flutter_iOS extends Flutter {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "arm64": {
                primary: "FF 83 01 D1 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 08 34 40 F9 08 51 41 F9 48 08 00 B4", // Primary pattern
                fallback: "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4"  // Fallback pattern
            }
        };
    }



    install_key_extraction_hook(): PatternBasedHooking | null {
        const flutterModule = Process.findModuleByName(this.module_name);
        if (flutterModule === null) return null;
        const hooker = new PatternBasedHooking(flutterModule);

        if (isPatternReplaced()){
            devlog("Hooking Flutter functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"Flutter",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Flutter
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    this.dumpKeys(args[1], args[0], args[2]);  // Hook args passed to dumpKeys
                }
            );
        }
        return hooker;
    }

    execute_hooks(): PatternBasedHooking | null {
        return this.install_key_extraction_hook();
    }

}


export function flutter_execute(moduleName:string, is_base_hook: boolean){
    let flutter: Flutter_iOS;
    try {
        flutter = new Flutter_iOS(moduleName, socket_library, is_base_hook);
    } catch (e) {
        devlog_error(`flutter_execute constructor error for ${moduleName}: ${e}`);
        return;
    }

    let hooker: PatternBasedHooking | null = null;
    try {
        hooker = flutter.execute_hooks();
    } catch (e) {
        devlog_error(`flutter_execute error: ${e}`);
    }

    // BoringSSL symbol fallback. The 4th `len` arg from the symbol hook is
    // dropped because Flutter.dumpKeys derives length via heuristic and is
    // signature-incompatible with the 4-arg form.
    if (is_base_hook) {
        setTimeout(() => {
            try {
                if (hooker !== null && !hooker.no_hooking_success) return;
                devlog_debug("Trying symbol-based ssl_log_secret hook on " + moduleName);
                installBoringSSLSymbolHook(
                    moduleName,
                    (label, ssl, data, _len) => flutter.dumpKeys(label, ssl, data)
                );
            } catch (e) {
                devlog_error("flutter_execute symbol fallback error: " + e);
            }
        }, 1000);
    }

    if (is_base_hook) {
        try {
            const init_addresses = flutter.addresses[moduleName];
            if (init_addresses && Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        } catch (e) {
            devlog_error(`flutter_execute base-hook error: ${e}`);
        }
    }
}
