
import { Flutter } from "../../../tls/libs/flutter.js";
import { socket_library } from "../../../../platforms/android.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../../../tls/shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../../../../fritap_agent.js"
import { devlog, devlog_debug, devlog_error } from "../../../../util/log.js";
import { installBoringSSLSymbolHook } from "../../../../shared/boringssl_symbol_hook.js";


export class Flutter_Android extends Flutter {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": {
                primary: "55 41 57 41 56 41 55 41 54 53 48 83 EC 48 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84 FE 00 00 00", // Primary pattern
                fallback: "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 48 8B 47 68 48 83 B8 10 02 00 00 00 0F 84 19 01 00 00" // Fallback pattern
            },
            "x86": {
                primary: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34", // Primary pattern
                fallback: "55 89 E5 53 57 56 83 E4 F0 83 EC 50 E8 00 00 00 00" // Fallback pattern
            },
            "arm64": {
                primary: "E0 03 13 AA E2 03 16 AA 6D 62 FA 17", // Primary pattern
                fallback: "FF 83 01 D1 F6 1B 00 F9 F5 53 04 A9 F3 7B 05 A9 08 34 40 F9 08 09 41 F9 68 07 00 B4"  // Fallback pattern
            },
            "arm": {
                primary: "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };
    }




    install_key_extraction_hook(): PatternBasedHooking | null {
        const flutterModule = Process.findModuleByName(this.module_name);
        if (flutterModule === null) return null;
        const hooker = new PatternBasedHooking(flutterModule);

        if (isPatternReplaced()){
            devlog("Hooking libflutter functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libflutter.so",patterns,(args: any[]) => {
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
    const flutter = new Flutter_Android(moduleName, socket_library, is_base_hook);
    let hooker: PatternBasedHooking | null = null;
    try {
        hooker = flutter.execute_hooks();
    } catch (e) {
        devlog_error(`flutter_execute error: ${e}`);
    }

    // BoringSSL symbol fallback: schedule one second after pattern hooking so
    // the matcher has settled, then install only when patterns failed (or when
    // execute_hooks() threw before the hooker was ever assigned, hence the
    // `hooker === null` arm). Only on the base hook to avoid one timer per
    // dlopen of the same lib.
    // The 4th `len` arg from the symbol hook is dropped because Flutter.dumpKeys
    // derives length via its own heuristic and is signature-incompatible with
    // the 4-arg form Cronet uses.
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
            const init_addresses = (flutter as any).addresses?.[moduleName];
            if (init_addresses && Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        } catch (_) { /* ignore */ }
    }
}
