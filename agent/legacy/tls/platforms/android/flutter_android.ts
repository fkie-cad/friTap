
import { Flutter } from "../../../tls/libs/flutter.js";
import { socket_library } from "../../../../platforms/android.js";
import {PatternBasedHooking, get_CPU_specific_pattern, hasUsablePatternsFor } from "../../../tls/shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced, pairip_safe } from "../../../../fritap_agent.js"
import { devlog, devlog_debug, devlog_error } from "../../../../util/log.js";
import { installBoringSSLSymbolHook, scheduleBoringSSLSymbolFallback, type DumpKeysCb } from "../../../../shared/boringssl_symbol_hook.js";
import { guardKeylogDumpKeys } from "../../../../shared/boringssl_keylog_outcome.js";
import { lenArg } from "../../../../shared/keylog_length.js";


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
        // Guarded: the symbol tier or tier 4 may hook the same ssl_log_secret
        // while this scan still runs; only the first tier to deliver emits.
        const patternDumpKeys = guardKeylogDumpKeys(this.module_name, "pattern",
            (label, ssl, data, len) => this.dumpKeys(label, ssl, data, len));

        if (isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "libflutter.so", "Dump-Keys")){
            devlog("Hooking libflutter functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libflutter.so",patterns,(args: any[]) => {
                patternDumpKeys(args[1], args[0], args[2], lenArg(args[3]));  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Flutter
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    patternDumpKeys(args[1], args[0], args[2], lenArg(args[3]));  // Hook args passed to dumpKeys
                }
            );
        }
        return hooker;
    }

    execute_hooks(): PatternBasedHooking | null {
        return this.install_key_extraction_hook();
    }

}


/**
 * Symbol tier, then tier 4 (the anchor locator), once the byte patterns had a
 * settle window to match. Release engines often match neither the bundled
 * patterns nor a symbol, so a miss must reach tier 4 like the Cronet rows do;
 * a pattern that matched first keeps the module (no second hook).
 * --pairip-safe keeps the symbol tier only: tier 4 is a memory scan.
 */
export function scheduleFlutterKeylogFallback(
    moduleName: string,
    hooker: PatternBasedHooking | null,
    dumpKeys: DumpKeysCb,
    pairipSafe: boolean = pairip_safe,
): void {
    if (!pairipSafe) {
        scheduleBoringSSLSymbolFallback(moduleName, hooker, () => installBoringSSLSymbolHook(moduleName, dumpKeys), dumpKeys);
        return;
    }
    setTimeout(() => {
        try {
            if (hooker !== null && !hooker.no_hooking_success) return;
            devlog_debug("Trying symbol-based ssl_log_secret hook on " + moduleName);
            installBoringSSLSymbolHook(moduleName, dumpKeys);
        } catch (e) {
            devlog_error("flutter_execute symbol fallback error: " + e);
        }
    }, 1000);
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
    // The 4th `len` arg is passed through so SHA-384 secrets (48 bytes) are
    // not truncated to 32.
    if (is_base_hook) {
        scheduleFlutterKeylogFallback(moduleName, hooker,
            (label, ssl, data, len) => flutter.dumpKeys(label, ssl, data, len));
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
