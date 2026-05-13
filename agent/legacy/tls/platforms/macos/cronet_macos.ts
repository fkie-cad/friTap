
import {Cronet } from "../../../../tls/libs/cronet.js";
import { socket_library } from "../../../../platforms/macos.js";
import {PatternBasedHooking, get_CPU_specific_pattern, hasModulePatterns } from "../../../../tls/shared/pattern_based_hooking.js";
import { CRONET_X64_PATTERNS } from "../../../../tls/shared/cronet_patterns.js";
import { patterns, isPatternReplaced } from "../../../../fritap_agent.js"
import { devlog, devlog_debug, devlog_error } from "../../../../util/log.js";
import { scheduleBoringSSLSymbolFallback, installBoringSSLSymbolHook } from "../../../../shared/boringssl_symbol_hook.js";
import { lenArg } from "../../../../shared/keylog_length.js";

export type HookingResult = [success: boolean, handle: PatternBasedHooking | null];

export class Cronet_MacOS extends Cronet {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": CRONET_X64_PATTERNS,
            "arm64": {
                primary: "FF 83 01 D1 F6 57 03 A9 F4 4F 04 A9 FD 7B 05 A9 FD 43 01 91 08 34 40 F9 08 51 41 F9 48 08 00 B4",
                fallback: "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4"
            }
        };
    }

    install_key_extraction_pattern_hook(): PatternBasedHooking | null {
        const cronetModule = Process.findModuleByName(this.module_name);
        if (cronetModule === null) return null;
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced() && hasModulePatterns(patterns, this.module_name, "Cronet")){
            devlog("Hooking Cronet functions by pattern");
            hooker.hook_DumpKeys(this.module_name,"Cronet",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2], lenArg(args[3]));
            });
        }else{
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    this.dumpKeys(args[1], args[0], args[2], lenArg(args[3]));
                }
            );
        }
        return hooker;
    }

    execute_hooks(): HookingResult {
        const hooker = this.install_key_extraction_pattern_hook();
        if (hooker === null) return [false, null];
        return [!hooker.no_hooking_success, hooker];
    }

    // Symbol-based fallback for ssl_log_secret. Forwards the 4th `len` arg to
    // dumpKeys so safeKeyLen can use the exact length from bssl::ssl_log_secret's
    // ABI rather than falling back to the byte-walk heuristic.
    execute_symbol_based_hooking(hooker: PatternBasedHooking){
        if (!hooker.no_hooking_success) return;

        devlog_debug("Trying symbol-based ssl_log_secret hook on " + this.module_name);
        installBoringSSLSymbolHook(
            this.module_name,
            (label, ssl, data, len) => this.dumpKeys(label, ssl, data, len)
        );
    }
}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    let cronet: Cronet_MacOS;
    try {
        cronet = new Cronet_MacOS(moduleName, socket_library, is_base_hook);
    } catch (e) {
        devlog_error(`cronet_execute constructor error for ${moduleName}: ${e}`);
        return;
    }

    let success = false;
    let hooker: PatternBasedHooking | null = null;
    try {
        [success, hooker] = cronet.execute_hooks();
    } catch (e) {
        devlog_error(`cronet_execute error: ${e}`);
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
            if (init_addresses && Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        } catch (e) {
            devlog_error(`cronet_execute base-hook error: ${e}`);
        }
    }
}
