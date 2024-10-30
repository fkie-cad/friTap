
import { Mono_BTLS } from "../ssl_lib/monobtls.js";
import { socket_library } from "./android_agent.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog, devlog_error } from "../util/log.js";


export class Mono_BTLS_Android extends Mono_BTLS {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": {
                primary: "55 41 57 41 56 41 54 53 49 89 D4 49 89 F6 48 89 FB E8 5A F8 FF FF", // Primary pattern
                fallback: "55 41 57 41 56 41 55 41 54 53 48 83 EC 38 48 8B 47 68 48 83 B8 10 02 00 00 00 0F 84 19 01 00 00" // Fallback pattern
            },             
            "x86": {
                primary: "55 89 E5 53 57 56 83 E4 F0 83 EC 10 E8 00 00 00 00", // Primary pattern
                fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34" // Fallback pattern
            },
            "arm64": {
                primary: "F6 57 BD A9 F4 4F 01 A9 FD 7B 02 A9 FD 83 00 91 F3 03 02 AA F4 03 01 AA F5 03 00 AA 1F FE FF 97", // Primary pattern
                fallback: "FF 83 01 D1 F6 1B 00 F9 F5 53 04 A9 F3 7B 05 A9 08 34 40 F9 08 09 41 F9 68 07 00 B4"  // Fallback pattern
            },
            "arm": {
                primary: "F0 B5 03 AF 4D F8 04 8D 14 46 0D 46 06 46 FF F7 5F FD", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };
    }

    


    install_key_extraction_hook(){
        const flutterModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(flutterModule);

        if (isPatternReplaced()){
            devlog("Hooking Libmono functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libmono-btls-shared.so",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Libmono
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    this.dumpKeys(args[1], args[0], args[2]);  // Hook args passed to dumpKeys
                }
            );
        }

    }

    execute_hooks(){
        this.install_key_extraction_hook();
    }

}


export function mono_btls_execute(moduleName:string, is_base_hook: boolean){
    var mono_btls = new Mono_BTLS_Android(moduleName,socket_library,is_base_hook);
    try {
        mono_btls.execute_hooks();
    }catch(error_msg){
        devlog_error(`mono_btls_execute error: ${error_msg}`)
    }

    if (is_base_hook) {
        try {
            const init_addresses = mono_btls.addresses[moduleName];
            // ensure that we only add it to global when we are not 
            if (Object.keys(init_addresses).length > 0) {
                (global as any).init_addresses[moduleName] = init_addresses;
            }
        }catch(error_msg){
            devlog_error(`mono_btls_execute base-hook error: ${error_msg}`)
        }
    }

}