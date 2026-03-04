
import { Flutter } from "../../libs/flutter.js";
import { socket_library } from "../../../platforms/ios.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../../../fritap_agent.js"
import { devlog, devlog_error } from "../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions.js";


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

    


    install_key_extraction_hook(){
        const flutterModule = Process.findModuleByName(this.module_name);
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

    }

    execute_hooks(){
        this.install_key_extraction_hook();
    }

}


export function flutter_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(Flutter_iOS, moduleName, socket_library, is_base_hook, { tryCatch: true });
}