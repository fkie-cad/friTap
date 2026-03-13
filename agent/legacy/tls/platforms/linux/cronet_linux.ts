
import {Cronet } from "../../../../tls/libs/cronet.js";
import { socket_library } from "../../../../platforms/linux.js";
import {PatternBasedHooking, get_CPU_specific_pattern, hasModulePatterns } from "../../../../tls/shared/pattern_based_hooking.js";
import { CRONET_X64_PATTERNS } from "../../../../tls/shared/cronet_patterns.js";
import { patterns, isPatternReplaced } from "../../../../fritap_agent.js"
import { devlog } from "../../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class Cronet_Linux extends Cronet {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        this.default_pattern = {
            "x64": CRONET_X64_PATTERNS,
            "arm64": {
                primary: "3F 23 03 D5 FF ?3 01 D1 FD 7B 0? A9 F6 57 0? A9 F4 4F 0? A9 FD ?3 0? 91 08 34 40 F9 08 1? 41 F9 ?8 0? 00 B4",
                fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4"
            }
        };
    }

    install_key_extraction_pattern_hook(){
        const cronetModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced() && hasModulePatterns(patterns, this.module_name, "libcronet.so")){
            devlog("Hooking libcronet functions by pattern");
            hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }else{
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    this.dumpKeys(args[1], args[0], args[2]);
                }
            );
        }






    }

    execute_hooks(){
        this.install_key_extraction_pattern_hook();
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(Cronet_Linux, moduleName, socket_library, is_base_hook);
}
