
import {Cronet } from "../ssl_lib/cronet.js";
import { socket_library } from "./android_agent.js";
import {PatternBasedHooking } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog } from "../util/log.js";

export class Cronet_Android extends Cronet {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_key_extraction_hook(){
        const cronetModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced()){
            devlog("Hooking libcronet functions by pattern");
            hooker.hook_with_pattern_from_json(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Cronet
            hooker.hookModuleByPattern(
                {
                    primary: "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 C8 07 00 B4", // Primary pattern
                    fallback: "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 11 41 F9 E8 0F 00 B4"  // Fallback pattern
                },
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


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    var cronet = new Cronet_Android(moduleName,socket_library,is_base_hook);
    cronet.execute_hooks();

    if (is_base_hook) {
        const init_addresses = cronet.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }

}