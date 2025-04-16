
import {Cronet } from "../ssl_lib/cronet.js";
import { socket_library } from "./android_agent.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog } from "../util/log.js";


export class Cronet_Android extends Cronet {
    private default_pattern: { [arch: string]: { primary: string; fallback: string } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
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
                //primary: "3F 23 03 D5 FF C3 01 D1 FD 7B 04 A9 F6 57 05 A9 F4 4F 06 A9 FD 03 01 91 08 34 40 F9 08 1? 41 F9 ?8 0? 00 B4" // Primary pattern old
                primary: "3F 23 03 D5 FF ?3 01 D1 FD 7B 0? A9 F6 57 0? A9 F4 4F 0? A9 FD ?3 0? 91 08 34 40 F9 08 1? 41 F9 ?8 0? 00 B4", // Primary pattern
                fallback: "3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 ?? 41 F9 ?8 0? 00 B4"  // Fallback pattern
            },  

            "arm": {
                primary: "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };
    }

    


    install_key_extraction_hook(){
        const cronetModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced()){
            devlog("Hooking libcronet functions by patterns from JSON file");
            hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns.");
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }else{
            // This are the default patterns for hooking ssl_log_secret in BoringSSL inside Cronet
            hooker.hookModuleByPattern(
                get_CPU_specific_pattern(this.default_pattern),
                (args) => {
                    devlog("Installed ssl_log_secret() hooks using byte patterns.");
                    this.dumpKeys(args[1], args[0], args[2]);  // Hook args passed to dumpKeys
                }
            );
        }

        return hooker;

    }

    // instead of relying on pattern we check if the target module has a symbol of ssl_log_secret()
    execute_symbol_based_hooking(hooker){
        // Capture the dumpKeys function with the correct 'this'
        let dumpKeysFunc = this.dumpKeys.bind(this);

        if(this.module_name.includes("libwarp_mobile")){
            console.log("[!] The extracted CLIENT_RANDOM from libwarp_mobile.so is currently not working correctly.");
        }

        if(hooker.no_hooking_success){
            let symbols = Process.getModuleByName(this.module_name).enumerateSymbols().filter(exports => exports.name.toLowerCase().includes("ssl_log"));
            if(symbols.length > 0){
                devlog("Installed ssl_log_secret() hooks using sybmols.");
                try{
                    Interceptor.attach(symbols[0].address, {
                        onEnter: function(args) {
                            dumpKeysFunc(args[1], args[0], args[2]);
                        }
                    });

                }catch(e){
                    // right now we ingore error's here
                }
            }


        }

    }

    execute_hooks(){
        // hooking ssl_log_secret() from BoringSSL
        let hooker_instance = this.install_key_extraction_hook();

        return hooker_instance;
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    let cronet = new Cronet_Android(moduleName,socket_library,is_base_hook);
    try {
        let hooker = cronet.execute_hooks();
        // wait 1 sec before we continue
        setTimeout(function() {
            cronet.execute_symbol_based_hooking(hooker);
        }, 1000); 
    }catch(error_msg){
        devlog(`cronet_execute error: ${error_msg}`)
    }

    if (is_base_hook) {
        try {
            const init_addresses = cronet.addresses[moduleName];
            // ensure that we only add it to global when we are not 
            if (Object.keys(init_addresses).length > 0) {
                (global as any).init_addresses[moduleName] = init_addresses;
            }
        }catch(error_msg){
            devlog(`cronet_execute base-hook error: ${error_msg}`)
        }
    }

}
