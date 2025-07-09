
import {GoTLS, symbol_writeKeyLog, GoTlsLogger } from "../ssl_lib/gotls.js";
import { socket_library } from "./android_agent.js";
import {PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced, experimental } from "../ssl_log.js"
import { devlog, devlog_error } from "../util/log.js";

export class GoTLS_Android extends GoTLS {
    private default_pattern: { [arch: string]: { primary: string; fallback: string, second_fallback?: string; } };

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);

        /*
         * Default patterns for GoTLS hooking.
         * These patterns are used to hook the writeKeyLog function in GoTLS but for now only the primary pattern for ARM64 is valid.
         */

        this.default_pattern = {
            "x64": {
                primary:  "90 0B 40 F9 F1 43 00 D1 3F 02 10 EB E9 10 00 54 FE 0F 17 F8 FD 83 1F F8 FD 23 00 D1 E1 53 00 F9 E3 5B 00 F9 E6 67 00 F9 09 94 40 F9 49 0F 00 B4", // Primary pattern
                fallback: "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84" // Fallback pattern
            },
            "x86": {
                primary: "90 0B 40 F9 F1 43 00 D1 3F 02 10 EB E9 10 00 54 FE 0F 17 F8 FD 83 1F F8 FD 23 00 D1 E1 53 00 F9 E3 5B 00 F9 E6 67 00 F9 09 94 40 F9 49 0F 00 B4", // Primary pattern
                fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60" // Fallback pattern
            },
            "arm64": {
                primary: "90 0B 40 F9 F1 43 00 D1 3F 02 10 EB E9 10 00 54 FE 0F 17 F8 FD 83 1F F8 FD 23 00 D1 E1 53 00 F9 E3 5B 00 F9 E6 67 00 F9 09 94 40 F9 49 0F 00 B4", // Primary pattern
                fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4", // Fallback pattern
            },  

            "arm": {
                primary: "90 0B 40 F9 F1 43 00 D1 3F 02 10 EB E9 10 00 54 FE 0F 17 F8 FD 83 1F F8 FD 23 00 D1 E1 53 00 F9 E3 5B 00 F9 E6 67 00 F9 09 94 40 F9 49 0F 00 B4", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };
    }

    getSoName(modulePath: string): string {
        // Match the last segment ending in “.so”
        const m = modulePath.match(/([^\/\\]+\.so)$/);
        return m ? m[1] : modulePath;
      }

    


    install_key_extraction_hook(){
        var instance = this;
        let goTLSModule = Process.findModuleByName(this.module_name);
        let soName = this.module_name;
        if(goTLSModule === null){
            soName   = this.getSoName(this.module_name);
            goTLSModule = Process.findModuleByName(soName);
            if(goTLSModule === null){
                devlog("[-] GoTLS Error: Unable to find module: " + this.module_name);
                return;
            }
        }
        if (this.addresses[this.module_name][symbol_writeKeyLog] === undefined || this.addresses[this.module_name][symbol_writeKeyLog] === null )  {

            if(experimental === false){
                devlog("[!] Pattern-based hooking for GoTLS may cause instability or crashes. To proceed anyway, rerun friTap with the --experimental flag.");
                return;
            }



            
            const hooker = new PatternBasedHooking(goTLSModule);

            if (isPatternReplaced()){
                devlog("Hooking GoTLS functions by patterns from JSON file");
                hooker.hook_DumpKeys(this.module_name,soName,patterns,(args: any[]) => {
                    devlog("Installed writeKeyLog() hooks using byte patterns.");
                    const labelPtr = args[2];
                    const labelLen = args[3].toInt32();
                    const crPtr = args[4];
                    const crLen = args[5].toInt32();
                    const secretPtr = args[7];
                    const secretLen = args[8].toInt32();
                    this.dumpKeys(labelPtr, labelLen, crPtr, crLen,  secretPtr, secretLen);  // Unpack args into dumpKeys
                });
            }else{
                // This are the default patterns for hooking writeKeyLog in GoTLS
                hooker.hookModuleByPattern(
                    get_CPU_specific_pattern(this.default_pattern),
                    (args) => {
                        devlog("Installed writeKeyLog() hooks using byte patterns.");
                        const labelPtr = args[2];
                        const labelLen = args[3].toInt32();
                        const crPtr = args[4];
                        const crLen = args[5].toInt32();
                        const secretPtr = args[7];
                        const secretLen = args[8].toInt32();
                        this.dumpKeys(labelPtr, labelLen, crPtr, crLen,  secretPtr, secretLen);  // Hook args passed to dumpKeys
                    }
                );
            }

            return hooker;
        }else{
            devlog("[GoTLS] writeKeyLog symbol available");
            var result = instance.install_tls_keys_callback_hook();
            let hooker = new GoTlsLogger(goTLSModule,true,result);
            return hooker;

        }

    }

    // instead of relying on pattern we check if the target module has a symbol of writeKeyLog()
    execute_symbol_based_hooking(hooker){
        if(hooker === undefined || hooker === null){
            devlog("[-] Error: Hooker is undefined.");
            return;
        }
        // Capture the dumpKeys function with the correct 'this'
        let dumpKeysFunc = this.dumpKeys.bind(this);

       

        if(hooker.no_hooking_success){
            let symbols = Process.getModuleByName(this.module_name).enumerateSymbols().filter(exports => exports.name.toLowerCase().includes("ssl_log"));
            if(symbols.length > 0){
                devlog("Installed writeKeyLog() hooks using sybmols.");
                try{
                    Interceptor.attach(symbols[0].address, {
                        onEnter: function(args) {
                            const labelPtr = args[2];
                            const labelLen = args[3].toInt32();
                            const crPtr = args[4];
                            const crLen = args[5].toInt32();
                            const secretPtr = args[7];
                            const secretLen = args[8].toInt32();
                            this.dumpKeys(labelPtr, labelLen, crPtr, crLen,  secretPtr, secretLen);  // Hook args passed to dumpKeys
                        }
                    });

                }catch(e){
                    // right now we ingore error's here
                }
            }


        }

    }

    execute_hooks(){
        // hooking writeKeyLog() from GoTLS
        let hooker_instance = this.install_key_extraction_hook();

        return hooker_instance;
    }

}


export function gotls_execute(moduleName:string, is_base_hook: boolean){
    let gotls = new GoTLS_Android(moduleName,socket_library,is_base_hook);
    try {
        let hooker = gotls.execute_hooks();
        // wait 1 sec before we continue
        setTimeout(function() {
            try{
                gotls.execute_symbol_based_hooking(hooker);
            }catch(e){
                devlog("[-] Error in gotls.execute_symbol_based_hooking: "+ e);
            } 
            
        }, 1500); 
    }catch(error_msg){
        devlog(`gotls_execute error: ${error_msg}`)
    }

    if (is_base_hook) {
        try {
            const init_addresses = gotls.addresses[moduleName];
            // ensure that we only add it to global when we are not 
            if (Object.keys(init_addresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = init_addresses;
            }
        }catch(error_msg){
            devlog(`gotls_execute base-hook error: ${error_msg}`)
        }
    }

}
