
import {Cronet } from "../ssl_lib/cronet.js";
import { socket_library } from "./android_agent.js";
import {PatternBasedHooking } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog } from "../util/log.js";
import { rustls_execute } from "./rustls_android.js";


export class Pattern_Android extends Cronet {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_key_extraction_hook(){
        if(isPatternReplaced){
            const patternModuleName = Process.findModuleByName(this.module_name);
            const hooker = new PatternBasedHooking(patternModuleName);

            hooker.hook_DumpKeys(this.module_name,this.module_name,patterns,(args: any[]) => {
                devlog(`Installed ssl_log_secret() hooks using byte patterns for module ${this.module_name}`);
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });

            return hooker;
        }else{
            return null;
        }

    }

    // instead of relying on pattern we check if the target module has a symbol of ssl_log_secret()
    execute_symbol_based_hooking(hooker){
        // Capture the dumpKeys function with the correct 'this'
        let dumpKeysFunc = this.dumpKeys.bind(this);

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

    execute_boring_ssl_log_secret_hooks(){
        // hooking ssl_log_secret() from BoringSSL
        let hooker_instance = this.install_key_extraction_hook();
        return hooker_instance;
    }

}


export function pattern_execute(moduleName:string, is_base_hook: boolean){

    switch (true) {
        case moduleName.includes("boringssl"):
            let pattern_BoringSSL = new Pattern_Android(moduleName,socket_library,is_base_hook);
            try {
                let hooker = pattern_BoringSSL.execute_boring_ssl_log_secret_hooks();
                if(hooker != null){
                    // wait 1 sec before we continue
                    setTimeout(function() {
                        pattern_BoringSSL.execute_symbol_based_hooking(hooker);
                    }, 1000); 
                }
            }catch(error_msg){
                devlog(`pattern_execute error: ${error_msg}`)
            }

            if (is_base_hook) {
                try {
                    const init_addresses = pattern_BoringSSL.addresses[moduleName];
                    // ensure that we only add it to global when we are not 
                    if (Object.keys(init_addresses).length > 0) {
                        (global as any).init_addresses[moduleName] = init_addresses;
                    }
                }catch(error_msg){
                    devlog(`pattern_execute base-hook error: ${error_msg}`)
                }
            }
            break;
        case moduleName.includes("rustls"):
            rustls_execute(moduleName, is_base_hook);
            break;
        default:
            devlog(`Unsupported Module: ${moduleName}! Trying to hook boringssl (default) with patterns!`);
            let pattern_Default = new Pattern_Android(moduleName,socket_library,is_base_hook);
            try {
                let hooker = pattern_Default.execute_boring_ssl_log_secret_hooks();
                if(hooker != null){
                    // wait 1 sec before we continue
                    setTimeout(function() {
                        pattern_Default.execute_symbol_based_hooking(hooker);
                    }, 1000); 
                }
            }catch(error_msg){
                devlog(`pattern_execute error: ${error_msg}`)
            }

            if (is_base_hook) {
                try {
                    const init_addresses = pattern_Default.addresses[moduleName];
                    // ensure that we only add it to global when we are not 
                    if (Object.keys(init_addresses).length > 0) {
                        (global as any).init_addresses[moduleName] = init_addresses;
                    }
                }catch(error_msg){
                    devlog(`pattern_execute base-hook error: ${error_msg}`)
                }
            }
    }

    

}