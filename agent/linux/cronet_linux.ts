
import {Cronet } from "../ssl_lib/cronet.js";
import { socket_library } from "./linux_agent.js";
import {PatternBasedHooking } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../ssl_log.js"
import { devlog } from "../util/log.js";

export class Cronet_Linux extends Cronet {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_key_extraction_hook(){
        const cronetModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(cronetModule);

        if (isPatternReplaced()){
            devlog("Hooking libcronet functions by pattern");
            hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
        }

        

        

        
    }

    execute_hooks(){
        this.install_key_extraction_hook();
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    var cronet = new Cronet_Linux(moduleName,socket_library,is_base_hook);
    cronet.execute_hooks();

    if (is_base_hook) {
        const init_addresses = cronet.addresses[moduleName];
        // ensure that we only add it to global when we are not 
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }

}