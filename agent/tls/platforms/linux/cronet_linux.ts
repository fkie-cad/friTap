
import {Cronet } from "../../libs/cronet.js";
import { socket_library } from "../../../platforms/linux.js";
import {PatternBasedHooking } from "../../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced } from "../../../fritap_agent.js"
import { devlog } from "../../../util/log.js";
import { executeSSLLibrary } from "../../../shared/shared_functions.js";

export class Cronet_Linux extends Cronet {

    constructor(public moduleName:string, public socket_library:String, is_base_hook: boolean){
        super(moduleName,socket_library,is_base_hook);
    }

    install_key_extraction_pattern_hook(){
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
        this.install_key_extraction_pattern_hook();
    }

}


export function cronet_execute(moduleName:string, is_base_hook: boolean){
    executeSSLLibrary(Cronet_Linux, moduleName, socket_library, is_base_hook);
}