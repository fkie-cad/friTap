import { Rustls } from "../ssl_lib/rustls.js";
import { socket_library } from "./android_agent.js";
import { PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced} from "../ssl_log.js"
import { devlog } from "../util/log.js";

export class Rustls_Android extends Rustls {
    private default_pattern: { [arch: string]: { primary: string, fallback:string } };

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        super(moduleName, socket_library, is_base_hook);

        this.default_pattern = {
            "x64": {
                primary: "55 41 57 41 56 41 55 41 54 53 48 81 ec 88 01 00 00 4c 89 4c 24 30 4c 89 44 24 38 48 89 4c 24 40 48 89 54 24 48",
                fallback: "55 41 57 41 56 41 55 41 54 53 48 81 ec 88 01 00 00 4c 89 4c 24 30 4c 89 44 24 38 48 89 4c 24"
            }
        };
    }


    install_key_extraction_hook() {
        const rustlsModule = Process.findModuleByName(this.moduleName);
        const hooker = new PatternBasedHooking(rustlsModule);
        
        if (isPatternReplaced()) {
            devlog("Hooking librustls functions by patterns from JSON fiel");
            hooker.hook_DumpKeys(this.module_name, "librustls.so", patterns, (args: any[]) => {
                devlog("Installed derive_logged_secret() hooks using byte patterns.");
                this.dumpKeys_onEnter(args[6], args[0]);
            }, 
            (args) => {
                this.dumpKeys_onLeave();
            });
        } else {
            hooker.hookModuleByPattern (
                get_CPU_specific_pattern(this.default_pattern),
                (args: any) => {
                    devlog("Installed derived_logged_secret() hooks using byte patterns.");
                    this.dumpKeys_onEnter(args[6], args[0]);
                },
                (args) => {
                    this.dumpKeys_onLeave();
                }
            )
        }

        return hooker;
    }

    execute_hooks() {
        let hooker_instance = this.install_key_extraction_hook();

        return hooker_instance;
    }
}


export function rustls_execute(moduleName: string, is_base_hook: boolean) {
    let rustls = new Rustls_Android(moduleName, socket_library, is_base_hook);
    try {
        let hooker = rustls.execute_hooks();
    } catch (error_msg) {
        devlog(`rustls_execute error: ${error_msg}`);
    }

    if (is_base_hook) {
        try {
            const init_addresses = rustls.addresses[moduleName];
            if (Object.keys(init_addresses).length > 0) {
                (global as any).init_addresses[moduleName] = init_addresses;
            }
        } catch (error_msg){
            devlog(`rustls_execute base-hook error: ${error_msg}`);
        }
    }
}