import { socket_library } from "../../../../platforms/linux.js";
import { RusTLS } from "../../libs/rustls.js";
import { log, devlog } from "../../../../util/log.js"
import { toHexString } from "../../../../shared/shared_functions.js";
import { hasMoreThanFiveExports } from "../../../shared/shared_functions_legacy.js";
import { sendKeylog } from "../../../../shared/shared_structures.js";
import { PatternBasedHooking, get_CPU_specific_pattern, hasUsablePatternsFor } from "../../../../tls/shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced} from "../../../../fritap_agent.js"
import { installRustlsStaticPatternHooks } from "../../../../tls/shared/rustls_static_patterns.js";

export class Rustls_Linux extends RusTLS {
    private default_pattern: { [arch: string]: { primary: string, fallback:string } };
    private default_pattern_12: { [arch: string]: { primary: string, fallback:string } };

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        super(moduleName, socket_library, is_base_hook);

        this.default_pattern = {
            "x64": {
                primary:  "48 81 EC 18 01 00 00 4C 89 4C 24 40 48 89 7C 24 48 88 D0 48 89 7C 24 50 48 8B 94 24 28 01 00 00 48 89 54 24 58 48 8B 94 24 20 01 00 00 48 89",
                fallback: "48 81 EC 18 01 00 00 4C 89 4C 24 40 48 89 7C 24 48 88 D0 48 89 7C 24 50 48 8B 94 24 28 01 00 00 48 89 54 24 58 48 8B 94 24 20 01"
            }
        };

        this.default_pattern_12 = {
            "x64": {
                primary:  "41 57 41 56 53 48 81 ec c0 04 00 00 4c 89 8c 24 a0 00 00 00 4c 89 44 24 70 48 89 4c 24 78 48 89 bc 24 80 00 00 00 48 89 bc 24 88 00 00 00 48 8b",
                fallback: "41 57 41 56 53 48 81 ec c0 04 00 00 4c 89 8c 24 a0 00 00 00 4c 89 44 24 70 48 89 4c 24 78 48 89 bc 24 80 00 00 00 48 89 bc 24 88"
            }
        }
    }

    execute_pattern_hooks(){
        this.install_key_extraction_hook();

    }


    install_key_extraction_hook(){
        const rusTLSModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(rusTLSModule);

        // --patterns JSON for "rustls" wins; otherwise the shared static-rustls table
        // (statically linked rustls 0.22/0.23, arm64 + x64) first, and the older built-in
        // x64 patterns below only for a TLS version the table did not hook.
        const usesJsonPatterns = isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "rustls", "Dump-Keys");
        const shared = usesJsonPatterns ? { tls13: false, tls12: false } : installRustlsStaticPatternHooks(rusTLSModule);

        if (!shared.tls13) this.install_key_extraction_hook_tls(hooker);
        if (!shared.tls12) this.install_key_extraction_hook_tls_12(hooker);
    }

    install_key_extraction_hook_tls_12(hooker: PatternBasedHooking) {
        const doDumpKeysLogic = (args: any[], retval: NativePointer | undefined) => {
            let client_random_ptr: NativePointer;
            let master_secret_ptr: NativePointer;

            client_random_ptr = args[6];
            // retval structure:
            // | header (8 bytes) | client_random(32 bytes) | server_random(32 bytes) | master_secret(48 bytes) |
            master_secret_ptr = retval.add(72);

            this.dumpKeysFromPRF(client_random_ptr, master_secret_ptr);
        };

        // Wrapper 1: for the "normal" pattern. Only proceed if retval is null.
        const normalPatternCallback = (args: any[], retval?: NativePointer) => {
            if (!retval){
                devlog("retval is null");
                return;          // In case hooking is onEnter, ignore
            }
            if (!retval.isNull()) {
                //devlog("[normal pattern] [TLS 1.2] hooking triggered, retval is null. Doing work.");
                doDumpKeysLogic(args, retval);
            }
        };



        // Decide whether to hook from JSON patterns or from built-in patterns ( "_ex" vs. normal)
        if (isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "rustls", "Dump-Keys")) {
            hooker.hook_DumpKeys(
                this.module_name,
                // Pick the JSON module name based on whether it's "ex"
                "rustls",
                patterns,
                normalPatternCallback,
                true, // onReturn so we get retval
                7
            );
        } else {
            hooker.hookModuleByPatternOnReturn(
                // Pick the default pattern based on whether it's "ex"
                get_CPU_specific_pattern(this.default_pattern_12),
                normalPatternCallback,
                7
            );
        }
    }

    install_key_extraction_hook_tls(hooker: PatternBasedHooking){

        const doDumpKeysLogic = (args: any[], retval: NativePointer | undefined) => {
            // Decide offsets for client_random_ptr, key, key_len, label_enum
            let client_random_ptr: NativePointer;
            let key: NativePointer;
            let label_enum: number;

            client_random_ptr = args[7];
            key               = args[0];
            label_enum        = args[2].toInt32();

            this.dumpKeysFromDeriveLogged(client_random_ptr, key, label_enum);
        };

        // Wrapper 1: for the "normal" pattern. Only proceed if retval is null.
        const normalPatternCallback = (args: any[], retval?: NativePointer) => {
            //devlog("[TLS 1.3] normalPatternCallback");
            if (!retval) return;          // to ensure we don't get a runtime exception when retval is undefined
            if (retval.isNull()) {
                doDumpKeysLogic(args, retval);
            } else {
                //
                if (Process.arch === "x64") {
                    doDumpKeysLogic(args, retval);
                }
            }
        };

        // Decide whether to hook from JSON patterns or from built-in patterns
        if (isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "rustls", "Dump-Keys")) {
            hooker.hook_DumpKeys(
                this.module_name,
                "rustls",
                patterns,
                normalPatternCallback,
                true, // onReturn so we get retval
                9
            );
        } else {
            hooker.hookModuleByPatternOnReturn(
                get_CPU_specific_pattern(this.default_pattern),
                normalPatternCallback,
                9
            );
        }

    }

    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    // Extract the configBuilder from call to rustls_client_config_builder_new / _custom and set keyLogCB.
    // Shared, fixed implementation in the legacy RusTLS base class (new_custom writes the
    // builder through its out-parameter; its return value is a rustls_result status).
    install_tls_keys_callback_hook(): boolean {
        return super.install_tls_keys_callback_hook();
    }
}

export function rustls_execute(moduleName: string, is_base_hook: boolean) {
    var rusTLS = new Rustls_Linux(moduleName, socket_library, is_base_hook);
    if(hasMoreThanFiveExports(moduleName)){
        devlog("Trying to hook RusTLS using symbols...");
        rusTLS.execute_hooks();
    }else{
        devlog("Trying to hook RusTLS using patterns...");
        rusTLS.execute_pattern_hooks();
    }


    if (is_base_hook) {
        const init_addresses = rusTLS.addresses[moduleName];
        if (Object.keys(init_addresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = init_addresses;
        }
    }
}
