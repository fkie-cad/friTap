import { socket_library } from "./linux_agent.js";
import { RusTLS } from "../ssl_lib/rustls.js";
import { log, devlog } from "../util/log.js"
import { hasMoreThanFiveExports } from "../shared/shared_functions.js";
import { PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced} from "../ssl_log.js"

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

        this.install_key_extraction_hook_tls(hooker);
        this.install_key_extraction_hook_tls_12(hooker);
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

       

        // Decide whether to hook from JSON patterns or from built-in patterns ( “_ex” vs. normal) 
        if (isPatternReplaced()) {
            hooker.hook_DumpKeys(
                this.module_name,
                // Pick the JSON module name based on whether it’s “ex”
                "rustls",
                patterns, 
                normalPatternCallback,
                true, // onReturn so we get retval
                7
            );
        } else {
            hooker.hookModuleByPatternOnReturn(
                // Pick the default pattern based on whether it’s “ex”
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
        if (isPatternReplaced()) {
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

    // Extract the configBuilder from call to rustls_client_config_builder_new / _custom and set keyLogCB
    install_tls_keys_callback_hook() {
        RusTLS.rustls_client_config_set_key_log = new NativeFunction(this.addresses[this.moduleName]["rustls_client_config_builder_set_key_log"], 'uint32', ['pointer', 'pointer', 'pointer']);

        // Attach to both functions, which can create a config builder
        Interceptor.attach(this.addresses[this.moduleName]["rustls_client_config_builder_new"],
            {
                onLeave: function(retval: NativePointer) {
                    if (retval.isNull()) {
                        devlog("Error: retval is null");
                        return;
                    }
                    RusTLS.rustls_client_config_set_key_log(retval, RusTLS.keyLogCB, ptr('0'));
                    devlog("Attached keyLogCB to rustls_client_config_set_key_log");
                }
            })

        Interceptor.attach(this.addresses[this.moduleName]["rustls_client_config_builder_new_custom"],
            {
                onLeave: function(retval: NativePointer) {
                    if (retval.isNull()) {
                        devlog("Error: retval is null");
                        return;
                    }
                    RusTLS.rustls_client_config_set_key_log(retval, RusTLS.keyLogCB, ptr('0'));
                    devlog("Attached keyLogCB to rustls_client_config_set_key_log");
                }
            })
        
        // If the target sets its own Callback, Rustls.keyLogCB will be overwritten.
        // In this case we want to hook the Callback set by user. 
        Interceptor.attach(this.addresses[this.moduleName]["rustls_client_config_builder_set_key_log"], 
            {
                onEnter: function(args: any) {
                    // Extract the Address of the new Callback
                    var userCallbackAddress = args[1];
                    devlog("User set CB to: " + userCallbackAddress);
                    this.userCallbackAddress = userCallbackAddress;
                },
                onLeave: function(retval: any) {
                    // Check if the Callback was set
                    if (retval != 7000) {
                        // If the Callback was not set the keyLogCB has not been overwritten.
                        return;
                    } else {
                        // In case the keyLogCB has been overwritten, we attach to it.
                        Interceptor.attach(this.userCallbackAddress, {
                            onEnter(args: any) {
                                devlog ("Hooking user-defined callback for Rustls");
                                var message: { [key: string]: string | number | null } = {};
                                message["contentType"] = "keylog";

                                // Parse the arguments
                                var labelPtr = args[0];
                                var label_len = args[1].toInt32();
                                var client_random: NativePointer = args[2];
                                var client_random_len = args[3].toInt32();
                                var secret: NativePointer = args[4];
                                var secret_len = args[5].toInt32();

                                if (client_random.isNull() || client_random_len != 32) {
                                    devlog("Invalid client_random: " + client_random + " or client_random_lenght: " + client_random_len);
                                    return;
                                }

                                if (secret.isNull() || secret_len <= 0 || secret_len > 48) {
                                    devlog("Invalid secret or secret_length");
                                    return;
                                }
                                                               

                                // Read the client random and secrets as strings
                                var clientRandomStr = client_random.readByteArray(client_random_len);
                                var secretStr = secret.readByteArray(secret_len);
                                var labelStr = labelPtr.readUtf8String(label_len);

                                // Convert byte arrays to hex strings for better logging
                                var clientRandomHex = Array.from(new Uint8Array(clientRandomStr)).map(b => b.toString(16).padStart(2, '0')).join('');
                                var secretHex = Array.from(new Uint8Array(secretStr)).map(b => b.toString(16).padStart(2, '0')).join('');

                                // Construct the keylog message
                                message["keylog"] = `${labelStr} ${clientRandomHex} ${secretHex}`;
                                send(message);

                                return 1;
                            }
                        })
                    }
                }
            })
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
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }
}