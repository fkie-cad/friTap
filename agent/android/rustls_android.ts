import { socket_library } from "./android_agent.js";
import { RusTLS } from "../ssl_lib/rustls.js";
import { log, devlog } from "../util/log.js"
import { hasMoreThanFiveExports } from "../shared/shared_functions.js";
import { PatternBasedHooking, get_CPU_specific_pattern } from "../shared/pattern_based_hooking.js";
import { patterns, isPatternReplaced} from "../ssl_log.js"

export class Rustls_Android extends RusTLS {
    private default_pattern_tls13: { [arch: string]: { primary: string, fallback:string } };
    private default_pattern_ex_tls13: { [arch: string]: { primary: string, fallback:string } };
    private default_pattern_tls12: { [arch: string]: { primary: string, fallback:string } };

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        super(moduleName, socket_library, is_base_hook);

        /*
        used for the librustls_android_13.so and its variants
        */

        this.default_pattern_tls13 = {
            "x64": {
                //primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84", // Primary pattern
                primary:  "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C 24 18 49 89 D6 49 89 F4 48 89 FB 0F B6 C1 C1 E0 03 48 8D",
                fallback: "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C" // Fallback pattern
            },
            "x86": {
                primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34", // Primary pattern
                fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60" // Fallback pattern
            },
            "arm64": {
                primary:  "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A ?8 0? 00 ?0 08 ?1 ?? 91 C9 1E 40", // Primary pattern
                fallback: "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A ?8 0? 00 ?0 08"  // Fallback pattern
            },

            "arm": {
                primary:  "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };

         /*
        used for the librustls_android_13_ex.so and its variants
        */

        this.default_pattern_ex_tls13 = {
            "x64": {
                //primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84", // Primary pattern
                primary:  "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C 24 18 49 89 D6 49 89 F4 48 89 FB 0F B6 C1 C1 E0 03 48 8D",
                fallback: "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C" // Fallback pattern
            },
            "x86": {
                primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34", // Primary pattern
                fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60" // Fallback pattern
            },
            "arm64": {
                primary:  "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A 88 0C 00 F0 08 E1 3B 91 C9 1E 40", // Primary pattern
                fallback: "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A 88 0C 00 F0 08 E1"  // Fallback pattern
            },

            "arm": {
                primary:  "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0", // Primary pattern
                fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0"  // Fallback pattern
            }
        };

        // FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A E8 0B 00 90 08 E1 14 91 C9 1E 40 92 1F 20 03 D5 0A 60 8A 10 1C 79 69 F8 48 14 40 F9 FB 93 40 F9 5D 79 69 F8 F3 03 00 AA E0 03 01 AA F4 03 07 AA F5 03 06 AA F8 03 05 AA F9 03 04 AA FA 03 02 AA F7 03 01 AA 00 01 3F D6
        this.default_pattern_tls12 = {
            "x64": {
                primary:  "55 41 57 41 56 41 55 41 54 53 48 81 ec 48 01 00 00 4c 89 c0 49 89 cb 49 89 d6 49 89 f7 48 89 fb 48 8b 8c 24 88 01 00 00 48 8b 94 24 80 01 00",
                fallback: "55 41 57 41 56 41 55 41 54 53 48 81 ec 48 01 00 00 4c 89 c0 49 89 cb 49 89 d6 49 89 f7 48 89 fb 48 8b 8c 24 88 01 00 00 48 8b"
            },
            "arm64": {
                primary:  "FF 03 07 D1 FD 7B 19 A9 F6 57 1A A9 F4 4F 1B A9 A1 08 40 AD 03 E4 00 6F F3 03 08 AA 88 00 40 B9 EB 03 03 AA E9 03 02 AA F4 03 01 AA F5 03 00 AA E1 0B 01 AD A0 04 41 AD F6 43 02 91 E3 8F 03 AD E6 0F 00 F9 E0 03 84 3C E1 8F 02 AD", // Primary pattern
                fallback: "FF 03 07 D1 FD 7B 19 A9 F6 57 1A A9 F4 4F 1B A9 A1 08 40 AD 03 E4 00 6F F3 03 08 AA 88 00 40 B9 EB 03 03 AA E9 03 02 AA F4 03 01 AA F5 03 00 AA E1 0B 01 AD A0 04 41 AD F6 43 02 91 E3" // Fallback pattern
            },
            "arm": {
                primary:  "2D E9 F0 4F D1 B0 0A AD 8A 46 05 F1 44 07 81 46 30 21 1C 46 38 46 93 46 FB F0 A8 F9 5C 9E 28 1D 40 22 31 46 FB F0 2D FA 5B 99 DD F8 74 81 CD",
                fallback: "2D E9 F0 4F D1 B0 0A AD 8A 46 05 F1 44 07 81 46 30 21 1C 46 38 46 93 46 FB F0 A8 F9 5C 9E 28 1D 40 22 31 46 FB F0 2D FA 5B 99"
            }
        }

    }


    execute_pattern_hooks(){
        this.install_key_extraction_hook();

    }

    install_key_extraction_hook(){
        const rusTLSModule = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(rusTLSModule);

        const isEx = this.module_name.includes("_ex");
        const isX64 = Process.arch === "x64";

        this.install_key_extraction_hook_tls13(hooker, isEx, isX64);
        if (!isPatternReplaced()) {
            // Currently no support for tls12 json pattern
            this.install_key_extraction_hook_tls12(hooker, isEx, isX64);
        }
    }

    // This has been tested for x86_64 and ARM
    install_key_extraction_hook_tls12(hooker: PatternBasedHooking, isEx: boolean, isX64: boolean){

        const doDumpKeysLogic = (args: any[], retval: NativePointer | undefined) => {
            let client_random_ptr: NativePointer;
            let master_secret_ptr: NativePointer;

            if (Process.arch === "arm64") {
                /*
                ARM LAYOUT:
                    args[3] = 0x20 (random_size?)
                    args[5] = | client_random (32 byte) | server_random (32 byte) | padding (8 byte) | 
                              | client_random (32 byte) | server_random (32 byte) | master_secret (48 byte) |
                    args[7] = some address (cannot read or attach)
                    args[8] = NULL
                    retval = status code of some kind
                */
                client_random_ptr = args[5];
                master_secret_ptr = args[5].add(136);
            } else {
                // works for x64
                client_random_ptr = args[6];

                // retval structure:
                // | header (8 bytes) | client_random(32 bytes) | server_random(32 bytes) | master_secret(48 bytes) |
                master_secret_ptr = retval.add(72);
            }

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
            devlog(`[Hooking with JSON patterns onReturn] isEx = ${isEx}`);
            hooker.hook_DumpKeys(
                this.module_name,
                // Pick the JSON module name based on whether it’s “ex”
                isEx ? "librustls_ex.so" : "librustls.so",
                patterns,
                normalPatternCallback,
                true, // onReturn so we get retval
                isX64 ? 7 : 8
            );
        } else {
            devlog(`[Hooking with built-in fallback patterns onReturn] isEx = ${isEx}`);
            hooker.hookModuleByPatternOnReturn(
                // Pick the default pattern based on whether it’s “ex”
                get_CPU_specific_pattern(isEx ? this.default_pattern_tls12 : this.default_pattern_tls12),
                normalPatternCallback,
                isX64 ? 7 : 8
            );
        }

    }


    install_key_extraction_hook_tls13(hooker: PatternBasedHooking, isEx: boolean, isX64: boolean){

        const doDumpKeysLogic = (args: any[], retval: NativePointer | undefined) => {
            // Decide offsets for client_random_ptr, key, key_len, label_enum
            let client_random_ptr: NativePointer;
            let key: NativePointer;
            let key_len: number;
            let label_enum: number;

            // tested for x86_64, and ARM64
            client_random_ptr = args[9];
            key               = args[0];
            key_len           = args[5].toInt32();
            label_enum        = args[3].toInt32();         

            this.dumpKeysFromDeriveSecrets(client_random_ptr, key, key_len, label_enum);
        };

        // Wrapper 1: for the "normal" pattern. Only proceed if retval is null.
        const normalPatternCallback = (args: any[], retval?: NativePointer) => {
            //devlog("[TLS 1.3] normalPatternCallback");
            if (!retval) return;          // to ensure we don't get a runtime exception when retval is undefined
            if (retval.isNull()) {
                doDumpKeysLogic(args, retval);
            } else {
                
                if (Process.arch === "x64" || Process.arch === "arm64") {
                    doDumpKeysLogic(args, retval);
                }

            }
        };

        // Wrapper 2: for the "ex" pattern. Only proceed if retval is not null.
        const exPatternCallback = (args: any[], retval?: NativePointer) => {
            //devlog("[TLS 1.3] exPatternCallback");
            if (!retval) return;          // to ensure we don't get a runtime exception when retval is undefined
            if (!retval.isNull()) {
                doDumpKeysLogic(args, retval);
            } else {
                //
            }
        };

        // Decide whether to hook from JSON patterns or from built-in patterns ( “_ex” vs. normal)
        if (isPatternReplaced()) {
            devlog(`[Hooking with JSON patterns onReturn] isEx = ${isEx}`);
            hooker.hook_DumpKeys(
                this.module_name,
                // Pick the JSON module name based on whether it’s “ex”
                isEx ? "librustls_ex.so" : "librustls.so",
                patterns,
                isEx ? exPatternCallback : normalPatternCallback,
                true, // onReturn so we get retval
                isX64 ? 7 : 9
            );
        } else {
            devlog(`[Hooking with built-in fallback patterns onReturn] isEx = ${isEx}`);
            hooker.hookModuleByPatternOnReturn(
                // Pick the default pattern based on whether it’s “ex”
                get_CPU_specific_pattern(isEx ? this.default_pattern_ex_tls13 : this.default_pattern_tls13),
                isEx ? exPatternCallback : normalPatternCallback,
                isX64 ? 7 : 9
            );
            // Note: for ARM it seems, that normalPatternCallback is used for both client types (but it succeeds to extract the secrets)
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
    var rusTLS = new Rustls_Android(moduleName, socket_library, is_base_hook);
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