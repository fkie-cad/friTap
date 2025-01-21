import { socket_library } from "./android_agent.js";
import { Rustls } from "../ssl_lib/rustls.js";
import { log, devlog } from "../util/log.js"

export class Rustls_Android extends Rustls {

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        super(moduleName, socket_library);
    }

    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        this.install_tls_keys_callback_hook();
    }

    // Extract the configBuilder from call to rustls_client_config_builder_new / _custom and set keyLogCB
    install_tls_keys_callback_hook() {
        Rustls.rustls_client_config_set_key_log = new NativeFunction(this.addresses[this.moduleName]["rustls_client_config_builder_set_key_log"], 'uint32', ['pointer', 'pointer', 'pointer']);

        // Attach to both functions, which can create a config builder
        Interceptor.attach(this.addresses[this.moduleName]["rustls_client_config_builder_new"],
            {
                onLeave: function(retval: NativePointer) {
                    if (retval.isNull()) {
                        devlog("Error: retval is null");
                        return;
                    }
                    Rustls.rustls_client_config_set_key_log(retval, Rustls.keyLogCB, ptr('0'));
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
                    Rustls.rustls_client_config_set_key_log(retval, Rustls.keyLogCB, ptr('0'));
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
    var rus_tls = new Rustls_Android(moduleName, socket_library, is_base_hook);
    rus_tls.execute_hooks();

    if (is_base_hook) {
        const init_addresses = rus_tls.addresses[moduleName];
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }
}