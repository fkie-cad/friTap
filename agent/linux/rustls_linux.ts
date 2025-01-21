import { socket_library } from "./linux_agent.js";
import { Rustls } from "../ssl_lib/rustls.js";
import { log, devlog } from "../util/log.js"

export class Rustls_Linux extends Rustls {

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

        // TODO: handle the case, that the application set its own keyLogCB. In this case the user set callback should be extracted and
        // hooked.
    }
}

export function rustls_execute(moduleName: string, is_base_hook: boolean) {
    var rus_tls = new Rustls_Linux(moduleName, socket_library, is_base_hook);
    rus_tls.execute_hooks();

    if (is_base_hook) {
        const init_addresses = rus_tls.addresses[moduleName];
        if (Object.keys(init_addresses).length > 0) {
            (global as any).init_addresses[moduleName] = init_addresses;
        }
    }
}