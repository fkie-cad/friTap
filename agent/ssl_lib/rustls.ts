import { readAddresses, getBaseAddress, getPortsAndAddresses} from "../shared/shared_functions.js"
import { offsets, enable_default_fd } from "../ssl_log.js" 
import { log, devlog } from "../util/log.js"

export class Rustls {

    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;

    static rustls_client_config_builder_new: any;
    static rustls_client_config_builder_new_custom: any;
    static rustls_client_config_set_key_log: any;

    // Callbackfuntion for logging keying material
    static keyLogCB = new NativeCallback (function(label: [NativePointer, UInt64], client_random: NativePointer, client_random_len: UInt64 , secret: NativePointer, secret_size:UInt64) {
        devlog("invoking keyLogCB from rustls");
        var message: { [key: string]: string | number | null } = {};
        message["contentType"] = "keylog";
        var labelStr: string;

        // If no label is provided the keyLog should begin with "CLIENT_RANDOM "
        if (label[1].toNumber() == 0) {
            labelStr = "CLIENT_RANDOM ";
        } else {
            labelStr = label[0].readUtf8String(label[1].toNumber());
        }

        // Read the client random and secrets as strings
        var clientRandomStr = client_random.readByteArray(client_random_len.toNumber());
        var secretStr = secret.readByteArray(secret_size.toNumber());

        
        // Convert byte arrays to hex strings for better logging
        var clientRandomHex = Array.from(new Uint8Array(clientRandomStr)).map(b => b.toString(16).padStart(2, '0')).join('');
        var secretHex = Array.from(new Uint8Array(secretStr)).map(b => b.toString(16).padStart(2, '0')).join('');

        // Construct the keylog message
        message["keylog"] = `${labelStr} ${clientRandomHex} ${secretHex}`;
        send(message);

        return 1;
    }, 'void', [['pointer', 'size_t'], 'pointer', 'size_t', 'pointer', 'size_t']);

    constructor(public moduleName: string, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<string>}) {

        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        } else {
            // Different read and write funtions, Builder for optaining the config, which is needed to set the keyCB
            this.library_method_mapping[`*${moduleName}*`] = ["rustls_connection_write_tls", "rustls_connection_read_tls", "rustls_client_config_builder_new", 
                "rustls_client_config_builder_new_custom", "rustls_client_config_builder_set_key_log"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }

        this.addresses = readAddresses(moduleName, this.library_method_mapping);
        this.module_name = moduleName;

        //@ts-ignore
        if (offsets != "{OFFSETS}" && offsets.rustls != null) {
            if (offsets.sockets != null) {
                const socketBaseAddress = getBaseAddress(socket_library);

                for (const method of Object.keys(offsets.sockets)) {
                    const methodOffset = offsets.sockets[`${method}`];
                    const isAbsolute = methodOffset.absolute;
                    //@ts-ignore
                    const methodAddress = ptr(methodOffset.address)

                    if (isAbsolute || socketBaseAddress == null) {
                        this.addresses[this.moduleName][`${method}`] = methodAddress;
                    } else {
                        this.addresses[this.moduleName][`${method}`] = socketBaseAddress.add(methodAddress);
                    }

                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName);
            if (libraryBaseAddress == null) {
                log("Unable to find library base addresss! Given address values will be interpreted as absolute ones!");
            }

            for (const method of Object.keys(offsets.rustls)) {
                const methodOffset = offsets.rustls[`${method}`];
                const isAbsolute = methodOffset.absolute;
                //@ts-ignore
                const methodAddress = ptr(methodOffset.address);

                if (isAbsolute || libraryBaseAddress == null) {
                    this.addresses[this.moduleName][`${method}`] = methodAddress;
                } else {
                    this.addresses[this.moduleName][`${method}`] =libraryBaseAddress.add(methodAddress);
                }

            }
        }
    }

    install_tls_keys_callback_hook(){}
    install_plaintext_read_hook() {}
    install_plaintext_write_hook() {}
}