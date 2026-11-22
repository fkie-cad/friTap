import { NSS } from "../../../../tls/libs/nss.js";
import { socket_library } from "../../../../platforms/macos.js";
import { devlog } from "../../../../util/log.js";
import { installLegacyNssKeyExtraction } from "../../libs/nss_key_extraction.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

export class NSS_MacOS extends NSS {

    constructor(public moduleName: string, public socket_library: String, is_base_hook: boolean) {
        var library_method_mapping: { [key: string]: Array<string> } = {};
        devlog("Hooking module " + moduleName);
        // On macOS, Firefox bundles all NSS/NSPR/SSL symbols into a single libnss3.dylib
        library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType", "SSL_ImportFD", "SSL_HandshakeCallback", "PK11_ExtractKeyValue", "PK11_GetKeyData", "SSL_GetExperimentalAPI", "NSSSSL_GetVersion"]
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]

        super(moduleName, socket_library, library_method_mapping);
    }

    execute_hooks() {
        this.install_plaintext_read_hook();
        this.install_plaintext_write_hook();
        try {
            this.install_tls_keys_callback_hook();
        } catch (e) {
            devlog("Installing NSS key hooking failed");
            devlog("NSS Error code: " + e);
        }
    }

    install_tls_keys_callback_hook() {
        void installLegacyNssKeyExtraction(this.module_name, this.addresses[this.module_name]);
    }

}


export function nss_execute(moduleName: string, is_base_hook: boolean) {
    executeSSLLibrary(NSS_MacOS, moduleName, socket_library, is_base_hook);
}
