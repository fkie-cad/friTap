import { GnuTLS_Linux } from "../linux/gnutls_linux.js";
import { socket_library } from "../../../../platforms/macos.js";
import { executeSSLLibrary } from "../../../shared/shared_functions_legacy.js";

// GnuTLS on macOS (Homebrew's libgnutls.30.dylib). The Linux hooker is platform-neutral —
// plain C exports, gnutls_init keylog injection — so only the socket library differs.
export function gnutls_execute(moduleName: string, is_base_hook: boolean) {
    executeSSLLibrary(GnuTLS_Linux, moduleName, socket_library, is_base_hook);
}
