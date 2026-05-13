
import { socket_library } from "../../../platforms/ios.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition } from "../../definitions/openssl.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // iOS legacy uses struct-offset keylog via SSL_CTX_set_info_callback. Modern
    // mode runs THIS executor INSTEAD of the legacy struct-offset path (the
    // registry uses `use_modern ? boring_execute_modern : boring_execute`).
    // libraryType: "boringssl" routes through the three-tier hook chain in
    // agent/shared/boringssl_hook_chain.ts (callback / symbol / pattern). On
    // Apple builds where the symbol or callback exists, the chain installs
    // cleanly; if both are stripped on a future Apple release the user must
    // fall back to use_modern=false to get the legacy struct-offset path.
    const def = createOpenSslDefinition({ skipReadWriteHooks: true });
    def.libraryType = "boringssl";
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
