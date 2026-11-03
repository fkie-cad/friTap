
import { socket_library } from "../../../platforms/macos.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach, createSslReadWriteExHooks } from "../../definitions/openssl.js";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";

export function boring_execute_modern(moduleName: string, is_base_hook: boolean) {
    // macOS legacy uses struct-offset keylog via SSL_CTX_set_info_callback. Modern
    // mode runs THIS executor INSTEAD of the legacy struct-offset path (the
    // registry uses `use_modern ? boring_execute_modern : boring_execute`).
    // libraryType: "boringssl" routes through the three-tier hook chain in
    // agent/shared/boringssl_hook_chain.ts (callback / symbol / pattern). On
    // Apple builds where the symbol or callback exists, the chain installs
    // cleanly; if both are stripped on a future Apple release the user must
    // fall back to use_modern=false to get the legacy struct-offset path.
    //
    // The callback tier (def.keylog below) depends on deep symbol resolution:
    // Apple's libboringssl.dylib does NOT export SSL_CTX_set_keylog_callback, it
    // only keeps it as a LOCAL symbol (`t _SSL_CTX_set_keylog_callback`), which
    // exports-only resolution never sees. enableDeepSymbolResolution() lets
    // readAddresses fall back to Module.enumerateSymbols(), which does return
    // dyld-shared-cache locals — see agent/legacy/tls/shared/apple_keylog_offset.ts.
    enableDeepSymbolResolution(moduleName);
    const def = createOpenSslDefinition({ skipReadWriteHooks: true });
    def.keylog = createBoringSSLKeylogApproach();
    def.libraryType = "boringssl";
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

// Python links genuine OpenSSL, so this path must NOT be tagged
// libraryType: "boringssl" — that would send it hunting for a
// bssl::ssl_log_secret symbol that cannot exist here, then into a pointless
// Memory.scan. The generic SSL_CTX_set_keylog_callback approach (misleadingly
// named createBoringSSLKeylogApproach) does no struct-offset write; it installs
// by calling the target's own setter from the SSL_new / SSL_CTX_new hooks.
// includeExSymbols is load-bearing: it is what puts SSL_CTX_new in the symbol
// list. Deep symbol resolution is enabled for the same reason as above — the
// setter may be a local rather than an exported symbol.
//
// Plaintext: genuine OpenSSL's SSL_get_fd is the real one (unlike Apple's
// libboringssl, whose read/write hooks stay skipped above), so the SSL_read /
// SSL_write hooks of createOpenSslDefinition apply as on Linux. CPython's _ssl
// never calls those, only SSL_read_ex / SSL_write_ex — hence the _ex hooks,
// APPENDED so the definition's SSL_free lifecycle hook is kept. curl's custom
// BIO makes SSL_get_fd() return -1; both hook sets then recover the peer via
// the socket-fd tracker (deferred to onLeave, so curl's first request counts).
export function ssl_python_execute_modern(moduleName: string, is_base_hook: boolean) {
    enableDeepSymbolResolution(moduleName);
    const def = createOpenSslDefinition({ includeExSymbols: true });
    def.keylog = createBoringSSLKeylogApproach();
    def.extraHooks = [...(def.extraHooks || []), ...createSslReadWriteExHooks()];
    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}
