// agent/tls/shared/chromium_plaintext.ts
//
// TCP TLS plaintext for stripped Chromium monoliths (Chrome's libmonochrome /
// libchrome, WebView's libwebviewchromium). Their BoringSSL is statically
// linked and exports nothing, so the Cronet hooker can only extract keys; the
// record-layer API is located by boringssl_plaintext_locator.ts instead.
//
// Chrome drives SSL through its own BIO (net::SocketBIOAdapter), so SSL_get_fd
// is meaningless (-1). The records are attributed with friTap's SSL-scoped fd
// recovery (socket_fd_tracker.ts): the socket send()/recv() Chrome performs
// inside SSL_write/SSL_read — and the fd that SSL object used before — give the
// real TCP 4-tuple through the usual getpeername path.

import { log, devlog } from "../../util/log.js";
import { pcap_enabled } from "../../fritap_agent.js";
import { readAddresses } from "../../shared/shared_functions.js";
import { SslPlaintextHooks, SslPlaintextHost } from "../../shared/ssl_plaintext_hooks.js";
import { describeLocated, locateBoringSslPlaintextApi } from "./boringssl_plaintext_locator.js";

const installedModules = new Set<string>();

const NO_MODIFICATIONS = { readmod: null, writemod: null };

function plaintextHost(moduleName: string, socketLibrary: string, isBaseHook: boolean): SslPlaintextHost {
    let addresses: { [lib: string]: { [fn: string]: NativePointer } } = { [moduleName]: {} };
    try {
        addresses = readAddresses(moduleName, {
            [`*${socketLibrary}*`]: ["getpeername", "getsockname", "ntohs", "ntohl"],
        });
    } catch (e) {
        devlog(`[Chromium plaintext] ${moduleName}: socket helpers not resolved: ${e}`);
    }
    return {
        moduleName,
        module_name: moduleName,
        is_base_hook: isBaseHook,
        addresses,
        // No fd on Chrome's SSL objects: always take the deferred (SSL-scoped) path.
        SSL_get_fd: (_ssl: NativePointer) => -1,
        SSL_get_session: null,
        SSL_SESSION_get_id: null,
        getSslSessionId: (_ssl: NativePointer) => "",
    };
}

/**
 * Locate and hook SSL_read/SSL_write of the BoringSSL statically linked into
 * `moduleName`. Idempotent per module; never throws (rejects). Resolves `true`
 * when read and/or write hooks were attached, `false` when nothing was installed
 * (plaintext pcap disabled, module already handled, or the API not located).
 */
export async function installChromiumPlaintextHooks(moduleName: string, socketLibrary: string,
                                                    isBaseHook: boolean): Promise<boolean> {
    if (!pcap_enabled || installedModules.has(moduleName)) return false;
    installedModules.add(moduleName);
    try {
        const mod = Process.findModuleByName(moduleName);
        if (!mod) return false;
        const api = await locateBoringSslPlaintextApi(mod);
        if (!api || (!api.sslRead && !api.sslWrite)) {
            log(`[!] ${moduleName}: BoringSSL SSL_read/SSL_write not located; TCP TLS plaintext unavailable (keys only)`);
            return false;
        }
        const hooks = new SslPlaintextHooks(plaintextHost(moduleName, socketLibrary, isBaseHook),
                                            NO_MODIFICATIONS, false);
        if (api.sslRead) hooks.attachRead(api.sslRead);
        if (api.sslWrite) hooks.attachWrite(api.sslWrite);
        log(`[*] ${moduleName}: hooked statically linked BoringSSL for TCP TLS plaintext ` +
            `(${describeLocated(mod, api)}; located via ssl_lib.cc error-site anchors)`);
        return true;
    } catch (e) {
        devlog(`[Chromium plaintext] ${moduleName}: install failed: ${e}`);
        return false;
    }
}
