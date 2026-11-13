// agent/tls/shared/chromium_plaintext.ts
//
// TCP TLS plaintext for stripped Chromium monoliths (Chrome's libmonochrome /
// libchrome, WebView's libwebviewchromium) and stripped Cronet builds
// (libcronet.<ver>.so, embedded or GMS Dynamite). Their BoringSSL is statically
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
import { fdLessSslGetFd, sessionlessSslSessionGetId } from "../../shared/optional_ssl_fd_session.js";
import { describeLocated, locateBoringSslPlaintextApi, LocatedPlaintextApi } from "./boringssl_plaintext_locator.js";
import { prefetchSslLayout } from "../../shared/ssl_layout_autolocate.js";
import { SslLayout, setSslLayout, sslLayoutFor } from "../../shared/ssl_identity.js";

const installedModules = new Set<string>();

const NO_MODIFICATIONS = { readmod: null, writemod: null };

/**
 * Stock 64-bit BoringSSL: ssl->s3 at 0x30, s3->client_random at 0x30. Unvalidated:
 * ssl_identity only answers from it after 3 distinct SSL* read plausibly, and a
 * keylog line refutes or validates it. The decoded layout replaces it.
 */
const STOCK_BORINGSSL_LAYOUT: SslLayout = { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false };

/** Give a statically linked BoringSSL the stock layout until the decoder (or a keylog) knows better. */
function installStockSslLayout(moduleName: string): void {
    if (Process.pointerSize !== 8 || sslLayoutFor(moduleName) !== null) return;
    setSslLayout(moduleName, STOCK_BORINGSSL_LAYOUT);
}

/**
 * Seed the stock layout, then start the shared (arm64, pairip-safe-gated,
 * once-per-module) lookup that decodes {s3Off, crOff} from the module's
 * ssl_log_secret so the plaintext records carry client_random (design B2).
 * Independent of -k; records produced before it settles carry whatever the
 * stock layout/cache gives. Called before the hooks attach, so the lookup is
 * attributed to this installer rather than the generic hook-install prefetch.
 */
function prepareSslLayout(moduleName: string): void {
    installStockSslLayout(moduleName);
    prefetchSslLayout(moduleName, "chromium-install");
}

export function chromiumPlaintextHost(moduleName: string, socketLibrary: string, isBaseHook: boolean): SslPlaintextHost {
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
        SSL_get_fd: fdLessSslGetFd,
        SSL_get_session: null,
        SSL_SESSION_get_id: sessionlessSslSessionGetId,
        getSslSessionId: (_ssl: NativePointer) => "",
        fdLess: true,
    };
}

/** The read/write attach surface of SslPlaintextHooks (narrowed so tests can pass a fake). */
export type PlaintextHookAttacher = Pick<SslPlaintextHooks, "attachRead" | "attachWrite">;

/**
 * Attach the located SSL_read/SSL_write hooks. The host is fd-less, so the hooks arm the
 * socket fd tracker at attach time (SslPlaintextHooks.armFdTrackerIfFdLess).
 */
export function attachChromiumPlaintextHooks(hooks: PlaintextHookAttacher, api: LocatedPlaintextApi): void {
    if (api.sslRead) hooks.attachRead(api.sslRead);
    if (api.sslWrite) hooks.attachWrite(api.sslWrite);
}

/**
 * True when `mod` exports SSL_read or SSL_write: some libcronet builds do, and
 * their primary row hooks those exports, so the locator path must stay out.
 */
export function exportsSslRecordApi(mod: Pick<Module, "findExportByName">): boolean {
    return mod.findExportByName("SSL_read") !== null || mod.findExportByName("SSL_write") !== null;
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
        if (exportsSslRecordApi(mod)) {
            // The primary row (e.g. the Cronet hooker) already hooks the exported
            // SSL_read/SSL_write; locating them again would emit every record twice.
            devlog(`[Chromium plaintext] ${moduleName}: SSL_read/SSL_write are exported; left to the export-based hooks`);
            return false;
        }
        const api = await locateBoringSslPlaintextApi(mod);
        if (!api || (!api.sslRead && !api.sslWrite)) {
            log(`[!] ${moduleName}: BoringSSL SSL_read/SSL_write not located; TCP TLS plaintext unavailable (keys only)`);
            return false;
        }
        const hooks = new SslPlaintextHooks(chromiumPlaintextHost(moduleName, socketLibrary, isBaseHook),
                                            NO_MODIFICATIONS, false);
        prepareSslLayout(moduleName);
        attachChromiumPlaintextHooks(hooks, api);
        // Exports only: a no-op on stripped builds, harmless where SSL_free is exported.
        hooks.installScopeHooks();
        log(`[*] ${moduleName}: hooked statically linked BoringSSL for TCP TLS plaintext ` +
            `(${describeLocated(mod, api)}; located via ssl_lib.cc error-site anchors)`);
        return true;
    } catch (e) {
        devlog(`[Chromium plaintext] ${moduleName}: install failed: ${e}`);
        return false;
    }
}
