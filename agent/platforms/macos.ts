import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { collectContributedHooks } from "../shared/hook_contributors.js";
import { selected_protocols, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks, runInstallPhases } from "../shared/shared_functions.js";
import { Platform, PLATFORM_DARWIN } from "../shared/shared_structures.js";
import { VERSIONED_LIBSSL_DYLIB, SYSTEM_LIBRESSL_PATH, ANY_LIBSSL_DYLIB } from "../shared/darwin_library_patterns.js";
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/macos/openssl_boringssl_macos.js";
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/macos/openssl_boringssl_macos.js";
import { libressl_execute } from "../legacy/tls/platforms/macos/libressl_macos.js";
import { libressl_execute_modern } from "../tls/platforms/macos/libressl_macos.js";
import { cronet_execute } from "../legacy/tls/platforms/macos/cronet_macos.js";
import { cronet_execute_modern } from "../tls/platforms/macos/cronet_macos.js";
import { nss_execute } from "../legacy/tls/platforms/macos/nss_macos.js";
import { nss_execute_modern } from "../tls/platforms/macos/nss_macos.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { openssh_execute_modern } from "../ssh/platforms/macos/openssh_macos.js";
import { libssh_execute_modern } from "../ssh/platforms/macos/libssh_macos.js";
import { nss_hpke_execute_macos } from "../ohttp/platforms/macos/nss_hpke_macos.js";
import { quiche_execute } from "../quic/platforms/macos/quiche_macos.js";
import { google_quiche_execute } from "../quic/platforms/macos/google_quiche_macos.js";
import { neqo_execute } from "../quic/platforms/macos/neqo_macos.js";


var plattform_name: Platform = PLATFORM_DARWIN;

export const socket_library = "libSystem.B.dylib"


function hook_macOS_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, getModuleNames(), "MacOS", is_base_hook, selected_protocols)
}



export function load_macos_hooking_agent() {
    hookRegistry.registerAll([
        // TLS libraries (TLS protocol family — also covers QUIC and OHTTP below)
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "BoringSSL", libraryType: "boringssl", protocol: "tls" },
        // ── The libssl*.dylib name space, partitioned three ways ──────────────
        // Exhaustive and mutually exclusive by construction, which matters
        // because ssl_library_loader invokes EVERY match, not the first:
        //   * name is versioned (VERSIONED_LIBSSL_DYLIB) -> LibreSSL xor OpenSSL,
        //     split by SYSTEM_LIBRESSL_PATH. The two entries share an identical
        //     pattern and complementary predicates over that ONE constant, so
        //     exactly one survives — including when the module path is unknown,
        //     where pathFilter fails closed and excludePathFilter fails open.
        //   * name is libssl-shaped but not versioned -> the generic entry only,
        //     since its excludePattern IS VERSIONED_LIBSSL_DYLIB.
        //   * neither -> not a libssl, no hook.
        //
        // LibreSSL: macOS system SSL. Its executor carries the tier-2 KDF hooks
        // (tls1_PRF / tls13_hkdf_expand_label) that Apple's pre-3.5 LibreSSL
        // needs, so a false negative here costs keys outright.
        { platform: plattform_name, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: (use_modern ? libressl_execute_modern : libressl_execute), library: "LibreSSL", pathFilter: SYSTEM_LIBRESSL_PATH, priority: 150, libraryType: "libressl", protocol: "tls" },
        // Genuine OpenSSL: every versioned libssl that is NOT the system one —
        // Homebrew (arm64 /opt/homebrew and Intel /usr/local), pyenv, MacPorts,
        // conda, python.org and Xcode framework Pythons, and app bundles.
        //
        // ssl_python_execute* is the genuine-OpenSSL executor; the "python" in
        // its name is historical, from when a framework Python was the only case
        // anyone had here. boring_execute* must NOT be used for real OpenSSL: in
        // modern mode it is skipReadWriteHooks + libraryType "boringssl", which
        // drops the read/write hooks and sends the hook chain hunting a
        // bssl::ssl_log_secret symbol that cannot exist in OpenSSL (then into a
        // pointless Memory.scan); in legacy mode it writes an Apple BoringSSL
        // struct offset into a genuine OpenSSL SSL_CTX.
        //
        // priority 120 is load-bearing, not cosmetic: it makes THIS entry the
        // deterministic winner of findByLibraryType(darwin, "openssl") on the
        // tlsLibHunter scan path, which previously depended on Array#sort
        // stability at equal priority. Do not "tidy" it away.
        { platform: plattform_name, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "OpenSSL", excludePathFilter: SYSTEM_LIBRESSL_PATH, priority: 120, libraryType: "openssl", protocol: "tls" },
        // Everything else called libssl*: libssl.dylib, libssl_custom.dylib,
        // mylibssl.3.dylib, and statically-bundled BoringSSL copies.
        { platform: plattform_name, pattern: ANY_LIBSSL_DYLIB, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", excludePattern: VERSIONED_LIBSSL_DYLIB, libraryType: "openssl", protocol: "tls" },
        // Cronet on Apple: pinned to legacy on both paths — Apple's Cronet build
        // omits SSL_CTX_set_keylog_callback, so only legacy's ssl_log_secret
        // byte-pattern works. cronet_execute_modern kept imported for a future fix.
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libnss[0-9]*\.dylib/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss", protocol: "tls" },
        // SSH binaries / libraries
        { platform: plattform_name, pattern: /.*libssh2?\.dylib/, hookFn: (use_modern ? libssh_execute_modern : ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /^(\/.+\/)?(ssh|sshd|sshd-session|scp|sftp-server)$/, hookFn: (use_modern ? openssh_execute_modern : ssh_detect_execute), library: "OpenSSH", protocol: "ssh" },
        // OHTTP (NSS HPKE) — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libnss[0-9]*\.dylib/, hookFn: nss_hpke_execute_macos, library: "NSS HPKE (OHTTP)", protocol: "tls", libraryType: "nss_hpke" },
        // QUIC libraries — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libquiche\.dylib/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /Google Chrome Framework/, hookFn: google_quiche_execute, library: "Google QUICHE (Chrome)", libraryType: "google_quiche", protocol: "tls", supplementary: true },
        // Neqo (Firefox HTTP/3) — module is "XUL" at /Applications/Firefox.app/Contents/MacOS/XUL
        { platform: plattform_name, pattern: /^XUL$/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls", supplementary: true },
        // Hooks contributed by optional units (e.g. the public RC4 key-capture
        // unit under `--protocol rc4`). Empty when no unit registered.
        ...collectContributedHooks(),
    ]);

    const macosLoaderConfig = {
        platform: plattform_name,
        platformLabel: "MacOS",
        loaderLibrary: /libSystem.B.dylib/,
        functionName: "dlopen",
        // Resolve the module path in the dlopen onLeave (as Linux already does).
        // Without it `modulePath` is undefined on the dynamic-load path, where
        // `_isExcluded` fails closed for a positive `pathFilter` — so the
        // LibreSSL entry above could never install for a library that appears
        // after attach. Python's `_ssl` loads its libssl lazily, which is exactly
        // that case. The lookup in hookDynamicLoader is try/catch-guarded, so a
        // not-yet-resolvable module degrades to "no path" instead of throwing
        // inside the loader hook; the OpenSSL entry's `excludePathFilter` fails
        // OPEN precisely so that degraded case still gets a hook.
        extractModulePath: true,
    };

    // Same phase order as before, now contained + breadcrumbed + yielded. Phase 0
    // stays synchronous so the base TLS hooks are live before the host resumes a
    // spawned target.
    runInstallPhases("MacOS", [
        // NOTE: shares the iOS implementation, so it needs the same additional testing.
        { label: "ssl-libs",     fn: () => hook_macOS_SSL_Libs(hookRegistry, true) },
        { label: "ohttp",        fn: () => installOhttpHooks(plattform_name, hookRegistry, getModuleNames(), "MacOS", macosLoaderConfig) },
        { label: "scan-results", fn: () => processScanResults(scan_results, plattform_name, true, selected_protocols) },
        { label: "loader",       fn: () => hookDynamicLoader(macosLoaderConfig, hookRegistry, getModuleNames(), false, selected_protocols) },
    ]);
}