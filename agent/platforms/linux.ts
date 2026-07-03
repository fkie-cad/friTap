import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { selected_protocol, use_modern, scan_results, quic_only } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks } from "../shared/shared_functions.js";
import { Platform, PLATFORM_LINUX } from "../shared/shared_structures.js";
// Modern (definition-based) executors
import { boring_execute_modern, ssl_python_execute_modern } from "../tls/platforms/linux/openssl_boringssl_linux.js";
import { gnutls_execute_modern } from "../tls/platforms/linux/gnutls_linux.js";
import { wolfssl_execute_modern } from "../tls/platforms/linux/wolfssl_linux.js";
import { nss_execute_modern } from "../tls/platforms/linux/nss_linux.js";
import { mbedTLS_execute_modern } from "../tls/platforms/linux/mbedTLS_linux.js";
import { s2ntls_execute_modern } from "../tls/platforms/linux/s2ntls_linux.js";
// Legacy (class-based) executors
import { boring_execute, ssl_python_execute } from "../legacy/tls/platforms/linux/openssl_boringssl_linux.js";
import { gnutls_execute } from "../legacy/tls/platforms/linux/gnutls_linux.js";
import { wolfssl_execute } from "../legacy/tls/platforms/linux/wolfssl_linux.js";
import { nss_execute } from "../legacy/tls/platforms/linux/nss_linux.js";
import { mbedTLS_execute } from "../legacy/tls/platforms/linux/mbedTLS_linux.js";
import { s2ntls_execute } from "../legacy/tls/platforms/linux/s2ntls_linux.js";
import { cronet_execute } from "../legacy/tls/platforms/linux/cronet_linux.js";
import { cronet_execute_modern } from "../tls/platforms/linux/cronet_linux.js";
// V1-only (re-exported from legacy)
import { matrixSSL_execute, matrixSSL_execute_modern } from "../tls/platforms/linux/matrixssl_linux.js";
import { rustls_execute, rustls_execute_modern } from "../tls/platforms/linux/rustls_linux.js";
import { gotls_execute, gotls_execute_modern } from "../tls/platforms/linux/gotls_linux.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { strongswan_execute_modern } from "../ipsec/platforms/linux/strongswan_linux.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { openssh_execute_modern } from "../ssh/platforms/linux/openssh_linux.js";
import { libssh_execute_modern } from "../ssh/platforms/linux/libssh_linux.js";
import { nss_hpke_execute_linux } from "../ohttp/platforms/linux/nss_hpke_linux.js";
// QUIC
import { quiche_execute } from "../quic/platforms/linux/quiche_linux.js";
import { google_quiche_execute } from "../quic/platforms/linux/google_quiche_linux.js";
import { neqo_execute } from "../quic/platforms/linux/neqo_linux.js";

var plattform_name: Platform = PLATFORM_LINUX;
var moduleNames: Array<string> = getModuleNames()

export const socket_library = "libc"

function hook_Linux_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Linux", is_base_hook, selected_protocol)
}

// --quic-only on Linux: install ONLY QUIC hooks (Cloudflare quiche, Google
// QUICHE/Cronet, Mozilla Neqo). Broader than Android's google_quiche-only
// filter because Linux desktop QUIC research is multi-stack: Cloudflare
// warp/cloudflared (quiche), Chromium/Cronet (google_quiche), Firefox HTTP/3
// (neqo). All three work on both arm64 and x86_64 via exported symbols;
// google_quiche additionally has arm64 byte patterns in quic_patterns.json
// (x86_64 patterns deferred — symbol resolution covers symbol-bearing desktop
// Chrome/Cronet builds, which is the common case).
const QUIC_ONLY_LINUX_HOOKS: Parameters<typeof hookRegistry.registerAll>[0] = [
    { platform: plattform_name, pattern: /.*libquiche\.so/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
    { platform: plattform_name, pattern: /.*libcronet.*\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Cronet)", libraryType: "google_quiche", protocol: "tls" },
    { platform: plattform_name, pattern: /.*libxul\.so/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls" },
];



export function load_linux_hooking_agent(skipLoaderHook: boolean = false) {

    if (quic_only) {
        // QUIC-only opt-in path: install ONLY QUIC hooks, phased via
        // setTimeout(0) to release the Frida runtime between Interceptor.attach
        // bursts. Mirrors android.ts pattern but Linux-flavored: no Java VM
        // step (Linux has none), no OHTTP (non-QUIC), no scan-results
        // (tlsLibHunter doesn't classify QUIC), no library-scan (BoringSSL
        // detection, contradicts quic-only intent).
        //
        // ROLLBACK: delete this entire `if (quic_only)` block to restore
        // pre-change behavior (--quic-only silently no-op'd on Linux).
        hookRegistry.registerAll(QUIC_ONLY_LINUX_HOOKS);

        const linuxLoaderConfig = {
            platform: plattform_name,
            platformLabel: "Linux",
            loaderLibrary: /.*libdl.*\.so/,        // POSIX dynamic loader (libdl); arch-agnostic
            functionName: "dlopen",                // hook glibc dlopen() to catch late-loaded QUIC libs
            extractModulePath: true,
        };

        const phases: Array<{ label: string; fn: () => void }> = [];
        phases.push({ label: "quic-hooks", fn: () => hook_Linux_SSL_Libs(hookRegistry, true) });
        phases.push({
            label: "loader",
            fn: () => hookDynamicLoader(linuxLoaderConfig, hookRegistry, moduleNames, false, selected_protocol),
        });

        const runPhase = (i: number) => {
            if (i >= phases.length) return;
            setTimeout(() => {
                try { phases[i].fn(); }
                catch (e) { devlog("[Linux/quic-only] install phase " + phases[i].label + " threw: " + e); }
                runPhase(i + 1);
            }, 0);
        };
        runPhase(0);
        return;
    }

    // Normal Linux path (quic_only=false): existing synchronous behavior,
    // preserved verbatim. NO CHANGES below this line.
    hookRegistry.registerAll([
        // TLS libraries (TLS protocol family — also covers QUIC and OHTTP below)
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libssl.*\.so/, hookFn: (use_modern ? ssl_python_execute_modern : ssl_python_execute), library: "Python OpenSSL", pathFilter: "python", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*cronet.*\.so/, excludePattern: /_(libpki|libcrypto)\.so$/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libnspr[0-9]?\.so/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss", protocol: "tls" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls", protocol: "tls" },
        { platform: plattform_name, pattern: /libssl_s.a/, hookFn: (use_modern ? matrixSSL_execute_modern : matrixSSL_execute), library: "MatrixSSL", libraryType: "matrixssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: (use_modern ? s2ntls_execute_modern : s2ntls_execute), library: "s2n-tls", libraryType: "s2ntls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*rustls.*/, hookFn: (use_modern ? rustls_execute_modern : rustls_execute), library: "Rustls", libraryType: "rustls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*\.go.so$/, hookFn: (use_modern ? gotls_execute_modern : gotls_execute), library: "Go TLS", libraryType: "gotls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*go[0-9.]+$/, hookFn: (use_modern ? gotls_execute_modern : gotls_execute), library: "Go TLS", libraryType: "gotls", protocol: "tls" },
        // IPSec libraries (detection stubs — key extraction in the future)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: (use_modern ? strongswan_execute_modern : ipsec_detect_execute), library: "strongSwan (charon)", libraryType: "ipsec_strongswan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: (use_modern ? strongswan_execute_modern : ipsec_detect_execute), library: "strongSwan", libraryType: "ipsec_strongswan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libipsec\.so/, hookFn: (use_modern ? strongswan_execute_modern : ipsec_detect_execute), library: "strongSwan (IPSec)", libraryType: "ipsec_strongswan", protocol: "ipsec" },
        // SSH binaries / libraries
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: (use_modern ? libssh_execute_modern : ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /^(\/.+\/)?(ssh|sshd|sshd-session|scp|sftp-server)$/, hookFn: (use_modern ? openssh_execute_modern : ssh_detect_execute), library: "OpenSSH", protocol: "ssh" },
        // OHTTP (NSS HPKE) — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libnss3?\.so/, hookFn: nss_hpke_execute_linux, library: "NSS HPKE (OHTTP)", protocol: "tls", libraryType: "nss_hpke" },
        // QUIC libraries — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libquiche\.so/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libcronet.*\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Cronet)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libxul\.so/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls" },
    ]);

    hook_Linux_SSL_Libs(hookRegistry, true);
    const linuxLoaderConfig = {
        platform: plattform_name,
        platformLabel: "Linux",
        loaderLibrary: /.*libdl.*\.so/,
        functionName: "dlopen",
        extractModulePath: true,
    };

    installOhttpHooks(plattform_name, hookRegistry, moduleNames, "Linux", linuxLoaderConfig, skipLoaderHook);
    processScanResults(scan_results, plattform_name, true, selected_protocol);
    // Wine callers pass skipLoaderHook=true: Wine uses its own preloader, not
    // libdl.dlopen, so the inline trampoline only grows the spawn-time footprint
    // without catching anything Wine actually loads. DLL interception runs via
    // hook_Wine_LdrLoadDll (see agent/platforms/wine.ts), once ntdll
    // appears.
    if (!skipLoaderHook) {
        hookDynamicLoader(linuxLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
    }
}