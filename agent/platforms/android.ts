import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks } from "../shared/shared_functions.js";
import { Platform, PLATFORM_LINUX } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { findModulesWithSSLKeyLogCallback } from "../tls/shared/library_identification.js";
// Modern (definition-based) executors
import { gnutls_execute_modern } from "../tls/platforms/android/gnutls_android.js";
import { wolfssl_execute_modern } from "../tls/platforms/android/wolfssl_android.js";
import { nss_execute_modern } from "../tls/platforms/android/nss_android.js";
import { mbedTLS_execute_modern } from "../tls/platforms/android/mbedTLS_android.js";
import { boring_execute_modern } from "../tls/platforms/android/openssl_boringssl_android.js";
import { conscrypt_execute_modern } from "../tls/platforms/android/conscrypt.js";
import { s2ntls_execute_modern } from "../tls/platforms/android/s2ntls_android.js";
import { cronet_execute_modern } from "../tls/platforms/android/cronet_modern_android.js";
// Legacy (class-based) executors
import { boring_execute } from "../legacy/tls/platforms/android/openssl_boringssl_android.js";
import { gnutls_execute } from "../legacy/tls/platforms/android/gnutls_android.js";
import { wolfssl_execute } from "../legacy/tls/platforms/android/wolfssl_android.js";
import { nss_execute } from "../legacy/tls/platforms/android/nss_android.js";
import { mbedTLS_execute } from "../legacy/tls/platforms/android/mbedTLS_android.js";
import { cronet_execute } from "../legacy/tls/platforms/android/cronet_android.js";
import { conscrypt_native_execute } from "../legacy/tls/platforms/android/conscrypt.js";
import { s2ntls_execute } from "../legacy/tls/platforms/android/s2ntls_android.js";
// V1-only (re-exported from legacy)
import { java_execute } from "../tls/platforms/android/android_java_tls_libs.js";
import { flutter_execute, flutter_execute_modern } from "../tls/platforms/android/flutter_android.js";
import { mono_btls_execute, mono_btls_execute_modern } from "../tls/platforms/android/mono_btls_android.js";
import { patterns, isPatternReplaced, selected_protocol, use_modern, scan_results, library_scan_enabled, quic_only } from "../fritap_agent.js"
import { processScanResults, isModuleHooked, markModuleHooked } from "../shared/library_scanner.js";
import { pattern_execute } from "../tls/platforms/android/pattern_android.js"
import { rustls_execute, rustls_execute_modern } from "../tls/platforms/android/rustls_android.js";
import { gotls_execute, gotls_execute_modern } from "../tls/platforms/android/gotls_android.js";
import { metartc_execute } from "../tls/platforms/android/metartc.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { strongswan_execute_modern } from "../ipsec/platforms/android/strongswan_android.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { openssh_execute_modern } from "../ssh/platforms/android/openssh_android.js";
import { libssh_execute_modern } from "../ssh/platforms/android/libssh_android.js";
import { nss_hpke_execute_android } from "../ohttp/platforms/android/nss_hpke_android.js";
import { quiche_execute } from "../quic/platforms/android/quiche_android.js";
import { google_quiche_execute } from "../quic/platforms/android/google_quiche_android.js";
import { neqo_execute } from "../quic/platforms/android/neqo_android.js";

var plattform_name: Platform = PLATFORM_LINUX;
var moduleNames: Array<string> = getModuleNames();

export const socket_library = "libc"

function install_java_hooks(){
    java_execute();
}

function hook_native_Android_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean){
    ssl_library_loader(plattform_name, hookRegistry, moduleNames, "Android", is_base_hook, selected_protocol)

}

function loadPatternsFromJSON(jsonContent: string): any {
    try {
        let data = JSON.parse(jsonContent);
        return data;
    } catch (error) {
        devlog("[-] Error loading or parsing JSON pattern:  "+ error);
        return null;
    }
}

// Support for this feature is currently limited to Android systems and allows that any given module can be hooked provided by the JSON to hook the .
function install_pattern_based_hooks(){
    try{
        let data = loadPatternsFromJSON(patterns);
        if (data === null || !data.modules) return;

        for (const patternKey of Object.keys(data.modules)) {
            devlog("[*] Module name: " + patternKey);
            hookRegistry.register({
                platform: plattform_name,
                pattern: new RegExp(patternKey),
                hookFn: pattern_execute,
                library: "Pattern: " + patternKey,
            });

            // Targeted dispatch: walk only currently-loaded modules matching
            // this new pattern, skipping ones an earlier registry entry
            // already hooked. Avoids re-walking moduleNames globally and the
            // resulting "already hooked, skipping" noise. Future dlopen events
            // are still picked up by the dynamic-loader hook installed earlier.
            const matcher = new RegExp(patternKey);
            for (const candidate of moduleNames) {
                if (!matcher.test(candidate)) continue;
                if (isModuleHooked(candidate, "tls")) continue;
                try {
                    Process.getModuleByName(candidate).ensureInitialized();
                } catch {
                    continue;
                }
                log(`${candidate} found & will be hooked on Android!`);
                try {
                    pattern_execute(candidate, true);
                    markModuleHooked(candidate, "tls");
                    send({ contentType: "library_detected", library: candidate, path: "", protocol: "tls" });
                } catch (e) {
                    devlog(`pattern_execute(${candidate}) threw: ${e}`);
                }
            }
        }
    }catch(e){

    }

    //console.log("data: \n"+data);
    /*
    for (const moduleName in data.modules) {
        /*if (Object.prototype.hasOwnProperty.call(data.modules, moduleName)) {
          console.log("[*] Module name:", moduleName);
        }
      }*/

      /*
      const hooker = new PatternBasedHooking(cronetModule);
      hooker.hook_DumpKeys(this.module_name,"libcronet.so",patterns,(args: any[]) => {
                devlog("Installed ssl_log_secret() hooks using byte patterns.");
                this.dumpKeys(args[1], args[0], args[2]);  // Unpack args into dumpKeys
            });
      */
}


export function load_android_hooking_agent() {
    const __androidHooks: Parameters<typeof hookRegistry.registerAll>[0] = [
        // TLS libraries (TLS protocol family — also covers QUIC and OHTTP below)
        { platform: plattform_name, pattern: /.*libssl_sb.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libssl\.so/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: /libconscrypt_gmscore_jni.so/, hookFn: (use_modern ? conscrypt_execute_modern : conscrypt_native_execute), library: "Conscrypt", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /libconscrypt_jni.so/, hookFn: (use_modern ? conscrypt_execute_modern : conscrypt_native_execute), library: "Conscrypt", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*flutter.*\.so/, hookFn: (use_modern ? flutter_execute_modern : flutter_execute), library: "Flutter BoringSSL", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libgnutls\.so/, hookFn: (use_modern ? gnutls_execute_modern : gnutls_execute), library: "GnuTLS", libraryType: "gnutls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libwolfssl\.so/, hookFn: (use_modern ? wolfssl_execute_modern : wolfssl_execute), library: "WolfSSL", libraryType: "wolfssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libnss[3-4]\.so/, hookFn: (use_modern ? nss_execute_modern : nss_execute), library: "NSS", libraryType: "nss", protocol: "tls" },
        { platform: plattform_name, pattern: /libmbedtls\.so.*/, hookFn: (use_modern ? mbedTLS_execute_modern : mbedTLS_execute), library: "mbedTLS", libraryType: "mbedtls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libs2n.so/, hookFn: (use_modern ? s2ntls_execute_modern : s2ntls_execute), library: "s2n-tls", libraryType: "s2ntls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*mono-btls.*\.so/, hookFn: (use_modern ? mono_btls_execute_modern : mono_btls_execute), library: "Mono BTLS", libraryType: "boringssl", protocol: "tls" },
        // Cronet APEX split: libmainlinecronet's BoringSSL surface lives in the
        // stable_cronet_libssl.so sibling. libraryType must match the sibling's
        // entry above ("openssl") for coveredBySibling suppression to fire.
        {
            platform: plattform_name,
            pattern: /^libmainlinecronet\.[\d.]+\.so$/,
            hookFn: (use_modern ? cronet_execute_modern : cronet_execute),
            library: "Cronet (mainline runtime)",
            libraryType: "openssl",
            protocol: "tls",
            coveredBySibling: {
                siblingPattern: /^stable_cronet_libssl\.so$/,
                reason: "BoringSSL handshake state machine lives in sibling stable_cronet_libssl.so",
            },
        },
        // Generic Cronet host — modules named after Cronet itself with BoringSSL
        // statically linked in. `boring_execute` (libssl entry above) owns standalone
        // BoringSSL .so files that export SSL_* (e.g. stable_cronet_libssl.so).
        // Cronet-derived hosts are claimed by the named-out entries below.
        { platform: plattform_name, pattern: /^libcronet([_.]|\.\d).*\.so$/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libringrtc_rffi.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (RingRTC)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libsignal_jni.*\.so/, excludePattern: /_testing\.so$/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (Signal)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*monochrome.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (Monochrome)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libwarp_mobile.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (Warp Mobile)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*lib*quiche*.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (QUICHE)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*librustls.*\.so/, hookFn: (use_modern ? rustls_execute_modern : rustls_execute), library: "Rustls", libraryType: "rustls", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libstartup.*\.so/, hookFn: metartc_execute, library: "metaRTC", protocol: "tls" },
        { platform: plattform_name, pattern: /libgojni.*\.so/, hookFn: (use_modern ? gotls_execute_modern : gotls_execute), library: "Go TLS", libraryType: "gotls", protocol: "tls" },
        // IPSec libraries — strongSwan VPN is common on Android (detection stub, key extraction still needs to be done)
        { platform: plattform_name, pattern: /.*libcharon\.so/, hookFn: (use_modern ? strongswan_execute_modern : ipsec_detect_execute), library: "strongSwan (charon)", libraryType: "ipsec_strongswan", protocol: "ipsec" },
        { platform: plattform_name, pattern: /.*libstrongswan\.so/, hookFn: (use_modern ? strongswan_execute_modern : ipsec_detect_execute), library: "strongSwan", libraryType: "ipsec_strongswan", protocol: "ipsec" },
        // SSH binaries / libraries (Termux ships OpenSSH at $PREFIX/bin/ssh, sshd)
        { platform: plattform_name, pattern: /.*libssh2?\.so/, hookFn: (use_modern ? libssh_execute_modern : ssh_detect_execute), library: "libssh", protocol: "ssh" },
        { platform: plattform_name, pattern: /^(\/.+\/)?(ssh|sshd|sshd-session|scp|sftp-server)$/, hookFn: (use_modern ? openssh_execute_modern : ssh_detect_execute), library: "OpenSSH", protocol: "ssh" },
        // Dropbear stays on the legacy executor; no modern-path wrapper exists yet
        { platform: plattform_name, pattern: /^(\/.+\/)?dropbear$/, hookFn: ssh_detect_execute, library: "Dropbear", protocol: "ssh" },
        // OHTTP (NSS HPKE) — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libnss3?\.so/, hookFn: nss_hpke_execute_android, library: "NSS HPKE (OHTTP)", protocol: "tls", libraryType: "nss_hpke" },
        // QUIC libraries — gated under the TLS family for `--protocol tls`
        { platform: plattform_name, pattern: /.*libquiche\.so/, hookFn: quiche_execute, library: "Cloudflare QUICHE", libraryType: "quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libchrome\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Chrome)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libcronet.*\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Cronet)", libraryType: "google_quiche", protocol: "tls" },
        // libmainlinecronet does not match /.*libcronet.*\.so/ — "libcronet" is
        // not a substring of "libmainlinecronet". Needs its own entry.
        { platform: plattform_name, pattern: /^libmainlinecronet\.[\d.]+\.so$/, hookFn: google_quiche_execute, library: "Google QUICHE (Mainline Cronet APEX)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*monochrome.*\.so/, hookFn: google_quiche_execute, library: "Google QUICHE (Monochrome)", libraryType: "google_quiche", protocol: "tls" },
        { platform: plattform_name, pattern: /.*libxul\.so/, hookFn: neqo_execute, library: "Mozilla Neqo (Firefox HTTP/3)", libraryType: "neqo", protocol: "tls" },
    ];
    // --quic-only: install ONLY the Google QUICHE hooks (skip every TLS-library
    // hook and its keylog pattern scans). Faster attach, no Java VM sync, less
    // risk of stalling an already-busy target.
    hookRegistry.registerAll(quic_only ? __androidHooks.filter(e => (e as any).libraryType === "google_quiche") : __androidHooks);

    const androidLoaderConfig = {
        platform: plattform_name,
        platformLabel: "Android",
        loaderLibrary: /.*libdl.*\.so/,
        functionName: "dlopen",
        preferFunction: "android_dlopen_ext",
    };

    // Attach-time freeze mitigation: break the heavy install into setTimeout(0)-
    // yielded phases. Each yield releases the Frida runtime so the target's hot
    // threads (e.g. the QUICHE I/O thread when attaching to an already-playing
    // YouTube) can make progress between bursts of Interceptor.attach work,
    // preventing the cascading stall that drops the QUIC session. The host's
    // script.load() promise still resolves promptly after the synchronous part
    // (registerAll above) — actual hook installation completes within a few ticks.
    const phases: Array<{ label: string; fn: () => void }> = [];
    if (!quic_only) phases.push({ label: "java", fn: () => install_java_hooks() });
    phases.push({ label: "ssl-libs", fn: () => hook_native_Android_SSL_Libs(hookRegistry, true) });
    if (!quic_only) phases.push({
        label: "ohttp+scan-results",
        fn: () => {
            installOhttpHooks(plattform_name, hookRegistry, moduleNames, "Android", androidLoaderConfig);
            processScanResults(scan_results, plattform_name, true, selected_protocol);
        },
    });
    phases.push({
        label: "loader+patterns",
        fn: () => {
            hookDynamicLoader(androidLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
            if (isPatternReplaced()) install_pattern_based_hooks();
        },
    });
    // --library-scan is the auto-detect-extra-BoringSSL pass. Deferred to the
    // last phase so it runs AFTER the base hooks (preserving the original
    // synchronous ordering) and inherits the same per-phase yield budget.
    if (library_scan_enabled) phases.push({
        label: "library-scan",
        fn: () => {
            let matchedModules = findModulesWithSSLKeyLogCallback();
            // Filter out modules already matched by registry to prevent double-hooking
            matchedModules = matchedModules.filter(mod => !hookRegistry.findMatch(plattform_name, mod, "", selected_protocol));
            if (matchedModules.length > 0) {
                for (const mod of matchedModules) {
                    devlog("[!] Installing BoringSSL hooks for " + mod);
                    hookRegistry.register({
                        platform: plattform_name,
                        pattern: new RegExp(`.*${mod}`),
                        hookFn: (use_modern ? boring_execute_modern : boring_execute),
                        library: "BoringSSL (auto-detected)",
                        libraryType: "boringssl",
                    });
                }
                hook_native_Android_SSL_Libs(hookRegistry, false);
                hookDynamicLoader(androidLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
                log("[*] Hooked additional modules with SSL_CTX_set_keylog_callback.");
            }
        },
    });
    const runPhase = (i: number) => {
        if (i >= phases.length) return;
        setTimeout(() => {
            try { phases[i].fn(); }
            catch (e) { devlog("[Android] install phase " + phases[i].label + " threw: " + e); }
            runPhase(i + 1);
        }, 0);
    };
    runPhase(0);
}