import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, installOhttpHooks, installStealthDynamicLoader, installPairipSafeWatcher } from "../shared/shared_functions.js";
import { matchAntiTamper, warnAntiTamper, scanForAntiTamper, bannerAntiTamper } from "../util/anti_tamper.js";
import { matchNonTLSLibrary, noteNonTLSLibrary } from "../util/non_tls_libs.js";
import { Platform, PLATFORM_LINUX } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { findModulesWithSSLKeyLogCallback } from "../tls/shared/library_identification.js";
// Modern (definition-based) executors
import { gnutls_execute_modern } from "../tls/platforms/android/gnutls_android.js";
import { wolfssl_execute_modern } from "../tls/platforms/android/wolfssl_android.js";
import { nss_execute_modern } from "../tls/platforms/android/nss_android.js";
import { mbedTLS_execute_modern } from "../tls/platforms/android/mbedTLS_android.js";
import { boring_execute_modern, httpengine_execute_modern } from "../tls/platforms/android/openssl_boringssl_android.js";
import { conscrypt_execute_modern } from "../tls/platforms/android/conscrypt.js";
import { s2ntls_execute_modern } from "../tls/platforms/android/s2ntls_android.js";
import { cronet_execute_modern } from "../tls/platforms/android/cronet_modern_android.js";
// Legacy (class-based) executors
import { boring_execute, httpengine_execute } from "../legacy/tls/platforms/android/openssl_boringssl_android.js";
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
import { patterns, isPatternReplaced, selected_protocol, use_modern, scan_results, library_scan_enabled, quic_only, no_loader_hook, spawned, stealth_loader, pairip_safe } from "../fritap_agent.js"
import { processScanResults, isModuleHooked, markModuleHooked } from "../shared/library_scanner.js";
import { buildPairipSafeRegistrations, matchPairipSafeLib } from "../shared/pairip_safe_libs.js";
import { pattern_execute } from "../tls/platforms/android/pattern_android.js"
import { rustls_execute, rustls_execute_modern } from "../tls/platforms/android/rustls_android.js";
import { gotls_execute, gotls_execute_modern } from "../tls/platforms/android/gotls_android.js";
import { metartc_execute } from "../tls/platforms/android/metartc.js";
import { ipsec_detect_execute } from "../ipsec/platforms/linux/ipsec_linux.js";
import { strongswan_execute_modern } from "../ipsec/platforms/android/strongswan_android.js";
import { ssh_detect_execute } from "../ssh/platforms/linux/ssh_linux.js";
import { openssh_execute_modern } from "../ssh/platforms/android/openssh_android.js";
import { libssh_execute_modern } from "../ssh/platforms/android/libssh_android.js";
import { tgnet_execute_modern } from "../mtproto/platforms/android/tgnet_android.js";
import { collectContributedHooks } from "../shared/hook_contributors.js";
import { telegram_execute_modern } from "../telegram/platforms/android/telegram_android.js";
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
                // Never Memory.scan an anti-tamper lib (PairIP) even if a
                // user-supplied pattern would match it; it crashes the target.
                if (matchAntiTamper(candidate)) { warnAntiTamper(candidate); continue; }
                // Skip known non-TLS libraries (e.g. WebView plat_support/loader)
                // even if a user-supplied pattern would match them; no keys live there.
                if (matchNonTLSLibrary(candidate)) { noteNonTLSLibrary(candidate); continue; }
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
        // libhttpengine.so statically links BoringSSL and exports the SSL_* surface
        // (possibly only in .symtab). httpengine_execute* opts the module into deep
        // symbol resolution, then runs the standard BoringSSL chain.
        { platform: plattform_name, pattern: /.*libhttpengine\.so/, hookFn: (use_modern ? httpengine_execute_modern : httpengine_execute), library: "httpengine (BoringSSL)", libraryType: "boringssl", protocol: "tls" },
        // libcommerce_http_client.so is com.blizzard.arc's statically-linked BoringSSL
        // (curl + BoringSSL). It exports SSL_CTX_set_keylog_callback but may keep the
        // SSL_* surface in .symtab; httpengine_execute* opts it into deep symbol
        // resolution, then runs the standard BoringSSL chain — same as libhttpengine.so.
        { platform: plattform_name, pattern: /.*libcommerce_http_client\.so/, hookFn: (use_modern ? httpengine_execute_modern : httpengine_execute), library: "Blizzard commerce (BoringSSL)", libraryType: "boringssl", protocol: "tls" },
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
        // libringrtc_rffi.so is Signal's WebRTC/calls BoringSSL — it carries no
        // chat-TLS keys, and its ranges are churned by the call subsystem, which
        // makes the recursive readable-parts pattern scan fault the target
        // (tombstone_12, 2026-06-15: SIGSEGV inside frida-agent Memory.scan).
        // Exclude it under `--protocol signal`; still scanned for generic TLS.
        { platform: plattform_name, pattern: /.*libringrtc_rffi.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (RingRTC)", libraryType: "boringssl", protocol: "tls", excludeProtocols: ["signal"] },
        { platform: plattform_name, pattern: /.*libsignal_jni.*\.so/, excludePattern: /_testing\.so$/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (Signal)", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*monochrome.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (Monochrome)", libraryType: "boringssl", protocol: "tls" },
        // Android System WebView monolith — full Chromium with BoringSSL statically linked
        // (same shape as libmonochrome). The ssl_log_secret arm64 prologue is already covered
        // by the shipped wildcard pattern (bundled_cronet_patterns.ts:58/193, cronet_android.ts:56):
        //   3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4
        // Verified concrete bytes (user-supplied, 2026-06):
        //   3F 23 03 D5 FF 03 02 D1 FD 7B 04 A9 F7 2B 00 F9 F6 57 06 A9 F4 4F 07 A9 FD 03 01 91 08 34 40 F9 08 29 41 F9 C8 05 00 B4
        { platform: plattform_name, pattern: /.*libwebviewchromium.*\.so/, hookFn: (use_modern ? cronet_execute_modern : cronet_execute), library: "Cronet (WebView Chromium)", libraryType: "boringssl", protocol: "tls" },
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
        // Telegram MTProto (tgnet) — gated under `--protocol mtproto`. Hook bodies
        // are Phase-0 structured stubs (offsets require on-device RE).
        { platform: plattform_name, pattern: /libtmessages\.tmessages\.so/, hookFn: tgnet_execute_modern, library: "Telegram tgnet", libraryType: "mtproto_tgnet", protocol: "mtproto" },
        { platform: plattform_name, pattern: /libtmessages.*\.so/, hookFn: tgnet_execute_modern, library: "Telegram tgnet", libraryType: "mtproto_tgnet", protocol: "mtproto" },
        // Telegram Secret-Chat (Java E2E) — gated under `--protocol telegram`.
        // The Secret-Chat key + plaintext live in the Java layer
        // (SecretChatHelper / TLRPC$EncryptedChat); the native lib load is the
        // install trigger. `--protocol telegram` ALSO pulls in the tgnet/mtproto
        // transport hooks via registry.protocolMatches (telegram -> mtproto).
        { platform: plattform_name, pattern: /libtmessages.*\.so/, hookFn: telegram_execute_modern, library: "Telegram Secret Chat (Java E2E)", libraryType: "telegram_e2e", protocol: "telegram" },
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
        // Hooks contributed by optional, separately bundled units (empty in the
        // public build; a full build's private unit registers its rows before the
        // agent entry runs, so they are present here at registration time).
        ...collectContributedHooks(),
    ];
    // --pairip-safe (friTap#64): restrict to the curated, scan-free TLS-library
    // allowlist (PAIRIP_SAFE_LIBS — the single source of truth, also consumed by
    // the spawn watcher and the blink loop). PairIP's periodic integrity check
    // SIGSEGVs the process when friTap pattern-scans/hooks the WebView/Chromium
    // (Cronet) libs or installs the dynamic-loader hook, so every cronet/webview/
    // pattern/quic entry is excluded and the pattern (Memory.scan) tier is
    // hard-disabled elsewhere. Add a library by adding ONE entry to PAIRIP_SAFE_LIBS.
    const pairipSafeHooks = buildPairipSafeRegistrations(plattform_name, use_modern);
    // --quic-only: install ONLY the Google QUICHE hooks (skip every TLS-library
    // hook and its keylog pattern scans). Faster attach, no Java VM sync, less
    // risk of stalling an already-busy target.
    hookRegistry.registerAll(
        pairip_safe ? (pairipSafeHooks as typeof __androidHooks)
        : quic_only ? __androidHooks.filter(e => (e as any).libraryType === "google_quiche")
        : __androidHooks);

    // Prefer the linker's __loader_android_dlopen_ext over libdl's
    // android_dlopen_ext wrapper. bionic's wrapper derives the caller address via
    // __builtin_return_address(0) and forwards it to __loader_android_dlopen_ext,
    // where the linker uses it to pick the CALLER'S linker namespace. An inline
    // Interceptor trampoline on the wrapper changes the observed return address,
    // so the linker resolves the wrong/empty namespace; namespaced apps (e.g.
    // Chrome) then fail to find a class and SIGABRT with "JNI DETECTED ERROR ...
    // java_class == null" (CheckJNI) during startup (fkie-cad/friTap#64). Hooking
    // __loader_android_dlopen_ext is safe: it receives caller_addr as an explicit
    // argument from the still-intact wrapper, so namespace resolution is preserved
    // — and it observes every load (args[0] is still the filename). Fall back to
    // the libdl wrapper on old Android that predates the __loader_* export.
    let hasLoaderDlopen = false;
    for (const ln of ["linker64", "linker"]) {
        try {
            const exp = Process.getModuleByName(ln).findExportByName("__loader_android_dlopen_ext");
            if (exp && !exp.isNull()) {
                hasLoaderDlopen = true;
                break;
            }
        } catch (_) { /* linker not present under this name; try the next */ }
    }
    const androidLoaderConfig = hasLoaderDlopen ? {
        platform: plattform_name,
        platformLabel: "Android",
        loaderLibrary: /(^|\/)linker(64)?$/,
        functionName: "__loader_android_dlopen_ext",
        preferFunction: "__loader_android_dlopen_ext",
    } : {
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
    // Decide ONCE — before any phase runs — whether to install the inline
    // android_dlopen_ext loader hook. PairIP / anti-tamper runtimes detect that
    // linker trampoline and SIGSEGV the process during their spawn-time scan
    // (fkie-cad/friTap#64). Skip it when forced (--no-loader-hook) or, auto, in
    // spawn mode when a known anti-tamper lib is already present. This single
    // decision MUST gate EVERY loader-hook site — the OHTTP phase, the
    // loader+patterns phase, and the library-scan phase — because OHTTP installs
    // its OWN android_dlopen_ext hook (shared_functions.ts:installOhttpHooks),
    // which previously still crashed protected apps even with --no-loader-hook.
    // scanForAntiTamper() re-enumerates the live module list (getModuleNames()
    // captured at agent load is stale for spawned apps). Note: auto-detection is
    // best-effort — PairIP that loads AFTER this point can't be pre-detected, so
    // --no-loader-hook (or attach mode) remains the reliable control.
    const antiTamperPresent = scanForAntiTamper();
    // --pairip-safe forces the loader hook OFF (the inline android_dlopen_ext
    // trampoline AND the HW-bp stealth watcher both lead to hooking late-loaded
    // WebView/Cronet libs, which trips PairIP). Target libs are hooked by symbol/
    // offset only — already-loaded ones in the ssl-libs phase (attach), and
    // libs that load later via the non-invasive pairip-safe watcher (spawn).
    if (pairip_safe && spawned) {
        log("[!] --pairip-safe spawn: deferring hooks past PairIP's startup integrity window, then hooking on load.");
        log("[!] Note: spawn is best-effort and may miss the app's earliest (startup) handshakes; attach is the proven path.");
    }
    // EXPERIMENTAL stealth loader (Part C, friTap#64): watch android_dlopen_ext
    // via a hardware breakpoint (no linker code patch) instead of the inline
    // trampoline. It REPLACES the inline hook but, unlike the plain skip, still
    // captures late-loaded TLS libs — so it is its own mode, not a "disable".
    const useStealthLoader = stealth_loader && !pairip_safe;
    // Skip the inline loader hook when forced (--no-loader-hook) or, auto, in
    // spawn + anti-tamper. Stealth mode supplies its own (HW-bp) watcher, so the
    // inline hook is neither installed nor reported as a capture-disabling skip.
    const loaderHookSkipped = pairip_safe || (!useStealthLoader && (no_loader_hook || (spawned && antiTamperPresent)));
    // The single gate for the inline android_dlopen_ext trampoline across ALL
    // sites (OHTTP, loader+patterns, library-scan).
    const installInlineLoaderHook = !loaderHookSkipped && !useStealthLoader;
    if (loaderHookSkipped) {
        // Pass the matched module name when auto-detected so the host banner
        // names the protection; pass null for an explicit --no-loader-hook skip
        // with nothing detected (yet) so the banner reads as an info notice.
        bannerAntiTamper(antiTamperPresent ? "libpairipcore.so" : null, true);
    }

    // Attach-time freeze mitigation: break the heavy install into setTimeout(0)-
    // yielded phases. Each yield releases the Frida runtime so the target's hot
    // threads can make progress between bursts of Interceptor.attach work.
    const phases: Array<{ label: string; fn: () => void }> = [];
    // --pairip-safe: ONLY the symbol-based ssl-libs phase. Skip Java hooks
    // (ART instrumentation), OHTTP+scan-results, the loader+patterns phase
    // (pattern scan of WebView/Cronet libs is what trips PairIP), and the
    // library-scan pass.
    if (pairip_safe) log("[*] --pairip-safe: symbol-only keylog on libssl/libjavacrypto/conscrypt; loader hook, pattern scan, Java & OHTTP hooks disabled.");
    if (!quic_only && !pairip_safe) phases.push({ label: "java", fn: () => install_java_hooks() });
    phases.push({ label: "ssl-libs", fn: () => hook_native_Android_SSL_Libs(hookRegistry, true) });
    if (!quic_only && !pairip_safe) phases.push({
        label: "ohttp+scan-results",
        fn: () => {
            // Skip OHTTP's own android_dlopen_ext trampoline whenever the inline
            // loader hook is gated (plain skip OR stealth mode) — it only hooks
            // already-loaded modules then.
            installOhttpHooks(plattform_name, hookRegistry, moduleNames, "Android", androidLoaderConfig, !installInlineLoaderHook);
            processScanResults(scan_results, plattform_name, true, selected_protocol);
        },
    });
    if (!pairip_safe) phases.push({
        label: "loader+patterns",
        fn: () => {
            if (useStealthLoader) {
                log("[!] EXPERIMENTAL: stealth loader enabled — watching android_dlopen_ext via hardware");
                log("[!] breakpoint (no linker code patch). Unvalidated against PairIP; see friTap#64.");
                if (!installStealthDynamicLoader(androidLoaderConfig, hookRegistry, getModuleNames, selected_protocol)) {
                    log("[-] Stealth loader failed to arm — TLS libraries loaded later will NOT be hooked.");
                    log("[-] Re-run in attach mode (no -s) or with root frida-server. See friTap#64.");
                }
            } else if (installInlineLoaderHook) {
                hookDynamicLoader(androidLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
            }
            if (isPatternReplaced()) install_pattern_based_hooks();
        },
    });
    // --library-scan is the auto-detect-extra-BoringSSL pass. Deferred to the
    // last phase so it runs AFTER the base hooks (preserving the original
    // synchronous ordering) and inherits the same per-phase yield budget.
    if (library_scan_enabled && !pairip_safe) phases.push({
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
                // Honour the single loader-hook gate: don't re-introduce the
                // android_dlopen_ext trampoline that the skip / stealth path
                // avoided (fkie-cad/friTap#64). Stealth mode's HW-bp watcher
                // already covers future loads.
                if (installInlineLoaderHook) {
                    hookDynamicLoader(androidLoaderConfig, hookRegistry, moduleNames, false, selected_protocol);
                }
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

    // --pairip-safe: spawn + attach late-load watcher. The ssl-libs phase above
    // hooked already-loaded targets (attach). This non-invasive watcher hooks
    // targets that load LATER — the spawn case (TLS libs load after resume) and
    // any late dlopen in attach — without a loader hook or Memory.scan. Hooking
    // is deferred past PairIP's startup integrity window in spawn mode.
    if (pairip_safe) {
        // ~8s past agent-load (≈resume) clears PairIP's startup gate before any
        // inline keylog hook lands; attach is already past startup so use a short
        // delay there. Tunable starting points (see plan); device-validated.
        const PAIRIP_SAFE_HOOK_DELAY_MS = spawned ? 8000 : 1500;
        const PAIRIP_SAFE_POLL_MS = 1000;
        installPairipSafeWatcher(
            plattform_name, hookRegistry, getModuleNames, selected_protocol,
            (n) => matchPairipSafeLib(n) !== undefined,
            PAIRIP_SAFE_HOOK_DELAY_MS, PAIRIP_SAFE_POLL_MS,
        );
    }

    // Late-load anti-tamper surfacing (fkie-cad/friTap#64). PairIP's
    // libpairipcore.so frequently loads AFTER our synchronous scan above, so the
    // initial gate can't see it. Re-check a couple of times so the user still
    // gets the red anti-tamper banner — and the host records it for crash
    // attribution — even when we couldn't skip the loader hook in time. Cheap
    // module enumeration; the per-library warning is throttled to once.
    if (!antiTamperPresent) {
        setTimeout(() => scanForAntiTamper(), 500);
        setTimeout(() => scanForAntiTamper(), 2000);
    }
}