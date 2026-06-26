/**
 * --pairip-safe library allowlist (single source of truth).
 *
 * PairIP (libpairipcore.so) runs a PERIODIC in-process code-integrity check that
 * SIGSEGVs the app when it finds friTap's broad footprint (the android_dlopen_ext
 * loader trampoline, the WebView/Cronet pattern scans, or a Memory.scan over a
 * protected lib). --pairip-safe therefore hooks ONLY the small, curated set of
 * TLS libraries below, resolved WITHOUT any Memory.scan (exported symbols, or
 * user-supplied offsets for hidden-symbol libs), with the loader hook + Java
 * hooks + pattern scans all disabled. A minimal keylog footprint survives the
 * integrity check's window; persistence ("blink") keeps it alive longer.
 *
 * ADDING A LIBRARY -- it is one entry below:
 *  - Symbol-exporting BoringSSL/Conscrypt lib: resolution "symbol"; reuse an
 *    existing executor (boring_execute, httpengine_execute, conscrypt_*). Done.
 *  - Hidden-symbol / statically-linked lib (e.g. Unity): resolution "offset";
 *    set offsetKey (defaults to the module name) and supply offsets via
 *    --offsets keyed by that name. It NEVER reaches a Memory.scan (the pattern
 *    tier is hard-disabled under --pairip-safe).
 *
 * The registry build (android.ts), the spawn module-watcher, and the blink
 * persistence loop all derive their target set from THIS array via
 * matchPairipSafeLib(), so a new entry extends all three at once.
 */

import { HookRegistration } from "./registry.js";
import { ModuleHookingType, Platform, LibraryType } from "./shared_structures.js";
// Modern (definition-based) executors
import { boring_execute_modern, httpengine_execute_modern } from "../tls/platforms/android/openssl_boringssl_android.js";
import { conscrypt_execute_modern } from "../tls/platforms/android/conscrypt.js";
// Unity (statically-linked MbedTLS 3.x, export-keys compiled out): offset-based
// master-secret scrape (shared by the modern & legacy slots).
import { unity_mbedtls_execute, unity_mbedtls_execute_modern } from "../tls/platforms/android/unity_mbedtls_android.js";
// Legacy (class-based) executors
import { boring_execute, httpengine_execute } from "../legacy/tls/platforms/android/openssl_boringssl_android.js";
import { conscrypt_native_execute } from "../legacy/tls/platforms/android/conscrypt.js";

/** How a library's TLS functions are located — documentation + validation. */
export type ResolutionMethod = "symbol" | "offset";

export interface PairipSafeLib {
    /** Module-name matcher (same semantics as HookRegistration.pattern). */
    pattern: RegExp;
    /** Human-readable label for logs/banners. */
    library: string;
    /** tlsLibHunter library type (drives the keylog chain selection). */
    libraryType: LibraryType;
    /** Protocol — always "tls" here. */
    protocol: string;
    /** Executor selector; receives use_modern so the entry stays declarative. */
    hookFn: (use_modern: boolean) => ModuleHookingType;
    /**
     * Expected resolution. "symbol" = exported/.symtab symbols (turnkey).
     * "offset" = hidden-symbol lib; needs offsets via --offsets (keyed by
     * offsetKey) — a startup warning fires if none are supplied.
     */
    resolution: ResolutionMethod;
    /**
     * Offsets key for offset-based libs. Defaults to the module name so two
     * libs of the same libraryType (e.g. two static MbedTLS builds) never
     * collide on a shared type key. Only meaningful when resolution==="offset".
     */
    offsetKey?: string;
}

export const PAIRIP_SAFE_LIBS: PairipSafeLib[] = [
    // --- Symbol-exporting BoringSSL / Conscrypt (turnkey) ---
    {
        pattern: /.*libssl\.so/, library: "OpenSSL/BoringSSL", libraryType: "openssl", protocol: "tls",
        hookFn: (m) => (m ? boring_execute_modern : boring_execute), resolution: "symbol",
    },
    {
        // Statically-linked BoringSSL whose SSL_* surface lives in .symtab;
        // httpengine_execute* opts the module into deep symbol resolution.
        pattern: /.*libhttpengine\.so/, library: "httpengine (BoringSSL)", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? httpengine_execute_modern : httpengine_execute), resolution: "symbol",
    },
    {
        // Blizzard commerce SDK — curl + BoringSSL; exports SSL_CTX_set_keylog_callback.
        // This carries com.blizzard.arc's real TLS (the actual key-capture win).
        pattern: /.*libcommerce_http_client\.so/, library: "Blizzard commerce (BoringSSL)", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? httpengine_execute_modern : httpengine_execute), resolution: "symbol",
    },
    {
        pattern: /libjavacrypto\.so/, library: "Conscrypt (libjavacrypto)", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? boring_execute_modern : boring_execute), resolution: "symbol",
    },
    {
        pattern: /libconscrypt_gmscore_jni\.so/, library: "Conscrypt", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? conscrypt_execute_modern : conscrypt_native_execute), resolution: "symbol",
    },
    {
        pattern: /libconscrypt_jni\.so/, library: "Conscrypt", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? conscrypt_execute_modern : conscrypt_native_execute), resolution: "symbol",
    },
    // --- Hidden-symbol / statically-linked (offset-based) ---
    {
        // Android System WebView (Chromium): statically-linked BoringSSL, fully
        // stripped — no .dynsym/.symtab SSL_* and Chromium installs no keylog
        // callback, so neither the callback tier nor enumerateSymbols can reach
        // it, and --pairip-safe forbids the Memory.scan tier. We OFFSET-hook
        // bssl::ssl_log_secret (called unconditionally during the handshake) and
        // read (ssl, label, secret) from its ARGS in onEnter — independent of
        // whether a keylog callback is set. This captures the Battle.net login
        // WebView TLS (UniWebView -> System WebView). libraryType "boringssl"
        // routes through installBoringSSLKeylogChain; the offset is consumed by
        // resolveSslLogSecretSymbol's lookupViaOffset strategy. Supply via
        //   --offsets '{"libwebviewchromium.so":{"ssl_log_secret":{"address":"0x...","absolute":false}}}'
        // (WebView 149.0.7827.91 arm64: ssl_log_secret @ 0x5adbb60). The module
        // loads lazily when the login page renders; the spawn watcher catches it.
        pattern: /.*libwebviewchromium\.so/, library: "Android WebView (Chromium BoringSSL)", libraryType: "boringssl", protocol: "tls",
        hookFn: (m) => (m ? boring_execute_modern : boring_execute), resolution: "offset", offsetKey: "libwebviewchromium.so",
    },
    {
        // Unity engine: statically-linked MbedTLS 3.x (UnityTLS), export-keys
        // compiled out + no exported symbols. Key extraction OFFSET-hooks
        // ssl_compute_master and scrapes the master secret (TLS1.2 CLIENT_RANDOM).
        // Supply the function offset via --offsets keyed "libunity.so".
        pattern: /.*libunity\.so/, library: "Unity (MbedTLS/UnityTLS)", libraryType: "mbedtls", protocol: "tls",
        hookFn: (m) => (m ? unity_mbedtls_execute_modern : unity_mbedtls_execute), resolution: "offset", offsetKey: "libunity.so",
    },
];

/**
 * The single membership predicate shared by the registry build, the spawn
 * module-watcher, and the blink loop. Returns the matching entry or undefined.
 */
export function matchPairipSafeLib(moduleName: string): PairipSafeLib | undefined {
    return PAIRIP_SAFE_LIBS.find((l) => l.pattern.test(moduleName));
}

/** Element type accepted by HookRegistry.registerAll (priority etc. optional). */
type Registration = Partial<HookRegistration> &
    Pick<HookRegistration, "platform" | "pattern" | "hookFn" | "library">;

/** Build the registry entries for `--pairip-safe` from the allowlist. */
export function buildPairipSafeRegistrations(platform: Platform, use_modern: boolean): Registration[] {
    return PAIRIP_SAFE_LIBS.map((l) => ({
        platform,
        pattern: l.pattern,
        hookFn: l.hookFn(use_modern),
        library: l.library,
        libraryType: l.libraryType,
        protocol: l.protocol,
    }));
}
