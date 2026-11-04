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
 *    existing executor family ("boringssl", "httpengine", "conscrypt"). Done.
 *    (A NEW family also needs a row in BOTH executor tables in
 *    agent/platforms/android.ts -- legacy and modern.)
 *  - Hidden-symbol / statically-linked lib (e.g. Unity): resolution "offset";
 *    set offsetKey (defaults to the module name) and supply offsets via
 *    --offsets keyed by that name. It NEVER reaches a Memory.scan (the pattern
 *    tier is hard-disabled under --pairip-safe).
 *
 * The registry build (android.ts), the spawn module-watcher, and the blink
 * persistence loop all derive their target set from THIS array via
 * matchPairipSafeLib(), so a new entry extends all three at once.
 */

import type { HookRegistration } from "./registry.js";
import type { ModuleHookingType, Platform, LibraryType } from "./shared_structures.js";

/**
 * Executor families the allowlist can name. The concrete executors are
 * INJECTED by the caller (agent/platforms/android.ts) per hook path -- legacy
 * (agent/legacy/**) or modern (--modern; agent/tls/**) -- so this shared module
 * imports neither tree's hookers (the two paths stay separate until merged).
 */
export type PairipExecutorKey = "boringssl" | "httpengine" | "conscrypt" | "unity_mbedtls";

/** One concrete executor per family, for a single hook path. */
export type PairipExecutorTable = Record<PairipExecutorKey, ModuleHookingType>;

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
    /** Executor family; resolved against the injected per-path PairipExecutorTable. */
    executor: PairipExecutorKey;
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
        executor: "boringssl", resolution: "symbol",
    },
    {
        // Statically-linked BoringSSL whose SSL_* surface lives in .symtab;
        // httpengine_execute* opts the module into deep symbol resolution.
        pattern: /.*libhttpengine\.so/, library: "httpengine (BoringSSL)", libraryType: "boringssl", protocol: "tls",
        executor: "httpengine", resolution: "symbol",
    },
    {
        // Blizzard commerce SDK — curl + BoringSSL; exports SSL_CTX_set_keylog_callback.
        // This carries com.blizzard.arc's real TLS (the actual key-capture win).
        pattern: /.*libcommerce_http_client\.so/, library: "Blizzard commerce (BoringSSL)", libraryType: "boringssl", protocol: "tls",
        executor: "httpengine", resolution: "symbol",
    },
    {
        pattern: /libjavacrypto\.so/, library: "Conscrypt (libjavacrypto)", libraryType: "boringssl", protocol: "tls",
        executor: "boringssl", resolution: "symbol",
    },
    {
        pattern: /libconscrypt_gmscore_jni\.so/, library: "Conscrypt", libraryType: "boringssl", protocol: "tls",
        executor: "conscrypt", resolution: "symbol",
    },
    {
        pattern: /libconscrypt_jni\.so/, library: "Conscrypt", libraryType: "boringssl", protocol: "tls",
        executor: "conscrypt", resolution: "symbol",
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
        executor: "boringssl", resolution: "offset", offsetKey: "libwebviewchromium.so",
    },
    {
        // Unity engine: statically-linked MbedTLS 3.x (UnityTLS), export-keys
        // compiled out + no exported symbols. Key extraction OFFSET-hooks
        // ssl_compute_master and scrapes the master secret (TLS1.2 CLIENT_RANDOM).
        // Supply the function offset via --offsets keyed "libunity.so".
        pattern: /.*libunity\.so/, library: "Unity (MbedTLS/UnityTLS)", libraryType: "mbedtls", protocol: "tls",
        executor: "unity_mbedtls", resolution: "offset", offsetKey: "libunity.so",
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

/**
 * Build the registry entries for `--pairip-safe` from the allowlist, binding
 * each entry to the caller's executor table (legacy or modern hook path).
 */
export function buildPairipSafeRegistrations(platform: Platform, executors: PairipExecutorTable): Registration[] {
    return PAIRIP_SAFE_LIBS.map((l) => ({
        platform,
        pattern: l.pattern,
        hookFn: executors[l.executor],
        library: l.library,
        libraryType: l.libraryType,
        protocol: l.protocol,
    }));
}
