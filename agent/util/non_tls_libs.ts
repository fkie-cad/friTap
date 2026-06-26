/**
 * Known non-TLS libraries — OS-aware skip list.
 *
 * Some shared libraries have names that *look* like a TLS provider (or are
 * caught by an intentionally broad hook pattern) but link no TLS stack and
 * carry no SSL keys. Pattern-scanning or hooking them is pure wasted work —
 * a Memory.scan that cannot succeed, and an extra chance to trip target-side
 * protections — so friTap treats them as known non-TLS and skips them.
 *
 * Motivating case: Android System WebView ships three sibling libraries —
 *   - libwebviewchromium.so              → the real Chromium monolith with
 *                                          BoringSSL statically linked (KEEP).
 *   - libwebviewchromium_plat_support.so → GPU/graphics glue (NO TLS).
 *   - libwebviewchromium_loader.so       → thin loader stub that maps the real
 *                                          monolith (NO TLS).
 * The broad Android hook pattern `/.*libwebviewchromium.*\.so/` matches all
 * three, so the two non-TLS siblings must be excluded explicitly while the
 * real monolith keeps being hooked.
 *
 * This module is the single shared source of truth, consulted at every place a
 * library can be scanned or hooked (the hook registry's exclusion check, the
 * pattern.json scan path, the tlsLibHunter scan-result handler, the keylog
 * export auto-detect pass, and the legacy PatternBasedHooking entry points).
 *
 * Each entry is scoped to the operating system(s) it applies to. The OS keys
 * mirror the ones friTap's pattern files use ("android" | "ios" | "macos" |
 * "linux" | "windows"). This matters because Frida reports Android as "linux",
 * so the coarse `Platform` type used by the registry cannot tell the two apart —
 * the skip is keyed off the finer-grained platform key instead.
 *
 * Modelled on {@link ../util/anti_tamper}: a small declarative table plus a
 * pure predicate ({@link matchNonTLSLibrary}) safe to call on the hot path.
 * Like anti_tamper, this module is deliberately kept import-light — it resolves
 * the OS from Frida globals directly rather than importing process_infos (which
 * eagerly loads the Java bridge) so it stays dependency-free and unit-testable.
 */

import { devlog } from "./log.js";

/** Operating-system keys for scoping a skip. */
export type OSKey = "android" | "ios" | "macos" | "linux" | "windows";

interface NonTLSLib {
    /** Matches the module name (base name or full path). Anchor to avoid
     *  catching a real TLS-bearing sibling (e.g. libwebviewchromium.so). */
    pattern: RegExp;
    /** Operating system(s) on which this library is known to carry no TLS. */
    platforms: OSKey[];
    /** Human-readable name shown in devlog. */
    name: string;
    /** One-line description of why it is safe (and pointless) to skip. */
    note: string;
}

const NON_TLS_LIBS: ReadonlyArray<NonTLSLib> = [
    {
        pattern: /libwebviewchromium_plat_support\.so$/,
        platforms: ["android", "linux"],
        name: "Android WebView platform support (libwebviewchromium_plat_support.so)",
        note: "GPU/graphics glue for the WebView renderer; links no TLS stack and carries no SSL keys.",
    },
    {
        pattern: /libwebviewchromium_loader\.so$/,
        platforms: ["android", "linux"],
        name: "Android WebView loader (libwebviewchromium_loader.so)",
        note: "Thin loader stub that maps the real libwebviewchromium.so; contains no BoringSSL/TLS code.",
    },
];

/**
 * Bridge-free Android detection. Frida reports Android as `Process.platform ===
 * "linux"`, so we need a second signal. Prefer the legacy global `Java` bridge
 * (present on pre-v17 Frida); fall back to the presence of an Android-only
 * native runtime module (works on Frida >=17 where the global is absent).
 */
function isAndroidRuntime(): boolean {
    const J = (globalThis as any).Java;
    if (J && J.available) {
        try {
            if (J.androidVersion) return true; // throws / undefined off Android
        } catch (_) {
            // not Android — fall through to the module heuristic
        }
    }
    try {
        const P: any = (globalThis as any).Process;
        if (P && typeof P.findModuleByName === "function") {
            if (P.findModuleByName("libart.so") || P.findModuleByName("libandroid_runtime.so")) {
                return true;
            }
        }
    } catch (_) {
        // enumeration can race teardown; treat a miss as "not Android"
    }
    return false;
}

/** Resolve the finer-grained OS key from Frida globals (no heavy imports). */
function detectOS(): OSKey {
    const p = ((globalThis as any).Process?.platform ?? "linux").toString();
    if (p === "windows") return "windows";
    if (p === "darwin") return "macos"; // iOS not distinguished here (no iOS entries)
    if (p === "linux") return isAndroidRuntime() ? "android" : "linux";
    return p as OSKey;
}

/**
 * The current OS is constant for the lifetime of the agent, but resolving it
 * may touch the Java bridge / enumerate modules, which is too expensive to
 * repeat on the per-module hot path. Memoize it.
 */
let _osCache: OSKey | null = null;
function currentOS(): OSKey {
    if (_osCache === null) {
        _osCache = detectOS();
    }
    return _osCache;
}

/** Per-library throttle so the devlog note is emitted at most once each. */
const _notedNonTLS = new Set<string>();

/**
 * Return the matching non-TLS library descriptor for a module name on the
 * current (or supplied) OS, or null. Pure predicate — no side effects — safe to
 * call on the hot path to decide whether to skip hooking/scanning a module.
 *
 * @param moduleName Module base name or path to test.
 * @param platform   Optional OS key to test against; defaults to the (memoized)
 *                   current OS. Callers that already know the OS can pass it to
 *                   avoid the lookup; most callers should omit it.
 */
export function matchNonTLSLibrary(moduleName?: string | null, platform?: OSKey): NonTLSLib | null {
    if (!moduleName) return null;
    const os = platform ?? currentOS();
    for (const lib of NON_TLS_LIBS) {
        if (lib.platforms.includes(os) && lib.pattern.test(moduleName)) return lib;
    }
    return null;
}

/**
 * If `moduleName` is a known non-TLS library, emit a one-time devlog line
 * explaining the skip and return true (so callers can `continue` / `return`).
 * Returns false otherwise. Kept to devlog (not user-facing `log`) because these
 * skips are routine, non-actionable noise for the typical user.
 */
export function noteNonTLSLibrary(moduleName?: string | null): boolean {
    const lib = matchNonTLSLibrary(moduleName);
    if (!lib) return false;
    if (!_notedNonTLS.has(lib.name)) {
        _notedNonTLS.add(lib.name);
        devlog(`[non-tls] skipping ${lib.name}: ${lib.note}`);
    }
    return true;
}
