// agent/shared/bundled_cronet_patterns.ts
//
// Single source of truth for hardcoded BoringSSL ssl_log_secret byte patterns
// used by the modern hook chain's tier-3 fallback. These patterns are scanned
// inside Cronet-derived libraries when:
//   - tier 1 (SSL_CTX_set_keylog_callback) was installed but never fires
//     (Cronet bypasses SSL_new internally), AND
//   - tier 2 (bssl::ssl_log_secret symbol resolution) failed (stripped binary).
//
// The legacy path keeps its own copy in
//   agent/legacy/tls/platforms/android/cronet_android.ts:23-64
// LEGACY-SYNC: when adding or correcting a family/arch entry here, mirror the
// change in the legacy module (and vice versa) until the deduplication phase.
//
// Pattern format follows the same convention used everywhere else in friTap:
//   hex bytes separated by single spaces; '?' as a nibble wildcard.

export type FamilyKey =
    | "monochrome"          // libmonochrome_*.so — Chrome / WebView monolith bundling BoringSSL
    | "mainline_cronet"     // libmainlinecronet*.so — Chrome's mainline Cronet variant
    | "stable_cronet"       // stable_cronet_libssl.so etc.
    | "signal"              // libsignal_jni.so (Signal Messenger)
    | "ringrtc"             // libringrtc_rffi.so (Signal RingRTC)
    | "warp"                // libwarp_mobile.so (Cloudflare WARP)
    | "quiche"              // libquiche_android.so (Google QUIC implementation)
    | "rustls_android"      // librustls_android_*.so
    | "conscrypt"           // libconscrypt_jni*.so / statically embedded Conscrypt
    | "generic_boringssl";  // floor — covers unrecognised BoringSSL forks

export interface ArchPatterns {
    primary: string;
    fallback: string;
    second_fallback?: string;
}

export type ArchKey = "x64" | "x86" | "arm64" | "arm";

export type ArchPatternMap = Partial<Record<ArchKey, ArchPatterns>>;

// Patterns lifted verbatim from
//   agent/legacy/tls/platforms/android/cronet_android.ts:44-64
// (the generic_boringssl row that the legacy Cronet_Android.default_pattern
// uses as a final resort — this is what successfully matches ssl_log_secret
// in libmonochrome_64.so on arm64 today).
const GENERIC_BORINGSSL: ArchPatternMap = {
    x64: {
        primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84",
        fallback: "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84",
    },
    x86: {
        primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34",
        fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60",
    },
    arm64: {
        primary:         "3F 23 03 D5 FF ?3 01 D1 FD 7B 0? A9 F6 57 0? A9 F4 4F 0? A9 FD ?3 0? 91 08 34 40 F9 08 1? 41 F9 ?8 0? 00 B4",
        fallback:        "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4",
        second_fallback: "3F 23 03 D5 FF C3 05 D1 FD 7B 14 A9 FC 57 15 A9 F4 4F 16 A9 FD 03 05 91 54 D0 3B D5 88 16 40 F9 40 00 80 52 F3",
    },
    arm: {
        primary:  "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0",
        fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0",
    },
};

// Verbatim from cronet_android.ts:23-28 (STABLE_CRONET_PATTERNS).
const STABLE_CRONET: ArchPatternMap = {
    arm64: {
        primary:  "FF 83 02 D1 FD 7B 05 A9 F9 33 00 F9 F8 5F 07 A9 F6 57 08 A9 F4 4F 09 A9 FD 43 01 91 58 D0 3B D5 08 17 40 F9 A8 83 1F F8 08 34 40 F9 08 21 41 F9 28 11",
        fallback: "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4",
    },
};

// Verbatim from cronet_android.ts:30-36 (LIBSIGNAL_PATTERNS).
// The legacy dispatcher shares this bundle between libsignal_jni / libringrtc_rffi /
// libwarp_mobile (cronet_android.ts:223), so we re-use it for all three families
// here. WARP and RingRTC may eventually warrant their own entries; keeping them
// pointed at SIGNAL preserves legacy behaviour exactly.
const SIGNAL: ArchPatternMap = {
    arm64: {
        primary:  "FF 43 02 D1 FD 7B 05 A9 F? ?? 0? ?9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 5? D0 3B D5 ?8 1? 40 F9 A8 83 1F F8 08 34 40 F9 08 11 41 F9 ?8 0? 00 B4",
        fallback: "3F 23 03 D5 FF 43 02 D1 FD 7B 05 A9 F8 5F 06 A9 F6 57 07 A9 F4 4F 08 A9 FD 43 01 91 08 34 40 F9 08 21 41 F9 C8 11 00 B4",
    },
};

export const BUNDLED_BSSL_PATTERNS: Record<FamilyKey, ArchPatternMap> = {
    // Monochrome is the same BoringSSL fork shipped inside Chrome's mainline
    // monolith; reuse the generic Cronet patterns until we collect a
    // monochrome-specific signature.
    monochrome:        GENERIC_BORINGSSL,
    mainline_cronet:   GENERIC_BORINGSSL,
    stable_cronet:     STABLE_CRONET,
    signal:            SIGNAL,
    ringrtc:           SIGNAL,
    warp:              SIGNAL,
    // Quiche/rustls/conscrypt currently share the generic floor. A future
    // PR can add family-specific patterns once samples are collected.
    quiche:            GENERIC_BORINGSSL,
    rustls_android:    GENERIC_BORINGSSL,
    conscrypt:         GENERIC_BORINGSSL,
    generic_boringssl: GENERIC_BORINGSSL,
};

function normalizeArch(): ArchKey | null {
    const raw = Process.arch.toString();
    if (raw === "ia32") return "x86";
    if (raw === "x64" || raw === "x86" || raw === "arm64" || raw === "arm") return raw;
    return null;
}

export function getBundledPatterns(
    family: FamilyKey,
    arch?: ArchKey | null,
): ArchPatterns | null {
    const a = arch ?? normalizeArch();
    if (!a) return null;
    const bundle = BUNDLED_BSSL_PATTERNS[family];
    return bundle[a] ?? null;
}

/**
 * Lifted directly from openssl.<arch>.ssl_log_secret[] in
 * friTap/patterns/default_patterns.json. This is the widest BoringSSL
 * ssl_log_secret prologue net we ship; tier 3d uses it as the floor when
 * neither the user's pattern.json nor a family-specific bundle has a match.
 *
 * Kept inline here (rather than parsed out of `patterns` at runtime) so this
 * fallback is always available even when the Python pattern loader fails to
 * deliver the merged JSON (e.g. when the user explicitly disables defaults).
 *
 * LEGACY-SYNC: mirrors friTap/patterns/default_patterns.json#openssl.
 */
export const BUNDLED_OPENSSL_SSL_LOG_SECRET: Partial<Record<ArchKey, string[]>> = {
    x64: [
        "F3 0F 1E FA 48 89 F8 49 89 D0 48 89 F7 49 89 C9 48 8D 90 40 01 00 00 B9 20 00 00 00 48 89 C6 E9 8C 63 FF FF",
        "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84",
    ],
    arm64: [
        "3F 23 03 D5 FD 7B BF A9 E4 03 01 AA FD 03 00 91 FD 7B C1 A8 BF 23 03 D5 E1 03 00 AA E5 03 03 AA E0 03 04 AA 03 04 80 D2 E4 03 02 AA 22 80 05 91",
        "3F 23 03 D5 FF ?3 02 D1 FD 7B 0? A9 F? ?? 0? ?9 F6 57 0? A9 F4 4F 0? A9 FD ?3 01 91 08 34 40 F9 08 ?? 41 F9 ?8 ?? 00 B4",
    ],
    arm: [
        "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0",
        "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0",
    ],
    x86: [
        "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34",
        "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60",
    ],
};

export function getBundledOpenSslPatterns(arch?: ArchKey | null): string[] | null {
    const a = arch ?? normalizeArch();
    if (!a) return null;
    return BUNDLED_OPENSSL_SSL_LOG_SECRET[a] ?? null;
}

export function currentArchKey(): ArchKey | null {
    return normalizeArch();
}
