// agent/shared/boringssl_family_detect.ts
//
// Classifies a BoringSSL-bearing native module name into one of the families
// in agent/shared/bundled_cronet_patterns.ts. Used by the modern hook chain's
// tier-3 fallback to pick:
//   - the ordered list of pattern.json key aliases to retry (tier 3b)
//   - the per-family hardcoded byte patterns to scan (tier 3c)
//
// Family classification is intentionally driven by an explicit, ordered rule
// table — NOT by the buggy createRegexFromModule loop in
// agent/tls/shared/pattern_based_hooking.ts:826-836 (which builds a regex
// from the module name and tests it against the same module name, so it
// silently picks the first key with a matching arch entry). The rule list
// here is reviewed in code; ordering matters and is asserted by the unit
// test fixture in tests/.

import type { FamilyKey } from "./bundled_cronet_patterns.js";

interface FamilyRule {
    family: FamilyKey;
    match: (moduleName: string) => boolean;
}

/**
 * Ordered classification rules. The FIRST rule whose `match()` returns true
 * wins. Order from most-specific to most-generic so that
 * `libsignal_jni_testing.so` cannot accidentally fall through to a generic
 * BoringSSL match before being recognised as `signal`.
 */
const FAMILY_RULES: FamilyRule[] = [
    // Cronet variants — specific names first.
    { family: "stable_cronet",   match: (m) => /^stable_cronet/.test(m) },
    { family: "mainline_cronet", match: (m) => /libmainlinecronet/.test(m) },
    { family: "monochrome",      match: (m) => /monochrome/.test(m) },
    // Apps that statically link Cronet/BoringSSL.
    { family: "signal",          match: (m) => /libsignal_jni\b/.test(m) },
    { family: "ringrtc",         match: (m) => /libringrtc_rffi/.test(m) },
    { family: "warp",            match: (m) => /libwarp_mobile/.test(m) },
    { family: "quiche",          match: (m) => /libquiche/.test(m) || /quiche_android/.test(m) },
    { family: "rustls_android",  match: (m) => /librustls_android/.test(m) },
    // Conscrypt — both the standard JNI lib and statically-embedded variants
    // present in some apps.
    { family: "conscrypt",       match: (m) => /libconscrypt/.test(m) },
];

export function detectBoringSSLFamily(moduleName: string): FamilyKey {
    for (const rule of FAMILY_RULES) {
        if (rule.match(moduleName)) return rule.family;
    }
    return "generic_boringssl";
}

/**
 * Ordered list of pattern.json keys to retry after an exact-name miss.
 * Returning an empty array means "no further JSON lookup; proceed to the
 * bundled-pattern tier".
 *
 * The aliases reflect names actually observed in pattern.json today
 * (libmainlinecronet.so / libcronet.so / libwarp_mobile.so / libsignal_jni.so /
 * libquiche_android.so / librustls_android_13_ex.so). Adding a new pattern
 * entry to pattern.json for one of these families will start to match here
 * without code changes.
 */
export function familyAliases(family: FamilyKey): string[] {
    switch (family) {
        case "monochrome":
        case "mainline_cronet":
            return ["libmainlinecronet.so", "libcronet.so"];
        case "stable_cronet":
            return ["libcronet.so"];
        case "signal":
            return ["libsignal_jni.so", "libcronet.so"];
        case "ringrtc":
            return ["libringrtc_rffi.so", "libcronet.so"];
        case "warp":
            return ["libwarp_mobile.so", "libcronet.so"];
        case "quiche":
            return ["libquiche_android.so", "libcronet.so"];
        case "rustls_android":
            return ["librustls_android_13_ex.so"];
        case "conscrypt":
            return ["libconscrypt.so", "libcronet.so"];
        case "generic_boringssl":
            return ["libcronet.so"];
    }
}
