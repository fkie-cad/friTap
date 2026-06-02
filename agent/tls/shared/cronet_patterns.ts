/**
 * Shared hardcoded byte patterns for ssl_log_secret in BoringSSL-based Cronet libraries.
 * x64 patterns are platform-agnostic; arm64 patterns vary by platform.
 */

import { isAndroid, isiOS, isMacOS } from "../../util/process_infos.js";

export const CRONET_X64_PATTERNS = {
    primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84",
    fallback: "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84"
};

export const CRONET_X86_PATTERNS = {
    primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34",
    fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60"
};

// Memoizes the parsed JSON keyed by source-string identity. `patterns` is set
// once during the agent handshake and reused for the session, so identity is
// stable and a Cronet module that probes both SSL_Read and SSL_Write pays for
// JSON.parse once instead of twice per module.
let cachedParse: { source: string; parsed: any } | null = null;

function parsePatterns(jsonString: string): any {
    if (cachedParse && cachedParse.source === jsonString) return cachedParse.parsed;
    try {
        const parsed = JSON.parse(jsonString);
        cachedParse = { source: jsonString, parsed };
        return parsed;
    } catch {
        cachedParse = { source: jsonString, parsed: null };
        return null;
    }
}

/**
 * Check whether a JSON pattern string contains module-specific patterns.
 * Returns true when `parsed.modules[moduleName]` or `parsed.modules[fallbackName]` exists.
 * When `actionType` is supplied (e.g. "SSL_Read", "SSL_Write"), the check is stricter:
 * the module entry must have at least one platform/arch combination with the action
 * present. Used to gate Cronet plaintext hook installation on whether the user
 * has actually shipped byte patterns for the requested capture.
 */
export function hasModulePatterns(jsonString: string, moduleName: string, fallbackName: string, actionType?: string): boolean {
    const parsed = parsePatterns(jsonString);
    if (!parsed || !parsed.modules) return false;
    const moduleEntry = parsed.modules[moduleName] || parsed.modules[fallbackName];
    if (!moduleEntry) return false;
    if (!actionType) return true;
    for (const platformKey of Object.keys(moduleEntry)) {
        const archEntries = moduleEntry[platformKey];
        if (!archEntries || typeof archEntries !== "object") continue;
        for (const archKey of Object.keys(archEntries)) {
            const archPatterns = archEntries[archKey];
            if (archPatterns && archPatterns[actionType]) return true;
        }
    }
    return false;
}

/** Current Frida platform mapped onto the keys used in the Schema-B pattern files. */
function currentPlatformKey(): string {
    if (isAndroid()) return "android";
    if (isiOS()) return "ios";
    if (isMacOS()) return "macos";
    return Process.platform.toString(); // "linux", "windows"
}

/** Current Frida arch mapped onto the keys used in the pattern files ("ia32" -> "x86"). */
function currentArchKey(): string {
    const arch = Process.arch.toString();
    return arch === "ia32" ? "x86" : arch;
}

/**
 * True when an action value carries at least one non-empty byte-pattern string.
 * Accepts the Schema-B `{primary, fallback, second_fallback?}` object as well as a
 * bare string or an array of strings (defensive — never assumes a shape).
 */
function isNonEmptyActionPattern(actionValue: any): boolean {
    if (!actionValue) return false;
    const nonEmpty = (p: any) => typeof p === "string" && p.trim().length > 0;
    if (typeof actionValue === "string") return nonEmpty(actionValue);
    if (Array.isArray(actionValue)) return actionValue.some(nonEmpty);
    if (typeof actionValue === "object") {
        return nonEmpty(actionValue.primary) || nonEmpty(actionValue.fallback) || nonEmpty(actionValue.second_fallback);
    }
    return false;
}

/**
 * Strict, throw-safe gate for the "use JSON pattern vs. fall back to the library's shipped
 * hardcoded default" decision.
 *
 * Returns true ONLY when the loaded pattern JSON contains a USABLE (non-empty) Schema-B
 * pattern for `moduleName` (or its `fallbackName` library key) at the CURRENT platform+arch
 * for the given `actionType`. This mirrors the primary two branches of
 * `PatternBasedHooking.hook_with_pattern_from_json*` (exact module name, then the library
 * key), so a match here means the hooker would actually find something to scan.
 *
 * Returns false for absent / empty / wrong-schema input — notably the flat Schema-A
 * `default_patterns.json` (which has no top-level `modules` wrapper). The caller then keeps
 * its shipped hardcoded `default_pattern` instead of routing into an empty/no-op JSON scan.
 *
 * Uses optional chaining throughout so it NEVER throws (the legacy gate previously fed
 * Schema-A data into a non-optional `this.patterns.modules[...]` access that threw a
 * TypeError, which the loader swallowed — silently disabling the hook).
 */
export function hasUsablePatternsFor(jsonString: string, moduleName: string, fallbackName: string, actionType: string): boolean {
    const parsed = parsePatterns(jsonString);
    const modules = parsed?.modules;
    if (!modules) return false;
    const moduleEntry = modules[moduleName] ?? modules[fallbackName];
    if (!moduleEntry) return false;
    const archEntry = moduleEntry?.[currentPlatformKey()]?.[currentArchKey()];
    return isNonEmptyActionPattern(archEntry?.[actionType]);
}
