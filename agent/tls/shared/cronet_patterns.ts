/**
 * Shared hardcoded byte patterns for ssl_log_secret in BoringSSL-based Cronet libraries.
 * x64 patterns are platform-agnostic; arm64 patterns vary by platform.
 */

export const CRONET_X64_PATTERNS = {
    primary:  "41 57 41 56 41 55 41 54 53 48 83 EC ?? 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84",
    fallback: "55 41 57 41 56 41 54 53 48 83 EC 30 48 8B 47 68 48 83 B8 20 02 00 00 00 0F 84"
};

export const CRONET_X86_PATTERNS = {
    primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34",
    fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60"
};

/**
 * Check whether a JSON pattern string contains module-specific patterns.
 * Returns true only when `parsed.modules[moduleName]` or `parsed.modules[fallbackName]` exists.
 */
export function hasModulePatterns(jsonString: string, moduleName: string, fallbackName: string): boolean {
    try {
        const parsed = JSON.parse(jsonString);
        return !!(parsed.modules && (parsed.modules[moduleName] || parsed.modules[fallbackName]));
    } catch {
        return false;
    }
}
