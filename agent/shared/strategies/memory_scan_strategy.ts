/**
 * Memory scan strategy (BoringSecretHunter approach).
 *
 * Scans module memory ranges for TLS-related string indicators
 * to identify statically linked TLS libraries. Used as a last
 * resort when symbols, patterns, and offsets are unavailable.
 *
 * Priority: 40 (lowest - tried last)
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";

/** Known string indicators for TLS libraries */
const TLS_INDICATORS = [
    "CLIENT_RANDOM",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "EXPORTER_SECRET",
    "SERVER_TRAFFIC_SECRET_0",
    "CLIENT_TRAFFIC_SECRET_0",
    "SSLKEYLOGFILE",
    "SSL_CTX_set_keylog_callback",
    "ssl_log_secret",
    "tls13_hkdf_expand_label",
];

export class MemoryScanStrategy implements HookingStrategy {
    name = "memory_scan";
    priority = 40;

    tryHook(moduleName: string, _libraryType: string, functions: string[]): HookResult {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        try {
            const mod = Process.getModuleByName(moduleName);
            const foundIndicators: string[] = [];

            // Scan for TLS indicators in module memory
            for (const indicator of TLS_INDICATORS) {
                try {
                    const pattern = this._stringToHexPattern(indicator);
                    const matches = Memory.scanSync(mod.base, mod.size, pattern);
                    if (matches.length > 0) {
                        foundIndicators.push(indicator);
                    }
                } catch (scanErr) {
                    // Skip scan errors for individual indicators
                }
            }

            if (foundIndicators.length === 0) {
                errors.push(`No TLS indicators found in ${moduleName}`);
                return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
            }

            // If we found indicators, the module likely contains a TLS library
            // Mark functions as "identified" (actual hooking is done by caller)
            for (const funcName of functions) {
                // Check if the function name appears as a string in the module
                try {
                    const pattern = this._stringToHexPattern(funcName);
                    const matches = Memory.scanSync(mod.base, mod.size, pattern);
                    if (matches.length > 0) {
                        hooked.push(funcName);
                    }
                } catch (scanErr) {
                    // Skip
                }
            }

            // Even if we didn't find function name strings, the presence of
            // indicators means this module is worth investigating
            if (hooked.length === 0 && foundIndicators.length >= 2) {
                hooked.push("_tls_library_detected");
            }
        } catch (err) {
            errors.push(`Memory scan error: ${err}`);
        }

        return {
            success: hooked.length > 0,
            strategy: this.name,
            hookedFunctions: hooked,
            errors,
            resolvedAddresses: resolved,
        };
    }

    /**
     * Scan all loaded modules for TLS library indicators.
     * Returns modules that likely contain statically linked TLS code.
     */
    scanAllModules(): Array<{ name: string; path: string; indicators: string[] }> {
        const results: Array<{ name: string; path: string; indicators: string[] }> = [];
        const modules = Process.enumerateModules();

        for (const mod of modules) {
            const indicators: string[] = [];
            for (const indicator of TLS_INDICATORS) {
                try {
                    const pattern = this._stringToHexPattern(indicator);
                    const matches = Memory.scanSync(mod.base, mod.size, pattern);
                    if (matches.length > 0) {
                        indicators.push(indicator);
                    }
                } catch (scanErr) {
                    // Skip
                }
            }

            if (indicators.length >= 2) {
                results.push({
                    name: mod.name,
                    path: mod.path,
                    indicators,
                });
            }
        }

        return results;
    }

    isAvailable(): boolean {
        return true; // Always available as a last resort
    }

    private _stringToHexPattern(str: string): string {
        return str
            .split("")
            .map(c => c.charCodeAt(0).toString(16).padStart(2, "0"))
            .join(" ");
    }
}
