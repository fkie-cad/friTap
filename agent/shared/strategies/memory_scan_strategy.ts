/**
 * Memory scan strategy (BoringSecretHunter approach).
 *
 * Scans module memory ranges for TLS-related string indicators
 * to identify statically linked TLS libraries. Used as a last
 * resort when symbols, patterns, and offsets are unavailable.
 *
 * Scanning is asynchronous (Frida's non-blocking Memory.scan) so the JS
 * thread can service a gracefulDetach RPC mid-scan.
 *
 * Priority: 40 (lowest - tried last)
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";
import { _isShuttingDownNow } from "../../util/log.js";
import { toHexPattern } from "../../util/hex.js";

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

    /**
     * Resolve true as soon as the pattern is found anywhere in [base, base+size),
     * false otherwise. Wraps the async Memory.scan so the JS thread yields between
     * scan chunks and a gracefulDetach can be serviced mid-scan.
     */
    private _scanHasMatchAsync(base: NativePointer, size: number, pattern: string): Promise<boolean> {
        return new Promise((resolve) => {
            let matched = false;
            try {
                Memory.scan(base, size, pattern, {
                    onMatch: () => { matched = true; return "stop"; },
                    onError: () => { /* skip unreadable pages */ },
                    onComplete: () => resolve(matched),
                });
            } catch (_e) {
                resolve(false);
            }
        });
    }

    /**
     * Detect a statically linked TLS library by scanning module memory for
     * known TLS string indicators, then mark requested function names that
     * appear as strings. Uses the non-blocking async Memory.scan (via
     * _scanHasMatchAsync) so a gracefulDetach RPC can be serviced mid-scan.
     * Awaited by the pipeline's hookModuleAsync() as the last-resort strategy.
     */
    async tryHookAsync(moduleName: string, _libraryType: string, functions: string[]): Promise<HookResult> {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        try {
            const mod = Process.getModuleByName(moduleName);
            const foundIndicators: string[] = [];

            for (const indicator of TLS_INDICATORS) {
                if (_isShuttingDownNow()) break;
                const pattern = toHexPattern(indicator);
                if (await this._scanHasMatchAsync(mod.base, mod.size, pattern)) {
                    foundIndicators.push(indicator);
                }
            }

            if (foundIndicators.length === 0) {
                errors.push(`No TLS indicators found in ${moduleName}`);
                return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
            }

            for (const funcName of functions) {
                if (_isShuttingDownNow()) break;
                const pattern = toHexPattern(funcName);
                if (await this._scanHasMatchAsync(mod.base, mod.size, pattern)) {
                    hooked.push(funcName);
                }
            }

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
     * Scan all loaded modules for TLS library indicators (non-blocking).
     * Returns modules that likely contain statically linked TLS code.
     */
    async scanAllModulesAsync(): Promise<Array<{ name: string; path: string; indicators: string[] }>> {
        const results: Array<{ name: string; path: string; indicators: string[] }> = [];
        const modules = Process.enumerateModules();

        for (const mod of modules) {
            if (_isShuttingDownNow()) break;
            const indicators: string[] = [];
            for (const indicator of TLS_INDICATORS) {
                if (_isShuttingDownNow()) break;
                const pattern = toHexPattern(indicator);
                if (await this._scanHasMatchAsync(mod.base, mod.size, pattern)) {
                    indicators.push(indicator);
                }
            }

            if (indicators.length >= 2) {
                results.push({ name: mod.name, path: mod.path, indicators });
            }
        }

        return results;
    }

    isAvailable(): boolean {
        return true; // Always available as a last resort
    }
}
