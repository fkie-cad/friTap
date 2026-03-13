/**
 * Pattern-based hooking strategy.
 *
 * Scans binary memory for known byte sequences to find function
 * addresses when symbols are stripped. Supports architecture-specific
 * patterns with primary/fallback chains.
 *
 * Priority: 80
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";

export class PatternStrategy implements HookingStrategy {
    name = "pattern";
    priority = 80;
    private patternData: any = null;

    constructor(patternData?: any) {
        if (patternData) {
            this.patternData = patternData;
        }
    }

    setPatternData(data: any): void {
        this.patternData = data;
    }

    tryHook(moduleName: string, libraryType: string, functions: string[]): HookResult {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        if (!this.patternData) {
            errors.push("No pattern data available");
            return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
        }

        try {
            const mod = Process.getModuleByName(moduleName);
            const modulePatterns = this.patternData[moduleName] || this.patternData[libraryType];

            if (!modulePatterns) {
                errors.push(`No patterns defined for ${moduleName} or ${libraryType}`);
                return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
            }

            const arch = Process.arch;
            const archPatterns = modulePatterns[arch] || modulePatterns["default"];

            if (!archPatterns) {
                errors.push(`No patterns for architecture ${arch}`);
                return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
            }

            for (const funcName of functions) {
                const funcPatterns = archPatterns[funcName];
                if (!funcPatterns) continue;

                const patterns = Array.isArray(funcPatterns) ? funcPatterns : [funcPatterns];
                let found = false;

                for (const pattern of patterns) {
                    try {
                        const matches = Memory.scanSync(mod.base, mod.size, pattern);
                        if (matches.length > 0) {
                            hooked.push(funcName);
                            resolved.set(funcName, matches[0].address);
                            found = true;
                            break;
                        }
                    } catch (scanErr) {
                        // Try next pattern
                    }
                }

                if (!found) {
                    errors.push(`Pattern scan failed for ${funcName}`);
                }
            }
        } catch (err) {
            errors.push(`Pattern strategy error: ${err}`);
        }

        return {
            success: hooked.length > 0,
            strategy: this.name,
            hookedFunctions: hooked,
            errors,
            resolvedAddresses: resolved,
        };
    }

    isAvailable(): boolean {
        return this.patternData !== null;
    }
}
