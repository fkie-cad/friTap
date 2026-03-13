/**
 * Symbol-based hooking strategy.
 *
 * Uses exported function symbols (e.g., SSL_read, SSL_write) to install
 * hooks. This is the fastest and most reliable strategy when symbols
 * are available.
 *
 * Priority: 100 (highest - tried first)
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";

export class SymbolStrategy implements HookingStrategy {
    name = "symbol";
    priority = 100;

    tryHook(moduleName: string, libraryType: string, functions: string[]): HookResult {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        try {
            const mod = Process.getModuleByName(moduleName);
            const exports = mod.enumerateExports();
            const exportMap = new Map(exports.map(e => [e.name, e.address]));

            for (const funcName of functions) {
                const addr = exportMap.get(funcName);
                if (addr && !addr.isNull()) {
                    hooked.push(funcName);
                    resolved.set(funcName, addr);
                } else {
                    errors.push(`Symbol '${funcName}' not found in ${moduleName}`);
                }
            }
        } catch (err) {
            errors.push(`Failed to enumerate exports: ${err}`);
        }

        return {
            success: hooked.length > 0 && hooked.length >= functions.length / 2,
            strategy: this.name,
            hookedFunctions: hooked,
            errors,
            resolvedAddresses: resolved,
        };
    }

    isAvailable(): boolean {
        return true; // Always available
    }
}
