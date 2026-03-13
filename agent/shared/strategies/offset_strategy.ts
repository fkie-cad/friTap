/**
 * Offset-based hooking strategy.
 *
 * Uses pre-computed function offsets (relative to module base or
 * absolute addresses) from a JSON configuration file.
 *
 * Priority: 60
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";

export class OffsetStrategy implements HookingStrategy {
    name = "offset";
    priority = 60;
    private offsetData: any = null;

    constructor(offsetData?: any) {
        if (offsetData) {
            this.offsetData = offsetData;
        }
    }

    setOffsetData(data: any): void {
        this.offsetData = data;
    }

    tryHook(moduleName: string, libraryType: string, functions: string[]): HookResult {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        if (!this.offsetData) {
            errors.push("No offset data available");
            return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
        }

        try {
            const mod = Process.getModuleByName(moduleName);
            const moduleOffsets = this.offsetData[moduleName] || this.offsetData[libraryType] || this.offsetData;

            for (const funcName of functions) {
                const offset = moduleOffsets[funcName];
                if (offset === undefined || offset === null) {
                    continue;
                }

                let addr: NativePointer;
                if (typeof offset === "string" && offset.startsWith("0x")) {
                    // Could be absolute or relative
                    const offsetNum = parseInt(offset, 16);
                    if (moduleOffsets["_absolute"] === true) {
                        addr = ptr(offsetNum);
                    } else {
                        addr = mod.base.add(offsetNum);
                    }
                } else if (typeof offset === "number") {
                    addr = mod.base.add(offset);
                } else {
                    errors.push(`Invalid offset format for ${funcName}: ${offset}`);
                    continue;
                }

                if (!addr.isNull()) {
                    hooked.push(funcName);
                    resolved.set(funcName, addr);
                } else {
                    errors.push(`Offset resolved to null for ${funcName}`);
                }
            }
        } catch (err) {
            errors.push(`Offset strategy error: ${err}`);
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
        return this.offsetData !== null;
    }
}
