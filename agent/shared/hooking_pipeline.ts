/**
 * Multi-strategy hooking pipeline for friTap.
 *
 * Provides a chain-of-responsibility pattern where multiple hooking
 * strategies are tried in priority order until one succeeds.
 *
 * Default order: Symbol -> Pattern -> Offset -> Memory Scan
 */

import { devlog, devlog_info } from "../util/log";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HookResult {
    success: boolean;
    strategy: string;
    hookedFunctions: string[];
    errors: string[];
    resolvedAddresses: Map<string, NativePointer>;
}

export interface HookingStrategy {
    /** Human-readable strategy name */
    name: string;

    /** Higher = tried first (default: symbol=100, pattern=80, offset=60, scan=40) */
    priority: number;

    /**
     * Attempt to hook the required functions in the given module.
     *
     * @param moduleName - Name of the module to hook
     * @param libraryType - Type of library (e.g., "openssl", "gnutls")
     * @param functions - Required function names to hook
     * @returns HookResult indicating success/failure
     */
    tryHook(moduleName: string, libraryType: string, functions: string[]): HookResult;

    /**
     * Check if this strategy is available/applicable for the current context.
     */
    isAvailable(): boolean;
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

export class HookingPipeline {
    private strategies: HookingStrategy[] = [];

    /**
     * Add a strategy to the pipeline. Strategies are sorted by priority
     * (highest first) on each call to hookModule().
     */
    addStrategy(strategy: HookingStrategy): void {
        if (!this.strategies.some(s => s.name === strategy.name)) {
            this.strategies.push(strategy);
        }
    }

    /**
     * Remove a strategy by name.
     */
    removeStrategy(name: string): void {
        this.strategies = this.strategies.filter(s => s.name !== name);
    }

    /**
     * Try all available strategies in priority order, accumulating results.
     * Each strategy resolves what it can; remaining functions are passed to the next.
     */
    hookModule(moduleName: string, libraryType: string, requiredFunctions: string[]): HookResult {
        const sorted = this.strategies
            .filter(s => s.isAvailable())
            .sort((a, b) => b.priority - a.priority);

        const allErrors: string[] = [];
        const allHooked: string[] = [];
        const allResolved = new Map<string, NativePointer>();
        let remaining = [...requiredFunctions];
        let winningStrategy = "none";

        for (const strategy of sorted) {
            if (remaining.length === 0) break;

            devlog(`[HookingPipeline] Trying strategy: ${strategy.name} for ${moduleName} (${remaining.length} remaining)`);
            try {
                const result = strategy.tryHook(moduleName, libraryType, remaining);

                for (const [fn, addr] of result.resolvedAddresses) {
                    if (!allResolved.has(fn)) {
                        allResolved.set(fn, addr);
                        allHooked.push(fn);
                    }
                }

                if (result.hookedFunctions.length > 0 && winningStrategy === "none") {
                    winningStrategy = result.strategy;
                }

                remaining = remaining.filter(fn => !allResolved.has(fn));

                if (result.errors.length > 0) {
                    allErrors.push(...result.errors.map(e => `[${strategy.name}] ${e}`));
                }

                if (remaining.length === 0) {
                    devlog_info(`[HookingPipeline] All functions resolved after '${strategy.name}'`);
                    break;
                }
            } catch (err) {
                const msg = `[${strategy.name}] Exception: ${err}`;
                devlog(`[HookingPipeline] ${msg}`);
                allErrors.push(msg);
            }
        }

        return {
            success: allHooked.length > 0,
            strategy: winningStrategy,
            hookedFunctions: allHooked,
            errors: remaining.length > 0
                ? [...allErrors, `Unresolved: ${remaining.join(", ")}`]
                : allErrors,
            resolvedAddresses: allResolved,
        };
    }

    /**
     * List registered strategies in priority order.
     */
    listStrategies(): Array<{ name: string; priority: number; available: boolean }> {
        return this.strategies
            .sort((a, b) => b.priority - a.priority)
            .map(s => ({
                name: s.name,
                priority: s.priority,
                available: s.isAvailable(),
            }));
    }

    /**
     * Get the number of registered strategies.
     */
    get size(): number {
        return this.strategies.length;
    }
}

/** Singleton pipeline instance */
export const defaultPipeline = new HookingPipeline();
