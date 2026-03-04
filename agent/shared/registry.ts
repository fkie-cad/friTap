/**
 * Hook Registry for friTap agent.
 *
 * Typed, queryable registry for platform hooks. Platform agents register
 * their hooks declaratively, and the loader queries the registry at runtime.
 */

import { ModuleHookingType } from "./shared_structures";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HookRegistration {
    /** Target platform: "linux", "android", "ios", "macos", "windows", "wine" */
    platform: string;
    /** Regex pattern to match module/library names */
    pattern: RegExp;
    /** The hooking function to invoke when the pattern matches */
    hookFn: ModuleHookingType;
    /** Protocol this hook targets */
    protocol: string;
    /** Human-readable library name for logging/display */
    library: string;
    /** Higher priority = tried first (default 100) */
    priority: number;
    /** Optional path substring filter for extra specificity */
    pathFilter?: string;
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

class HookRegistry {
    private _hooks: HookRegistration[] = [];

    /**
     * Register a new hook.
     *
     * @param reg Partial registration; `protocol` defaults to "tls",
     *            `priority` defaults to 100.
     */
    register(reg: Partial<HookRegistration> & Pick<HookRegistration, "platform" | "pattern" | "hookFn" | "library">): void {
        this._hooks.push({
            protocol: "tls",
            priority: 100,
            ...reg,
        } as HookRegistration);
    }

    /**
     * Bulk-register an array of hooks (convenience for platform agents).
     */
    registerAll(regs: Array<Partial<HookRegistration> & Pick<HookRegistration, "platform" | "pattern" | "hookFn" | "library">>): void {
        for (const reg of regs) {
            this.register(reg);
        }
    }

    /**
     * Return all hooks for a given platform, optionally filtered by protocol,
     * sorted by descending priority.
     */
    getHooks(platform: string, protocol?: string): HookRegistration[] {
        let result = this._hooks.filter(h => h.platform === platform);
        if (protocol) {
            result = result.filter(h => h.protocol === protocol);
        }
        return result.sort((a, b) => b.priority - a.priority);
    }

    /**
     * Find the first hook whose pattern matches *moduleName* on *platform*.
     *
     * @param protocol Optional protocol filter. "auto" or undefined = no filter.
     */
    findMatch(platform: string, moduleName: string, modulePath?: string, protocol?: string): HookRegistration | undefined {
        const effectiveProtocol = (protocol && protocol !== "auto") ? protocol : undefined;
        const hooks = this.getHooks(platform, effectiveProtocol);
        for (const hook of hooks) {
            if (hook.pattern.test(moduleName)) {
                // Optional path filter check
                if (hook.pathFilter && modulePath) {
                    if (!modulePath.includes(hook.pathFilter)) {
                        continue;
                    }
                } else if (hook.pathFilter && !modulePath) {
                    continue;
                }
                return hook;
            }
        }
        return undefined;
    }

    /**
     * Find ALL hooks whose pattern matches *moduleName* on *platform*.
     *
     * @param protocol Optional protocol filter. "auto" or undefined = no filter.
     */
    findAllMatches(platform: string, moduleName: string, modulePath?: string, protocol?: string): HookRegistration[] {
        const effectiveProtocol = (protocol && protocol !== "auto") ? protocol : undefined;
        const hooks = this.getHooks(platform, effectiveProtocol);
        const matches: HookRegistration[] = [];
        for (const hook of hooks) {
            if (hook.pattern.test(moduleName)) {
                if (hook.pathFilter && modulePath) {
                    if (!modulePath.includes(hook.pathFilter)) {
                        continue;
                    }
                } else if (hook.pathFilter && !modulePath) {
                    continue;
                }
                matches.push(hook);
            }
        }
        return matches;
    }

    /**
     * List all registered platforms.
     */
    getPlatforms(): string[] {
        const platforms = new Set(this._hooks.map(h => h.platform));
        return Array.from(platforms);
    }

    /**
     * List all registered protocols.
     */
    getProtocols(): string[] {
        const protocols = new Set(this._hooks.map(h => h.protocol));
        return Array.from(protocols);
    }

    /**
     * Total number of registered hooks.
     */
    get size(): number {
        return this._hooks.length;
    }

    /**
     * Clear all registrations (mainly for testing).
     */
    clear(): void {
        this._hooks = [];
    }
}

// ---------------------------------------------------------------------------
// Singleton instance
// ---------------------------------------------------------------------------

export const hookRegistry = new HookRegistry();
