/**
 * Hook Registry for friTap agent.
 *
 * Typed, queryable registry for platform hooks. Platform agents register
 * their hooks declaratively, and the loader queries the registry at runtime.
 */

 import { ModuleHookingType, Platform, LibraryType } from "./shared_structures";

 // ---------------------------------------------------------------------------
 // Types
 // ---------------------------------------------------------------------------
 
 export interface HookRegistration {
     /** Target platform: "linux", "darwin", "windows", "wine" */
     platform: Platform;
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
     /** Regex pattern to exclude modules that match the main pattern */
     excludePattern?: RegExp;
     /** tlsLibHunter library_type for scan-based matching */
     libraryType?: LibraryType;
     /**
      * Annotation: this module's TLS surface is actually carried by a sibling
      * library loaded into the same process.  When a trusted sibling is
      * present, the loader will suppress this hook to avoid burning wall-clock
      * on a pattern scan that cannot succeed (the function we are looking for
      * lives in the sibling).  See `findAllMatchesWithCoverage`.
      */
     coveredBySibling?: { siblingPattern: RegExp; reason: string };
     /** Bypass `coveredBySibling` suppression (e.g. user passed --force-scan). */
     forceScan?: boolean;
 }

 /**
  * Record emitted when {@link HookRegistry.findAllMatchesWithCoverage} drops a
  * candidate hook because a trusted sibling library already covers its
  * TLS surface.  Callers use this to log a friendly explanation to the user.
  */
 export interface HookCoverageSuppression {
     hook: HookRegistration;
     moduleName: string;
     siblingName: string;
     reason: string;
 }
 
 // ---------------------------------------------------------------------------
 // Registry
 // ---------------------------------------------------------------------------
 
 export class HookRegistry {
     private _hooks: HookRegistration[] = [];
     private _cache = new Map<string, HookRegistration[]>();
 
     /**
      * Register a new hook.
      *
      * @param reg Partial registration; `protocol` defaults to "tls",
      *            `priority` defaults to 100.
      */
     register(reg: Partial<HookRegistration> & Pick<HookRegistration, "platform" | "pattern" | "hookFn" | "library"> & { platform: Platform }): void {
         this._cache.clear();
         this._hooks.push({
             protocol: "tls",
             priority: 100,
             ...reg,
         } as HookRegistration);
     }
 
     /**
      * Bulk-register an array of hooks (convenience for platform agents).
      */
     registerAll(regs: Array<Partial<HookRegistration> & Pick<HookRegistration, "platform" | "pattern" | "hookFn" | "library"> & { platform: Platform }>): void {
         for (const reg of regs) {
             this._hooks.push({
                 protocol: "tls",
                 priority: 100,
                 ...reg,
             } as HookRegistration);
         }
         this._cache.clear();
     }
 
     /**
      * Return all hooks for a given platform, optionally filtered by protocol,
      * sorted by descending priority.
      */
     getHooks(platform: Platform, protocol?: string): HookRegistration[] {
         const key = `${platform}:${protocol || '*'}`;
         const cached = this._cache.get(key);
         if (cached) return cached;
         let result = this._hooks.filter(h => h.platform === platform);
         if (protocol) {
             result = result.filter(h => h.protocol === protocol);
         }
         result = result.sort((a, b) => b.priority - a.priority);
         this._cache.set(key, result);
         return result;
     }
 
     /**
      * Find the first hook whose pattern matches *moduleName* on *platform*.
      *
      * @param protocol Optional protocol filter. "auto", "all", or undefined = no filter.
      */
     findMatch(platform: Platform, moduleName: string, modulePath?: string, protocol?: string): HookRegistration | undefined {
         const effectiveProtocol = (protocol && protocol !== "auto" && protocol !== "all") ? protocol : undefined;
         const hooks = this.getHooks(platform, effectiveProtocol);
         for (const hook of hooks) {
             if (hook.pattern.test(moduleName)) {
                 if (this._isExcluded(hook, moduleName, modulePath)) {
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
      * @param protocol Optional protocol filter. "auto", "all", or undefined = no filter.
      */
     findAllMatches(platform: Platform, moduleName: string, modulePath?: string, protocol?: string): HookRegistration[] {
         const effectiveProtocol = (protocol && protocol !== "auto" && protocol !== "all") ? protocol : undefined;
         const hooks = this.getHooks(platform, effectiveProtocol);
         const matches: HookRegistration[] = [];
         for (const hook of hooks) {
             if (hook.pattern.test(moduleName)) {
                 if (this._isExcluded(hook, moduleName, modulePath)) {
                     continue;
                 }
                 matches.push(hook);
             }
         }
         return matches;
     }
 
     /**
      * Find the first hook matching a tlsLibHunter library_type.
      */
     findByLibraryType(platform: Platform, libraryType: string, protocol?: string): HookRegistration | undefined {
         const effectiveProtocol = (protocol && protocol !== "auto" && protocol !== "all") ? protocol : undefined;
         const hooks = this.getHooks(platform, effectiveProtocol);
         return hooks.find(h => h.libraryType === libraryType);
     }

     /**
      * Like {@link findAllMatches}, but suppresses any match whose
      * `coveredBySibling` annotation is satisfied by a currently-loaded sibling
      * (e.g. Cronet APEX split → libmainlinecronet covered by stable_cronet_libssl).
      * `loadedModuleNames` may be passed as a thunk so callers on the dlopen
      * hot path can avoid enumerating modules unless coverage is actually needed.
      */
     findAllMatchesWithCoverage(
         platform: Platform,
         moduleName: string,
         modulePath: string | undefined,
         loadedModuleNames: string[] | (() => string[]),
         protocol?: string,
     ): { matches: HookRegistration[]; suppressed: HookCoverageSuppression[] } {
         const candidates = this.findAllMatches(platform, moduleName, modulePath, protocol);
         const effectiveProtocol = (protocol && protocol !== "auto" && protocol !== "all") ? protocol : undefined;
         const matches: HookRegistration[] = [];
         const suppressed: HookCoverageSuppression[] = [];
         let resolvedModules: string[] | null = null;
         const resolveLoaded = (): string[] => {
             if (resolvedModules === null) {
                 resolvedModules = typeof loadedModuleNames === "function"
                     ? loadedModuleNames() : loadedModuleNames;
             }
             return resolvedModules;
         };
         for (const hook of candidates) {
             if (hook.forceScan || !hook.coveredBySibling) {
                 matches.push(hook);
                 continue;
             }
             const sibling = this._findCoveringSibling(hook, moduleName, resolveLoaded(), effectiveProtocol);
             if (!sibling) {
                 matches.push(hook);
                 continue;
             }
             suppressed.push({
                 hook,
                 moduleName,
                 siblingName: sibling,
                 reason: hook.coveredBySibling.reason,
             });
         }
         return { matches, suppressed };
     }

     findMatchWithCoverage(
         platform: Platform,
         moduleName: string,
         modulePath: string | undefined,
         loadedModuleNames: string[] | (() => string[]),
         protocol?: string,
     ): { hook: HookRegistration | undefined; suppressed: HookCoverageSuppression[] } {
         const { matches, suppressed } = this.findAllMatchesWithCoverage(
             platform, moduleName, modulePath, loadedModuleNames, protocol,
         );
         return { hook: matches[0], suppressed };
     }

     /**
      * A qualifying sibling has a different name, matches `siblingPattern`,
      * and is itself registered with matching libraryType (and protocol) —
      * the last criterion guards against coincidental name matches.
      */
     private _findCoveringSibling(
         hook: HookRegistration,
         selfName: string,
         loadedModuleNames: string[],
         protocol?: string,
     ): string | undefined {
         if (!hook.coveredBySibling) return undefined;
         const siblingPattern = hook.coveredBySibling.siblingPattern;
         const requiredType = hook.libraryType;
         for (const candidate of loadedModuleNames) {
             if (!candidate || candidate === selfName) continue;
             if (!siblingPattern.test(candidate)) continue;
             const registered = this._hooks.some((other) => {
                 if (other === hook) return false;
                 if (other.platform !== hook.platform) return false;
                 if (protocol && other.protocol !== protocol) return false;
                 if (requiredType && other.libraryType !== requiredType) return false;
                 if (!other.pattern.test(candidate)) return false;
                 return true;
             });
             if (registered) return candidate;
         }
         return undefined;
     }
 
     /**
      * Check whether a matched hook should be skipped due to excludePattern or pathFilter.
      */
     private _isExcluded(hook: HookRegistration, moduleName: string, modulePath?: string): boolean {
         if (hook.excludePattern && hook.excludePattern.test(moduleName)) {
             return true;
         }
         if (hook.pathFilter && modulePath) {
             return !modulePath.includes(hook.pathFilter);
         }
         if (hook.pathFilter && !modulePath) {
             return true;
         }
         return false;
     }
 
     /**
      * List all registered platforms.
      */
     getPlatforms(): Platform[] {
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
         this._cache.clear();
     }
 }
 
 // ---------------------------------------------------------------------------
 // Singleton instance
 // ---------------------------------------------------------------------------
 
 export const hookRegistry = new HookRegistry();
 