/**
 * Hook Registry for friTap agent.
 *
 * Typed, queryable registry for platform hooks. Platform agents register
 * their hooks declaratively, and the loader queries the registry at runtime.
 */

 import { ModuleHookingType, Platform, LibraryType } from "./shared_structures";
 import { contributedImplications } from "./hook_contributors.js";
 import { matchNonTLSLibrary } from "../util/non_tls_libs.js";
 import { devlog } from "../util/log.js";

 /**
  * Report a registry exclusion at most once per distinct message.
  *
  * `_isExcluded` runs inside `hookDynamicLoader`'s `onLeave` — on the target's
  * own thread, inside `dlopen`/`LoadLibraryExW` — and `devlog()` ALWAYS `send()`s
  * to the host (only the Python side decides whether to print). An *excluded*
  * module is never passed to `markModuleHooked`, so the usual `isModuleHooked`
  * short-circuit never applies: an app that repeatedly `dlopen`s a denylisted
  * library would post one IPC message per load from inside the loader hook.
  * The message text already encodes module + hook + reason, so it is its own key.
  */
 const reportedExclusions = new Set<string>();

 function devlogExclusionOnce(message: string): void {
     if (reportedExclusions.has(message)) return;
     reportedExclusions.add(message);
     devlog(message);
 }

 // ---------------------------------------------------------------------------
 // Types
 // ---------------------------------------------------------------------------
 
 /**
  * A predicate over a module's filesystem path.
  *
  * A `string` is a case-INSENSITIVE plain substring of the path — the historical
  * semantics, kept because "python" must match `Python.framework` and
  * `C:\Python312\DLLs` alike (see the note in {@link HookRegistry._isExcluded}).
  * A `RegExp` is tested against the RAW path, so the author adds `/i` when they
  * want case-insensitivity; use it when a substring is too loose, e.g. to anchor
  * `/^\/usr\/lib\//` so a vendored `.../Frameworks/usr/lib/` sysroot is not
  * mistaken for the real one.
  *
  * A `RegExp` used here MUST NOT carry the `/g` or `/y` flag: those make
  * `RegExp.prototype.test` stateful via `lastIndex`, and these predicates are
  * deliberately shared across several registrations so that one entry's filter
  * is provably the complement of another's (see
  * `agent/shared/darwin_library_patterns.ts`).
  */
 export type PathFilter = string | RegExp;

 /**
  * Test a single {@link PathFilter} against a module path.
  *
  * Shared by the positive (`pathFilter`) and negative (`excludePathFilter`)
  * filters so the two can never disagree about what "matches" means.
  */
 function pathMatches(modulePath: string, filter: PathFilter): boolean {
     return typeof filter === "string"
         ? modulePath.toLowerCase().includes(filter.toLowerCase())
         : filter.test(modulePath);
 }

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
     /**
      * Positive path requirement for extra specificity: the hook installs only
      * when the module path satisfies this filter.
      *
      * FAILS CLOSED — when no module path is available the hook is skipped, on
      * the grounds that a requirement which cannot be verified is unmet.
      */
     pathFilter?: PathFilter;
     /**
      * Negative path requirement: the hook is skipped when ANY of these filters
      * matches the module path. Same string/RegExp semantics as
      * {@link pathFilter}.
      *
      * FAILS OPEN — when no module path is available the hook is NOT skipped,
      * because an exclusion that cannot be evaluated must not exclude. That
      * asymmetry with `pathFilter` is deliberate and load-bearing: it is what
      * lets a complementary pair of entries (one `pathFilter: X`, one
      * `excludePathFilter: X`) still resolve to exactly one hook when the path
      * is unknown, instead of both dropping out and leaving the module unhooked.
      */
     excludePathFilter?: PathFilter | PathFilter[];
     /** Regex pattern to exclude modules that match the main pattern */
     excludePattern?: RegExp;
     /**
      * Requested protocols for which this hook must NOT install, even though
      * `protocolMatches` would otherwise select it. Used to suppress a
      * companion-protocol library that is irrelevant (and unsafe to scan) for a
      * specific capture intent — e.g. `libringrtc_rffi.so` (Signal's WebRTC/calls
      * BoringSSL) carries no chat keys and crashes the recursive readable-parts
      * scan, so it is excluded for `--protocol signal` while still scanned under
      * generic `--protocol tls`.
      */
     excludeProtocols?: string[];
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
     /**
      * Add-on hook that does NOT extract TLS keys (e.g. Google QUICHE stream
      * hooks, which only feed the plaintext pcap). It still installs and still
      * reports `library_detected`, but it never claims TLS coverage of the
      * module: the loaders record it under a separate dedup tag (see
      * `installTagFor`), and the "already matched by the registry" filters
      * ignore it (see {@link HookRegistry.findPrimaryMatch}). Without this a
      * QUICHE-only match on e.g. libchrome.so marked the module "hooked for
      * tls" and blocked every BoringSSL rescue path.
      */
     supplementary?: boolean;
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

/**
 * Whether a hook registered for `hookProtocol` should install when the user
 * selected `requested`. Beyond the exact match, this encodes companion-protocol
 * implications. Some app-layer protocols are transported over TLS, so selecting
 * one also installs the TLS hooks (to capture the SSLKEYLOGFILE used to strip
 * TLS before app-layer decryption). These implications are contributed
 * generically by optional units via `registerProtocolImplication(...)`; the
 * public core hardcodes only the public Telegram→MTProto implication. Mirrors
 * PROTOCOL_IMPLIES on the Python side (friTap/protocols/registry.py).
 */
/**
 * A requested-protocol selection as it arrives at the registry: a single name
 * (legacy, e.g. "tls"), a comma-joined string ("tls,rc4"), a pre-parsed
 * `Set<string>`, or `undefined`. Multi-protocol selection (Foundation F1) lets
 * the user activate several independent protocols at once (e.g. `--protocol
 * tls,rc4`); a single string keeps behaving exactly as before.
 */
export type RequestedProtocol = string | Set<string> | undefined;

/**
 * Normalize a {@link RequestedProtocol} into the effective FILTER set, or
 * `undefined` meaning "no filter / install everything". The meta values
 * `auto`/`all`, the empty selection and `undefined` all collapse to `undefined`
 * (their historical "install everything" semantics). A comma-joined string is
 * split; whitespace is trimmed; empties are dropped.
 */
export function protocolFilterSet(requested: RequestedProtocol): Set<string> | undefined {
    if (requested === undefined) return undefined;
    const names = typeof requested === "string"
        ? requested.split(",").map(s => s.trim()).filter(Boolean)
        : [...requested].map(s => (s ?? "").trim()).filter(Boolean);
    const set = new Set(names);
    if (set.size === 0) return undefined;
    if (set.has("auto") || set.has("all")) return undefined;
    return set;
}

/**
 * The PRIMARY protocol label for a selection (first element, "tls" fallback).
 * String-typed contexts that predate multi-select — per-module dedup keys
 * (`isModuleHooked`/`markModuleHooked`), `library_detected` message tags — keep
 * consuming a single label. For a single selection this is the selection itself,
 * so single-protocol behaviour is byte-for-byte unchanged.
 */
export function protocolLabel(requested: RequestedProtocol): string {
    if (requested === undefined) return "tls";
    const names = typeof requested === "string"
        ? requested.split(",").map(s => s.trim()).filter(Boolean)
        : [...requested].map(s => (s ?? "").trim()).filter(Boolean);
    return names[0] || "tls";
}

/**
 * Whether a hook registered for `hookProtocol` should install given the
 * requested-protocol SET. Beyond exact set membership this encodes the same
 * companion-protocol implications as before: contributed implications
 * (`registerProtocolImplication(...)`, empty in the public build) and the
 * public Telegram→MTProto rule. Contract: returns true iff `hookProtocol` is a
 * member of `requested`, OR some requested member implies `hookProtocol`.
 * Mirrors PROTOCOL_IMPLIES on the Python side (friTap/protocols/registry.py).
 */
function protocolMatches(hookProtocol: string, requested: Set<string>): boolean {
    if (requested.has(hookProtocol)) return true;
    const implications = contributedImplications();
    for (const req of requested) {
        // Contributed implications (e.g. a private messenger E2E unit declaring
        // that its traffic is TLS-wrapped). Empty in the public build.
        if (implications[req]?.includes(hookProtocol)) return true;
        // `--protocol telegram` ALSO installs the existing tgnet/mtproto
        // transport hooks (cloud-chat keys live in the MTProto transport,
        // Secret-Chat keys in the Java layer).
        if (req === "telegram" && hookProtocol === "mtproto") return true;
    }
    return false;
}

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
     getHooks(platform: Platform, protocol?: RequestedProtocol): HookRegistration[] {
         // Normalize the selection (single name, comma-joined string, or Set)
         // to the effective filter set; `undefined` means "no filter".
         const filter = protocolFilterSet(protocol);
         const key = `${platform}:${filter ? [...filter].slice().sort().join(",") : '*'}`;
         const cached = this._cache.get(key);
         if (cached) return cached;
         let result = this._hooks.filter(h => h.platform === platform);
         if (filter) {
             result = result.filter(h =>
                 protocolMatches(h.protocol, filter) &&
                 // Suppress a hook flagged unsafe for ANY requested protocol.
                 !h.excludeProtocols?.some(p => filter.has(p))
             );
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
     findMatch(platform: Platform, moduleName: string, modulePath?: string, protocol?: RequestedProtocol): HookRegistration | undefined {
         const hooks = this.getHooks(platform, protocol);
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
      * Like {@link findMatch}, but ignores `supplementary` hooks: returns the
      * first match that actually claims (TLS) coverage of the module. Used by
      * the "module already matched by the registry, skipping" filters so a
      * QUIC-stream-only add-on does not hide a module from the library scan.
      */
     findPrimaryMatch(platform: Platform, moduleName: string, modulePath?: string, protocol?: RequestedProtocol): HookRegistration | undefined {
         return this.findAllMatches(platform, moduleName, modulePath, protocol).find(h => !h.supplementary);
     }

     /**
      * Find ALL hooks whose pattern matches *moduleName* on *platform*.
      *
      * @param protocol Optional protocol filter. "auto", "all", or undefined = no filter.
      */
     findAllMatches(platform: Platform, moduleName: string, modulePath?: string, protocol?: RequestedProtocol): HookRegistration[] {
         const hooks = this.getHooks(platform, protocol);
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
     findByLibraryType(platform: Platform, libraryType: string, protocol?: RequestedProtocol): HookRegistration | undefined {
         const hooks = this.getHooks(platform, protocol);
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
         protocol?: RequestedProtocol,
     ): { matches: HookRegistration[]; suppressed: HookCoverageSuppression[] } {
         const candidates = this.findAllMatches(platform, moduleName, modulePath, protocol);
         const effectiveProtocol = protocolFilterSet(protocol);
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
         protocol?: RequestedProtocol,
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
         protocol?: Set<string>,
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
                 if (protocol && !protocolMatches(other.protocol, protocol)) return false;
                 if (requiredType && other.libraryType !== requiredType) return false;
                 if (!other.pattern.test(candidate)) return false;
                 return true;
             });
             if (registered) return candidate;
         }
         return undefined;
     }
 
     /**
      * Check whether a matched hook should be skipped.
      *
      * Four independent gates, evaluated as a FALL-THROUGH chain: the non-TLS
      * denylist, `excludePattern` (name), `excludePathFilter` (path, negative),
      * and `pathFilter` (path, positive). Every gate that applies is evaluated.
      * Do NOT reintroduce an early `return false` for a gate that passes — an
      * earlier version ended the `pathFilter` branch with `return excluded`,
      * which silently made any gate below it dead code for hooks carrying both.
      */
     private _isExcluded(hook: HookRegistration, moduleName: string, modulePath?: string): boolean {
         // Known non-TLS libraries (OS-aware) are never hooked, regardless of
         // which hook's pattern matched them. Resolve the OS via the denylist's
         // own (memoized) detection — the registry `platform` is "linux" for
         // both Android and desktop Linux and so cannot scope correctly here.
         if (matchNonTLSLibrary(moduleName)) {
             devlogExclusionOnce(`registry: skipping ${moduleName} for "${hook.library}" — known non-TLS library (denylist)`);
             return true;
         }
         if (hook.excludePattern && hook.excludePattern.test(moduleName)) {
             devlogExclusionOnce(`registry: skipping ${moduleName} for "${hook.library}" — excludePattern ${hook.excludePattern} matched the module name`);
             return true;
         }
         // Negative path filter. FAILS OPEN: an exclusion we cannot evaluate must
         // not exclude. See the field docs on `excludePathFilter` for why that
         // asymmetry with `pathFilter` below is what keeps a complementary pair of
         // entries resolving to exactly one hook when the path is unknown.
         if (hook.excludePathFilter) {
             if (modulePath) {
                 const filters = Array.isArray(hook.excludePathFilter)
                     ? hook.excludePathFilter : [hook.excludePathFilter];
                 for (const filter of filters) {
                     if (pathMatches(modulePath, filter)) {
                         devlogExclusionOnce(`registry: skipping ${moduleName} for "${hook.library}" — excludePathFilter ${filter} matched the path ${modulePath}`);
                         return true;
                     }
                 }
             } else {
                 devlogExclusionOnce(`registry: ${moduleName} for "${hook.library}" — excludePathFilter set but no module path available (fails open, not excluded)`);
             }
         }
         // Positive path filter. FAILS CLOSED: a requirement we cannot verify is
         // treated as unmet.
         //
         // The string form is case-INSENSITIVE on purpose — do not "tidy" it back
         // to a plain `includes()`. Apple capitalises the framework directory
         // (/Library/Frameworks/Python.framework/Versions/3.13/lib/libssl.3.dylib)
         // and Windows capitalises the install directory
         // (C:\Python312\DLLs\libssl-3.dll), so a case-sensitive match on the
         // "python" pathFilter silently dropped every framework/installer
         // Python's TLS: the hook never installed and nothing was logged.
         if (hook.pathFilter) {
             if (!modulePath) {
                 devlogExclusionOnce(`registry: skipping ${moduleName} for "${hook.library}" — pathFilter ${hook.pathFilter} set but no module path available (fails closed)`);
                 return true;
             }
             if (!pathMatches(modulePath, hook.pathFilter)) {
                 devlogExclusionOnce(`registry: skipping ${moduleName} for "${hook.library}" — pathFilter ${hook.pathFilter} not found in path ${modulePath}`);
                 return true;
             }
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
 