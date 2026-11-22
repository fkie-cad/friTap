/**
 * Pattern-based hooking strategy.
 *
 * Scans binary memory for known byte sequences to find function
 * addresses when symbols are stripped. Patterns are resolved by OS
 * layer first, then architecture (library → os → arch → function),
 * with primary/fallback chains.
 *
 * Scanning is asynchronous (Frida's non-blocking Memory.scan) so the JS
 * thread can service a gracefulDetach RPC mid-scan — important for large
 * stripped modules (e.g. Chrome's ~193 MB libmonochrome).
 *
 * Priority: 80
 */

import { HookingStrategy, HookResult } from "../hooking_pipeline";
import { devlog, devlog_debug, _isShuttingDownNow } from "../../util/log.js";
import { currentPlatformKey, normalizeArchKey } from "../../util/process_infos.js";
import type { ScanStatus } from "../arm64_xref.js";

type ArchPatterns = Record<string, string | string[]>;

/** Patterns for `funcName`, primary first. */
function patternList(archPatterns: ArchPatterns, funcName: string): string[] {
    const funcPatterns = archPatterns[funcName];
    if (!funcPatterns) return [];
    return Array.isArray(funcPatterns) ? funcPatterns : [funcPatterns];
}

/** A part of the scan could not run, so its misses prove nothing. */
function markIncomplete(status: ScanStatus | undefined, reason: string): void {
    if (!status) return;
    status.complete = false;
    devlog_debug(`[PatternStrategy] scan incomplete: ${reason}`);
}

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

    /** Patterns tryHookAsync tries for `funcName`, in order. */
    patternsFor(moduleName: string, libraryType: string, funcName: string | undefined): string[] {
        if (funcName === undefined) return [];
        const lookup = this.archPatternsFor(moduleName, libraryType);
        return "table" in lookup ? patternList(lookup.table, funcName) : [];
    }

    /** The library -> os -> arch pattern table for the module, or why there is none. */
    private archPatternsFor(moduleName: string, libraryType: string): { table: ArchPatterns } | { error: string } {
        const modulePatterns = this.patternData?.[moduleName] || this.patternData?.[libraryType];
        if (!modulePatterns) return { error: `No patterns defined for ${moduleName} or ${libraryType}` };

        const platform = currentPlatformKey();
        const osPatterns = modulePatterns[platform];
        if (!osPatterns) return { error: `No patterns for OS ${platform} in ${moduleName}` };

        const arch = normalizeArchKey(Process.arch);
        const archPatterns = osPatterns[arch] || osPatterns["default"];
        if (!archPatterns) return { error: `No patterns for architecture ${arch} (OS ${platform}) in ${moduleName}` };
        return { table: archPatterns };
    }

    /**
     * Uniqueness reporting: when a pattern matches MORE than one site in
     * the module, returning the first hit silently is dangerous — it
     * installs an Interceptor at a function we did not intend, often on
     * a hot path (the blog post's PersistentSampleVector trap). Surface
     * a warning at devlog level (always-on, not -do-gated) so the user
     * can spot pattern drift quickly. The first hit is still returned
     * because: (a) for many labels the first hit IS the right function,
     * (b) refusing to install would silently break legitimate captures.
     * For richer per-pattern diagnostics, the user can still run with
     * -do to get the chain-debug enumeration.
     */
    private reportIfAmbiguous(matches: MemoryScanMatch[], where: string): void {
        if (matches.length > 1) {
            const addrs = matches.slice(0, 5).map(m => m.address.toString()).join(", ");
            const more = matches.length > 5 ? `, ... +${matches.length - 5} more` : "";
            devlog(`[PatternStrategy] pattern matched ${matches.length} sites in ${where} ` +
                   `— installing at first hit (${addrs}${more}); if this is the wrong function ` +
                   `the resulting hook may sit on a hot path and slow/hang the process`);
        }
    }

    /**
     * Resolve the requested functions by byte pattern. The underlying memory
     * scan uses the async Memory.scan API (via scanFirstMatchAsync) so the
     * Frida JS thread yields to the event loop between scan chunks and a
     * gracefulDetach RPC can be serviced mid-scan. Awaited by the pipeline's
     * hookModuleAsync() for every TLS library and by the QUIC install path.
     * `status` (optional) learns about errors the result otherwise swallows.
     */
    async tryHookAsync(moduleName: string, libraryType: string, functions: string[],
                       status?: ScanStatus): Promise<HookResult> {
        const hooked: string[] = [];
        const errors: string[] = [];
        const resolved = new Map<string, NativePointer>();

        if (!this.patternData) {
            errors.push("No pattern data available");
            return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
        }

        try {
            const mod = Process.getModuleByName(moduleName);
            const lookup = this.archPatternsFor(moduleName, libraryType);
            if ("error" in lookup) {
                errors.push(lookup.error);
                return { success: false, strategy: this.name, hookedFunctions: hooked, errors, resolvedAddresses: new Map() };
            }

            for (const funcName of functions) {
                if (!lookup.table[funcName]) continue;
                const patterns = patternList(lookup.table, funcName);
                let found = false;

                for (const pattern of patterns) {
                    try {
                        const match = await this.scanFirstMatchAsync(mod, pattern, status);
                        if (match !== null) {
                            hooked.push(funcName);
                            resolved.set(funcName, match);
                            found = true;
                            break;
                        }
                    } catch (scanErr) {
                        markIncomplete(status, `${funcName}: ${scanErr}`);
                    }
                }

                if (!found) {
                    errors.push(`Pattern scan failed for ${funcName}`);
                }
            }
        } catch (err) {
            errors.push(`Pattern strategy error: ${err}`);
            markIncomplete(status, `${err}`);
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
     * Scan a module for a byte pattern and return the first match, or null.
     *
     * Scans only the module's executable (r-x) ranges. A single scan over the
     * whole [base, base+size] span throws an "access violation" on large modules
     * whose span includes unreadable pages (e.g. Chrome's ~193 MB
     * libmonochrome_64.so). Byte patterns target function prologues, which always
     * live in executable memory, so r-x scanning is both correct and faster.
     * Falls back to a whole-module scan if range enumeration yields nothing.
     * Checks _isShuttingDownNow() between ranges so the scan loop stops issuing
     * new scans the moment detach begins.
     */
    private async scanFirstMatchAsync(mod: Module, pattern: string,
                                      status?: ScanStatus): Promise<NativePointer | null> {
        let ranges: RangeDetails[] = [];
        try {
            ranges = mod.enumerateRanges("r-x");
        } catch (_e) {
            // fall through to whole-module scan
        }

        if (!ranges || ranges.length === 0) {
            return this.scanRegionAsync(mod.base, mod.size, pattern, `${mod.name} (whole-module scan)`, status);
        }

        for (const range of ranges) {
            // Early-abort on shutdown so a detach mid-scan returns fast.
            if (_isShuttingDownNow()) {
                markIncomplete(status, "shutting down");
                return null;
            }
            const hit = await this.scanRegionAsync(range.base, range.size, pattern, `${mod.name}@${range.base}`, status);
            if (hit !== null) return hit;
        }
        return null;
    }

    /**
     * Scan a single [base, base+size) region asynchronously and resolve to the
     * first match (or null). Accumulates every match — it does NOT stop on the
     * first — so reportIfAmbiguous can warn when a pattern is non-unique.
     * Unreadable pages are skipped.
     */
    private scanRegionAsync(base: NativePointer, size: number, pattern: string, where: string,
                            status?: ScanStatus): Promise<NativePointer | null> {
        return new Promise((resolve) => {
            const acc: MemoryScanMatch[] = [];
            try {
                Memory.scan(base, size, pattern, {
                    onMatch: (address, matchSize) => { acc.push({ address, size: matchSize }); },
                    onError: (reason) => { markIncomplete(status, `${where}: ${reason}`); },
                    onComplete: () => {
                        this.reportIfAmbiguous(acc, where);
                        resolve(acc.length > 0 ? acc[0].address : null);
                    },
                });
            } catch (e) {
                markIncomplete(status, `${where}: ${e}`);
                resolve(null);
            }
        });
    }

    isAvailable(): boolean {
        return this.patternData !== null;
    }
}
