/**
 * Shared pipeline utility functions for all TLS libraries.
 *
 * Extracted from OpenSSL_BoringSSL so that GnuTLS, WolfSSL, mbedTLS,
 * NSS, and s2n-tls can also use the hooking pipeline.
 */

import { devlog } from "../util/log.js";
import { defaultPipeline } from "./hooking_pipeline.js";
import { SymbolStrategy } from "./strategies/symbol_strategy.js";
import { PatternStrategy } from "./strategies/pattern_strategy.js";
import { MemoryScanStrategy } from "./strategies/memory_scan_strategy.js";

/**
 * Initialize the singleton pipeline with available strategies.
 * Idempotent — safe to call multiple times.
 *
 * @param patternData - Parsed pattern data (or undefined)
 * @param experimentalMode - Whether --experimental flag is set
 */
export function initializePipeline(patternData?: any, experimentalMode?: boolean): void {
    if (defaultPipeline.size > 0) return;

    // Priority 100: Symbol resolution (always)
    defaultPipeline.addStrategy(new SymbolStrategy());

    // Priority 80: Pattern-based (always registered; functional only when data available)
    if (patternData) {
        const ps = new PatternStrategy();
        ps.setPatternData(patternData);
        defaultPipeline.addStrategy(ps);
    }

    // Priority 40: Memory scan (only when user explicitly enables --experimental)
    if (experimentalMode) {
        defaultPipeline.addStrategy(new MemoryScanStrategy());
    }

    // NOTE: OffsetStrategy is NOT registered here.
    // Offsets are applied directly by the constructor when user provides --offsets flag.

    devlog(`[Pipeline] Initialized with ${defaultPipeline.size} strategies`);
}

/**
 * Fill in missing addresses using the hooking pipeline.
 * Never overwrites existing non-null addresses.
 *
 * @param addresses - The address map (e.g., this.addresses)
 * @param moduleName - Module name key into addresses
 * @param libraryType - Library type for pattern lookup (e.g., "openssl", "gnutls")
 * @param requiredFunctions - Function names that should be resolved
 */
export function resolveWithPipeline(
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } },
    moduleName: string,
    libraryType: string,
    requiredFunctions: string[]
): void {
    const modAddrs = addresses[moduleName] || {};
    const missing = requiredFunctions.filter(
        fn => !modAddrs[fn] || modAddrs[fn].isNull()
    );
    if (missing.length === 0) return;

    devlog(`[Pipeline] ${missing.length} unresolved in ${libraryType}: ${missing.join(", ")}`);
    const result = defaultPipeline.hookModule(moduleName, libraryType, missing);

    if (result.resolvedAddresses.size > 0) {
        if (!addresses[moduleName]) {
            addresses[moduleName] = {};
        }
        for (const [fn, addr] of result.resolvedAddresses) {
            if (!addresses[moduleName][fn] || addresses[moduleName][fn].isNull()) {
                addresses[moduleName][fn] = addr;
                devlog(`[Pipeline] Resolved ${fn} via ${result.strategy}: ${addr}`);
            }
        }
    } else {
        devlog(`[Pipeline] Could not resolve any of: ${missing.join(", ")}`);
    }
}
