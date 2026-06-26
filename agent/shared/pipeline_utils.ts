/**
 * Shared pipeline utility functions for all TLS libraries.
 *
 * Extracted from OpenSSL_BoringSSL so that GnuTLS, WolfSSL, mbedTLS,
 * NSS, and s2n-tls and other libary hooks can also use the hooking pipeline.
 */

 import { devlog } from "../util/log.js";
 import { defaultPipeline } from "./hooking_pipeline.js";
 import { SymbolStrategy } from "./strategies/symbol_strategy.js";
 import { PatternStrategy } from "./strategies/pattern_strategy.js";
 import { MemoryScanStrategy } from "./strategies/memory_scan_strategy.js";
 import { pairip_safe } from "../fritap_agent.js";
 
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
 
     // --pairip-safe: NEVER register a Memory.scan strategy. PairIP SIGSEGVs the
     // process on a scan of a protected lib, so resolution is symbol+offset only;
     // an unresolved function degrades to "no hook" rather than "scan → crash".
     if (pairip_safe) {
         devlog(`[Pipeline] --pairip-safe: pattern/memory-scan strategies disabled (symbol+offset only)`);
     } else {
         // Priority 80: Pattern-based — registered only when host delivered data.
         if (patternData) {
             const ps = new PatternStrategy();
             ps.setPatternData(patternData);
             defaultPipeline.addStrategy(ps);
         }

         // Priority 40: Memory scan (only when user explicitly enables --experimental)
         if (experimentalMode) {
             defaultPipeline.addStrategy(new MemoryScanStrategy());
         }
     }
 
     // NOTE: OffsetStrategy is NOT registered here.
     // Offsets are applied directly by the constructor when user provides --offsets flag.
 
     devlog(`[Pipeline] Initialized with ${defaultPipeline.size} strategies`);
 }
 
/**
 * Fill in missing addresses using the hooking pipeline. Never overwrites
 * existing non-null addresses. Awaits the pipeline's non-blocking
 * hookModuleAsync() so any underlying pattern/memory scan uses the async
 * Memory.scan and a gracefulDetach can be serviced mid-scan. Callers in an
 * async-capable context (e.g. an async execute_hooks) should await this;
 * fire-and-forget is acceptable where the resolved addresses are not consumed
 * synchronously on the next line.
 *
 * @param addresses - The address map (e.g., this.addresses)
 * @param moduleName - Module name key into addresses
 * @param libraryType - Library type for pattern lookup (e.g., "openssl", "gnutls")
 * @param requiredFunctions - Function names that should be resolved
 */
export async function resolveWithPipelineAsync(
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } },
    moduleName: string,
    libraryType: string,
    requiredFunctions: string[]
): Promise<void> {
    const modAddrs = addresses[moduleName] || {};
    const missing = requiredFunctions.filter(
        fn => !modAddrs[fn] || modAddrs[fn].isNull()
    );
    if (missing.length === 0) return;

    devlog(`[Pipeline] ${moduleName} (${libraryType}): ${missing.length} unresolved: ${missing.join(", ")}`);
    const result = await defaultPipeline.hookModuleAsync(moduleName, libraryType, missing);

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
    } else if (pairip_safe) {
        // Expected under symbol-only --pairip-safe: pattern/memory-scan tiers are
        // disabled, so a lib that doesn't export these symbols (e.g. Conscrypt's
        // libjavacrypto.so, or inlined SSL_get_fd/SSL_SESSION_get_id in libhttpengine.so)
        // simply gets no read/write hooks. Keylog still flows via the callback /
        // ssl_log_secret path — this is not an error.
        devlog(`[Pipeline] ${moduleName}: ${missing.join(", ")} not exported (expected under --pairip-safe; keylog via callback/ssl_log_secret, no read/write hooks for this lib)`);
    } else {
        devlog(`[Pipeline] Could not resolve any of: ${missing.join(", ")}`);
    }
}
 