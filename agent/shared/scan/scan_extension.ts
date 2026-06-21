/**
 * scan_extension.ts — generic provider/registration seam for the PUBLIC
 * memory-region key-scan engine (agent/shared/scan/scan_engine.ts).
 *
 * This is the scan counterpart of agent/shared/hook_contributors.ts: a private
 * protocol unit (full build only) contributes a *region selector* and an
 * optional *protocol-specific classifier* by calling registerScanProvider(...)
 * at module-load time. No PUBLIC file imports the private unit; the full build
 * pulls it in via the private entry (agent/fritap_agent_full.ts), exactly like
 * the hook contributor seam.
 *
 * In the public build no provider registers, so collectScanProviders() returns
 * empty and the engine runs purely generically (the region comes from the
 * public --scan-keys-region CLI value and every candidate is emitted under the
 * reveal-free "scan_candidate" classifier).
 *
 * This module has NO import side effects and (by `import type`) no runtime
 * dependency on the engine, so importing it never starts a scan.
 */

/** A memory region the engine should scan. */
export interface ScanRegionSpec {
    /**
     * "module"  — every readable range backing the named module.
     * "range"   — a single explicit [base, base+size) region.
     * "heap"    — all writable+readable (rw-) ranges in the process.
     */
    kind: "module" | "range" | "heap";
    /** Module name (kind="module"). */
    module?: string;
    /** Region base (kind="range"). */
    base?: NativePointer;
    /** Region size in bytes (kind="range"). */
    size?: number;
    /** Human-readable label carried into emitted candidates (e.g. the module name). */
    label?: string;
}

/** A ranked, anonymous candidate the engine found. Reveal-free by construction. */
export interface ScanCandidate {
    /** Region label the candidate was found in (module name or "base,size"/"heap"). */
    region: string;
    /** Byte offset of the candidate from the region base. */
    offset: number;
    /** Candidate length in bytes. */
    length: number;
    /** Candidate bytes (engine bounds the count it emits). */
    bytes: number[];
    /** Heuristic signal names that fired (e.g. "entropy", "aes128_schedule"). */
    signals: string[];
    /** Aggregate score (higher = more key-like). */
    score: number;
}

/**
 * A protocol's optional contribution to the scan. `selectRegions` narrows the
 * scan to the regions where THAT protocol keeps its keys; `classify` lets the
 * protocol tag a candidate with its own classifier (for private
 * decryption-confirmation in Python) IN ADDITION to the public "scan_candidate"
 * emission — it never replaces it.
 */
export interface ScanProvider {
    /** Provider name (for logging only; never emitted as a classifier). */
    name: string;
    /**
     * Regions to scan for this provider, derived from the generic
     * config_batch.extensions bag. Return [] to contribute no regions.
     */
    selectRegions(extensions: Record<string, any>): ScanRegionSpec[];
    /**
     * Optionally claim a candidate as this protocol's key material. Returns a
     * private classifier (+ optional extra fields) to emit an ADDITIONAL
     * key-material message, or null to leave the candidate as a generic
     * scan_candidate only.
     */
    classify?(candidate: ScanCandidate, extensions: Record<string, any>):
        { classifier: string; fields?: Record<string, any> } | null;
}

const _providers: ScanProvider[] = [];

/** Register a scan provider (idempotent by reference). */
export function registerScanProvider(provider: ScanProvider): void {
    if (!_providers.includes(provider)) {
        _providers.push(provider);
    }
}

/** All registered scan providers, in registration order. */
export function collectScanProviders(): ScanProvider[] {
    return _providers.slice();
}
