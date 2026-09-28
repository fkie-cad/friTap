import { log, devlog } from "../util/log.js";
import { hookRegistry, HookRegistration, RequestedProtocol, protocolLabel } from "./registry.js";
import { Platform } from "./shared_structures.js";
import { matchNonTLSLibrary, noteNonTLSLibrary } from "../util/non_tls_libs.js";

interface ScanResultEntry {
    name: string;
    path: string;
    base_address: string;
    library_type: string;
    matched_exports: string[];
    detected_version: string;
    /**
     * Annotation injected by the Python orchestrator
     * (friTap/protocols/tls_handler.covered_by_sibling) when a module's
     * BoringSSL surface is actually carried by another loaded library.
     * When present, the scanner skips this entry to avoid futile work.
     */
    covered_by_sibling?: { sibling: string; reason: string };
}

/** Tracks modules already hooked — prevents double-hooking.
 *  Keys are "${moduleName}:${protocol}" to allow the same module
 *  to be hooked by different protocols (e.g. TLS and OHTTP). */
const hookedModules: Set<string> = new Set();

export function markModuleHooked(moduleName: string, protocol: string = "tls"): void {
    hookedModules.add(`${moduleName}:${protocol}`);
}

export function isModuleHooked(moduleName: string, protocol: string = "tls"): boolean {
    return hookedModules.has(`${moduleName}:${protocol}`);
}

/**
 * Dedup tag under which an installed registry match is recorded. Supplementary
 * add-on hooks (e.g. Google QUICHE) get their own
 * `${protocol}:supplementary:${library}` tag so they never count as coverage
 * for `protocol` — the module stays eligible for the real (key-extracting)
 * hooks on later passes. The tag is per ROW (keyed by `library`), not per
 * module: a per-module `${protocol}:supplementary` tag made the first
 * supplementary row installed on a module block every other supplementary row
 * matching that module.
 */
export function installTagFor(match: HookRegistration, protocol: string = "tls"): string {
    return match.supplementary ? `${protocol}:supplementary:${match.library}` : protocol;
}

/**
 * Whether *match* must be skipped because this supplementary hook is already
 * installed on *moduleName* (e.g. the dynamic loader fired again for a module
 * a supplementary hook was installed on, but that no primary hook claimed).
 * Always false for primary hooks: their dedup is the module-level
 * `isModuleHooked(moduleName, protocol)` check the loaders run first.
 */
export function isSupplementaryHookInstalled(match: HookRegistration, moduleName: string, protocol: string = "tls"): boolean {
    return !!match.supplementary && isModuleHooked(moduleName, installTagFor(match, protocol));
}

/** Record that *match* was installed on *moduleName* (under {@link installTagFor}). */
export function recordHookInstalled(match: HookRegistration, moduleName: string, protocol: string = "tls"): void {
    markModuleHooked(moduleName, installTagFor(match, protocol));
}

export function announceSiblingCoverage(
    moduleName: string,
    sibling: string,
    reason: string,
    protocol: string = "tls",
): void {
    log(`${moduleName}: BoringSSL appears to live in sibling '${sibling}'; skipping redundant scan`);
    devlog(`[coverage] ${moduleName} covered by ${sibling}: ${reason}`);
    markModuleHooked(moduleName, protocol);
}

/**
 * Process pre-scan results from tlsLibHunter.
 * For each detected library NOT already matched by the regex registry,
 * look up by libraryType and invoke the corresponding hook.
 */
export function processScanResults(
    scanData: string,
    platform: Platform,
    is_base_hook: boolean,
    protocol?: RequestedProtocol
): void {
    // Primary label for the single-value string contexts (dedup keys, coverage
    // announce); the raw `protocol` selection drives multi-protocol registry
    // filtering via findMatch/findByLibraryType below.
    const protocolTag = protocolLabel(protocol);
    // Reject uninitialized scan_results (placeholder string from agent init)
    if (!scanData || scanData.length < 3 || scanData.startsWith("{SCAN_RESULTS")) return;

    let entries: ScanResultEntry[];
    try {
        entries = JSON.parse(scanData);
    } catch (e) {
        devlog("Failed to parse library scan results: " + e);
        return;
    }

    log(`[Scanner] Processing ${entries.length} pre-scanned libraries`);

    for (const entry of entries) {
        // Skip already-hooked modules (for this protocol)
        if (isModuleHooked(entry.name, protocolTag)) {
            devlog(`[Scanner] ${entry.name} already hooked for ${protocolTag}, skipping`);
            continue;
        }

        // Skip known non-TLS libraries (e.g. WebView plat_support/loader). The
        // registry's findMatch below applies this same guard, but the
        // findByLibraryType fallback does not — so filter explicitly here.
        if (matchNonTLSLibrary(entry.name)) {
            noteNonTLSLibrary(entry.name);
            continue;
        }

        if (entry.covered_by_sibling) {
            announceSiblingCoverage(
                entry.name,
                entry.covered_by_sibling.sibling,
                entry.covered_by_sibling.reason,
                protocolTag,
            );
            continue;
        }

        // Skip if registry regex already matches this module. Supplementary
        // (non-key-extracting) rows don't count: a QUICHE-only match must not
        // keep a BoringSSL module from its library_type hook.
        const regexMatch = hookRegistry.findPrimaryMatch(platform, entry.name, entry.path, protocol);
        if (regexMatch) {
            devlog(`[Scanner] ${entry.name} matches registry pattern, skipping`);
            continue;
        }

        // Look up hook by library_type
        const typeMatch = hookRegistry.findByLibraryType(platform, entry.library_type, protocol);
        if (typeMatch) {
            log(`[Scanner] ${entry.name} identified as ${entry.library_type} by tlsLibHunter → hooking as ${typeMatch.library}`);
            try {
                Process.getModuleByName(entry.name).ensureInitialized();
                typeMatch.hookFn(entry.name, is_base_hook);
                recordHookInstalled(typeMatch, entry.name, protocolTag);
            } catch (error) {
                devlog(`[Scanner] Error hooking ${entry.name}: ${error}`);
            }
        } else {
            devlog(`[Scanner] No hook registered for library_type: ${entry.library_type}`);
        }
    }
}
