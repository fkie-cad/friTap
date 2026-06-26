import { log, devlog } from "../util/log.js";
import { hookRegistry } from "./registry.js";
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
    protocol?: string
): void {
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
        if (isModuleHooked(entry.name, protocol || "tls")) {
            devlog(`[Scanner] ${entry.name} already hooked for ${protocol || "tls"}, skipping`);
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
                protocol || "tls",
            );
            continue;
        }

        // Skip if registry regex already matches this module
        const regexMatch = hookRegistry.findMatch(platform, entry.name, entry.path, protocol);
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
                markModuleHooked(entry.name, protocol || "tls");
            } catch (error) {
                devlog(`[Scanner] Error hooking ${entry.name}: ${error}`);
            }
        } else {
            devlog(`[Scanner] No hook registered for library_type: ${entry.library_type}`);
        }
    }
}
