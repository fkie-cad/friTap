import { log, devlog } from "../util/log.js";
import { hookRegistry } from "./registry.js";
import { Platform } from "./shared_structures.js";

interface ScanResultEntry {
    name: string;
    path: string;
    base_address: string;
    library_type: string;
    matched_exports: string[];
    detected_version: string;
}

/** Tracks modules already hooked — prevents double-hooking */
const hookedModules: Set<string> = new Set();

export function markModuleHooked(moduleName: string): void {
    hookedModules.add(moduleName);
}

export function isModuleHooked(moduleName: string): boolean {
    return hookedModules.has(moduleName);
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
        // Skip already-hooked modules
        if (isModuleHooked(entry.name)) {
            devlog(`[Scanner] ${entry.name} already hooked, skipping`);
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
                markModuleHooked(entry.name);
            } catch (error) {
                devlog(`[Scanner] Error hooking ${entry.name}: ${error}`);
            }
        } else {
            devlog(`[Scanner] No hook registered for library_type: ${entry.library_type}`);
        }
    }
}
