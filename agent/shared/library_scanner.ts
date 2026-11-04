import { log, devlog } from "../util/log.js";
import { hookRegistry, HookRegistration, RequestedProtocol, protocolLabel } from "./registry.js";
import { Platform } from "./shared_structures.js";
import { matchNonTLSLibrary, noteNonTLSLibrary } from "../util/non_tls_libs.js";
import { baseKey, findLoadedModule, moduleIdentityKey, nameKey } from "./module_identity.js";
import { executeHookRow } from "./record_protocol.js";

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

/** Tracks modules already hooked — prevents double-hooking. This is the one
 *  guard every loader path (initial scan, dlopen/LoadLibrary hook, dependency
 *  scan, tlsLibHunter results, Android/Wine watchers) consults.
 *
 *  Keyed by module IDENTITY (base address, see module_identity.ts) plus the
 *  install tag, so one image reached under several spellings (bare name, real
 *  path, symlinked dlopen() path) is hooked once, while different protocols /
 *  supplementary rows on the same image still each install. Maps identity ->
 *  install tags so an unloaded image's markers can be dropped in one step. */
const hookedModules: Map<string, Set<string>> = new Map();

let unloadObserverAttached = false;

/** Drop the markers of an image the process unmapped, so a later reload is hooked again. */
export function forgetUnloadedModule(module: { name: string; path: string; base: NativePointer | string }): void {
    for (const key of [baseKey(module.base), nameKey(module.name), nameKey(module.path)]) {
        if (hookedModules.delete(key)) devlog(`[hook-guard] ${module.name} unloaded; markers cleared`);
    }
}

function ensureUnloadObserver(): void {
    if (unloadObserverAttached) return;
    unloadObserverAttached = true;
    const P: any = Process as any;
    if (typeof P.attachModuleObserver !== "function") return;
    try {
        P.attachModuleObserver({ onRemoved: (m: Module) => forgetUnloadedModule(m) });
    } catch (error) {
        devlog(`[hook-guard] module observer unavailable: ${error}`);
    }
}

export function markModuleHooked(moduleName: string, protocol: string = "tls"): void {
    ensureUnloadObserver();
    const key = moduleIdentityKey(moduleName);
    let tags = hookedModules.get(key);
    if (tags === undefined) hookedModules.set(key, tags = new Set());
    tags.add(protocol);
}

export function isModuleHooked(moduleName: string, protocol: string = "tls"): boolean {
    // The name key also covers a marker recorded before the image was resolvable.
    for (const key of [moduleIdentityKey(moduleName), nameKey(moduleName)]) {
        if (hookedModules.get(key)?.has(protocol)) return true;
    }
    return false;
}

/**
 * The module name to hand a hook executor (and the loaders' bookkeeping) for
 * `nameOrPath`. Executors look their image up with Process.getModuleByName,
 * which does not follow symlinks, so a dlopen() spelling such as
 * `/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib` must become the mapped
 * module's own name. That is `module.name` unless another loaded image shares
 * the basename, then the unambiguous `module.path`. Strings that resolve to no
 * Frida module (e.g. Wine PE DLLs) are returned unchanged.
 */
export function executorModuleName(nameOrPath: string): string {
    const module = findLoadedModule(nameOrPath);
    if (module === null) return nameOrPath;
    let byName: Module | null = null;
    try { byName = Process.findModuleByName(module.name); } catch (_) { /* ambiguous or missing */ }
    const nameIsUnique = byName !== null && byName.base.toString() === module.base.toString();
    return nameIsUnique ? module.name : module.path;
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

/**
 * Identity of a registry ROW, independent of the protocol SELECTION a loader
 * pass ran under. The selection label (`tls`, `auto`, `rc4`, ...) is what the
 * module-level dedup is keyed by, so two passes with different labels — e.g.
 * the main `--protocol auto` pass and the OHTTP pass that re-runs the TLS
 * loader under "tls", or `--protocol rc4,tls` (label "rc4") plus that same
 * OHTTP pass — both resolve the same TLS rows. Without a row-level marker the
 * executor ran twice and every SSL_read/SSL_write was emitted twice.
 */
export function hookRowTag(match: HookRegistration): string {
    return `row:${match.protocol}:${match.libraryType ?? ""}:${match.library}:${match.pattern}`;
}

/** Whether this exact registry row is already installed on *moduleName*, under any selection. */
export function isHookRowInstalled(match: HookRegistration, moduleName: string): boolean {
    return isModuleHooked(moduleName, hookRowTag(match));
}

/**
 * Whether *match* is already handled on *moduleName*: the row ran under any selection, or
 * (supplementary rows) its own install tag is set. The one per-row check every loader
 * consults before running a row, so a new loader cannot forget half of it.
 */
export function isRowHandled(match: HookRegistration, moduleName: string, protocol: string = "tls"): boolean {
    return isSupplementaryHookInstalled(match, moduleName, protocol) || isHookRowInstalled(match, moduleName);
}

/** Record that *match* was installed on *moduleName* (under {@link installTagFor} and its row identity). */
export function recordHookInstalled(match: HookRegistration, moduleName: string, protocol: string = "tls"): void {
    markModuleHooked(moduleName, installTagFor(match, protocol));
    markModuleHooked(moduleName, hookRowTag(match));
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
        entry.name = executorModuleName(entry.name);
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
        if (typeMatch && isRowHandled(typeMatch, entry.name, protocolTag)) {
            devlog(`[Scanner] ${entry.name}: ${typeMatch.library} already installed, skipping`);
        } else if (typeMatch) {
            log(`[Scanner] ${entry.name} identified as ${entry.library_type} by tlsLibHunter → hooking as ${typeMatch.library}`);
            try {
                Process.getModuleByName(entry.name).ensureInitialized();
                executeHookRow(typeMatch, entry.name, is_base_hook);
                recordHookInstalled(typeMatch, entry.name, protocolTag);
            } catch (error) {
                devlog(`[Scanner] Error hooking ${entry.name}: ${error}`);
            }
        } else {
            devlog(`[Scanner] No hook registered for library_type: ${entry.library_type}`);
        }
    }
}
