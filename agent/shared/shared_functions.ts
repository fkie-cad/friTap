import { log, devlog, devlog_error, hookBreadcrumb } from "../util/log.js";
import { toHexString } from "../util/hex.js";
import { AF_INET, AF_INET6, AddressFamilyMapping, unwantedFDs, Platform, hookExecutorInstalled, isPendingHookOutcome } from "./shared_structures.js";
import { HookRegistration, HookRegistry, RequestedProtocol, protocolLabel } from "./registry.js";
import { Java, JavaWrapper } from "./javalib.js";
import { offsets, ohttp_enabled, resolveProtocolTag, selected_protocol, selected_protocols } from "./shared_structures.js";
import { announceSiblingCoverage, executorModuleName, isModuleHooked, isRowHandled, recordHookInstalled } from "./library_scanner.js";
import { executeHookRow, recordProtocolOf } from "./record_protocol.js";
import { isDeepSymbolResolutionEnabled } from "./deep_symbol_resolution.js";
import { warnAntiTamper } from "../util/anti_tamper.js";
import { watchFunctionEntries } from "../util/hw_breakpoint.js";
import { isReadable, resetReadableCache } from "../util/safe_memory.js";
import { nativeSocketObserver, NativeSocketObserver, CLOSED_FD_CONSUMER, fdCloseFunction } from "./native_socket_observer.js";
// Pure sockaddr/PRNetAddr decoders live in sockaddr.ts so they can be unit-tested
// under Node without this module's heavy Frida import graph. Imported for internal
// use (getPortsAndAddresses) and re-exported below for existing importers.
import { decodeSockaddr, readSockaddrFamily } from "./sockaddr.js";
import type { DecodedSockaddr, ByteOrderFns } from "./sockaddr.js";

/*
 * Tracks which (platform, loader-function, protocol) triples already have a
 * dlopen / android_dlopen_ext interceptor installed. The dynamic-loader hook
 * is installed once per protocol on purpose — installOhttpHooks() and
 * android.ts each install one for the active protocol selection. The
 * library_scan_enabled branch in android.ts:182-188 used to install a
 * redundant *second* TLS-protocol hook on the same loader; this Set
 * suppresses that one.
 */
const _installedDynamicLoaders = new Set<string>();

/**
 * Check whether OHTTP hooks should be installed for the current configuration.
 *
 * OHTTP is part of the TLS protocol family in the registry (entries are
 * tagged `protocol: "tls"`), so it activates whenever the TLS family is
 * being installed — that is, on the default `--protocol tls` and on the
 * install-everything modes (`--protocol auto` and `--protocol all`).
 */
/**
 * Whether the TLS protocol family is in the active selection. True for the
 * default `--protocol tls` and the install-everything meta values `auto`/`all`;
 * false for a non-TLS exclusive selection such as `--protocol mtproto`/`ssh`/
 * `ipsec`. TLS-only work (the Android TLS Java provider hooks, OHTTP) keys off
 * this so it is not installed for a purely-native capture. Membership test over
 * the full selection set so it holds regardless of where tls appears in a
 * multi-protocol selection.
 */
export function isTlsFamilyRequested(): boolean {
    return selected_protocols.has("tls") ||
        selected_protocols.has("auto") ||
        selected_protocols.has("all");
}

export function shouldInstallOhttpHooks(): boolean {
    return ohttp_enabled && isTlsFamilyRequested();
}

/**
 * Install OHTTP hooks via ssl_library_loader and hookDynamicLoader if enabled.
 * Eliminates repeated guard + call patterns in platform files.
 *
 * Passes the TLS protocol filter because OHTTP entries live under the TLS
 * family in the registry (`protocol: "tls"` with `libraryType: "nss_hpke"`).
 *
 * @param skipLoaderHook When true, hook only already-loaded modules and do NOT
 *   install the inline `android_dlopen_ext`/`dlopen` loader trampoline. This is
 *   the same trampoline PairIP / anti-tamper runtimes detect and SIGSEGV on
 *   (fkie-cad/friTap#64); the Android caller gates it behind --no-loader-hook /
 *   spawn+anti-tamper. Defaults to false so every other platform is unchanged.
 */
export function installOhttpHooks(
    platform: Platform,
    hookRegistry: HookRegistry,
    moduleNames: Array<string>,
    platformLabel: string,
    loaderConfig: DynamicLoaderConfig,
    skipLoaderHook: boolean = false,
): void {
    if (!shouldInstallOhttpHooks()) return;
    ssl_library_loader(platform, hookRegistry, moduleNames, platformLabel, true, "tls");
    if (!skipLoaderHook) {
        hookDynamicLoader(loaderConfig, hookRegistry, moduleNames, false, "tls");
    }
}

function wait_for_library_loaded(module_name: string){
    let timeout_library = 5;
    let module_adress = Process.getModuleByName(module_name).base;
    if(module_adress === NULL || module_adress === null){
        log("[*] Waiting "+timeout_library+" milliseconds for the loading of "+module_name);
        setTimeout(wait_for_library_loaded,timeout_library)
    }
}

/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */

/**
 * Loader that uses HookRegistry to find and invoke hooks for loaded modules.
 * Queries the registry for hooks matching each module name and invokes them.
 *
 * @param platform Target platform (e.g., "linux", "android", "ios")
 * @param hookRegistry The HookRegistry singleton instance
 * @param moduleNames Array of loaded module names to check against
 * @param platformOs Human-readable platform OS name for logging
 * @param is_base_hook Boolean indicating if this is a base hook or dynamic load
 */
export function ssl_library_loader(platform: Platform, hookRegistry: HookRegistry, moduleNames: Array<string>, platformOs: string, is_base_hook: boolean, protocol?: RequestedProtocol): void {
    // Primary label for the single-value string contexts (dedup keys, message
    // tags); the raw `protocol` selection still drives multi-protocol registry
    // filtering via findAllMatchesWithCoverage below.
    const protocolTag = protocolLabel(protocol);
    for (let module_name of moduleNames) {
        module_name = executorModuleName(module_name);
        // Anti-tamper libraries (e.g. PairIP's libpairipcore.so) detect inline
        // hooks and crash the process; warn the user and never hook/scan them.
        if (warnAntiTamper(module_name)) continue;

        // Get module info for path filtering
        let modulePath: string | undefined;
        try {
            const module = Process.getModuleByName(module_name);
            modulePath = module.path;
        } catch (error) {
            // Module might not be loaded yet, continue without path
        }

        if (isModuleHooked(module_name, protocolTag)) {
            devlog(`${module_name} already hooked for ${protocolTag}, skipping`);
            continue;
        }

        const { matches, suppressed } = hookRegistry.findAllMatchesWithCoverage(
            platform, module_name, modulePath, moduleNames, protocol,
        );
        for (const drop of suppressed) {
            announceSiblingCoverage(drop.moduleName, drop.siblingName, drop.reason, protocolTag);
        }

        for (let match of matches) {
            if (isRowHandled(match, module_name, protocolTag)) {
                devlog(`${module_name}: ${match.library} already installed, skipping`);
                continue;
            }
            try {
                try {
                    Process.getModuleByName(module_name).ensureInitialized();
                } catch (error) {
                    wait_for_library_loaded(module_name);
                }

                // Crash-attribution: record which library we are about to
                // inline-hook. If an anti-tamper runtime (e.g. PairIP) tears the
                // process down in response, on_detach can name this as the last
                // instrumented library instead of an empty breadcrumb (#64).
                hookBreadcrumb(`install-tls-hooks: ${module_name}`);

                installHookRow(match, module_name, is_base_hook, protocolTag, modulePath, `found & will be hooked on ${platformOs}`);
            } catch (error) {
                if (checkNumberOfExports(module_name) > 3) {
                    devlog_error(`error: skipping module ${module_name}`)
                    devlog_error("Loader error: " + error)
                }
            }
        }
    }
}

/**
 * Run one registry row's executor on `moduleName`, then announce and report it. The row is
 * recorded as handled either way (supplementary rows under their own tag, so they never
 * mark the module as covered for protocolTag), so a declined row is not re-run on every
 * rescan; the executor runs under the row's record protocol (record_protocol.ts), so every
 * listener it attaches tags its records with it; the console line — naming that protocol, since one module can match
 * several (libssl: tls and rc4 under --protocol auto) — and library_detected are emitted
 * only when the executor installed hooks (ModuleHookingType: `false` = nothing installed).
 * An executor exception propagates: nothing is recorded or reported.
 */
function installHookRow(match: HookRegistration, moduleName: string, is_base_hook: boolean,
                        protocolTag: string, modulePath: string | undefined, announcement: string): void {
    const protocol = resolveProtocolTag(protocolTag, recordProtocolOf(match));
    const outcome = executeHookRow(match, moduleName, is_base_hook);
    recordHookInstalled(match, moduleName, protocolTag);
    const report = (settled: unknown) => reportHookRow(match, moduleName, protocol, modulePath, announcement, settled);
    if (isPendingHookOutcome(outcome)) {
        outcome.then(report, (e: unknown) => devlog(`${moduleName}: ${match.library} install failed: ${e}`));
        return;
    }
    report(outcome);
}

/** Announce and report (library_detected) a row once its executor's verdict is known. */
function reportHookRow(match: HookRegistration, moduleName: string, protocol: string,
                       modulePath: string | undefined, announcement: string, outcome: unknown): void {
    if (!hookExecutorInstalled(outcome)) {
        devlog(`${moduleName}: ${match.library} installed no ${protocol} hooks; not reported`);
        return;
    }
    log(`${moduleName} ${announcement} (${protocol})!`);
    // Notify host that a library was detected. modulePath is only resolved by the
    // loaders when registry filtering needs it (hookDynamicLoader: extractModulePath),
    // but the host classifies by path (GMS Cronet vs embedded Cronet), so fill it here.
    send({contentType: "library_detected", library: moduleName, path: modulePath || loadedModulePath(moduleName), protocol});
}

/**
 * Filesystem path of the loaded module `moduleName`, or "" when it is not (or no
 * longer) mapped. Used for host-side reporting only, never for registry filtering.
 */
export function loadedModulePath(moduleName: string): string {
    try {
        return Process.findModuleByName(moduleName)?.path ?? "";
    } catch (_) {
        return "";
    }
}

/**
 * --pairip-safe spawn + attach watcher (friTap#64). Hooks the allowlisted TLS
 * libs (already registered in `hookRegistry`) WITHOUT an inline android_dlopen_ext
 * loader hook, WITHOUT a HW breakpoint, and WITHOUT any Memory.scan:
 *   - waits out PairIP's startup integrity window (`firstDelayMs`), then hooks
 *     any already-loaded targets (the spawn case: TLS libs load AFTER resume),
 *   - keeps watching for late target loads via Process.attachModuleObserver
 *     (Frida 17.x; non-invasive — no code patch) with a setInterval poll fallback.
 * All hooking runs on the JS thread via setTimeout(0) — never inline inside a
 * loader callback (which fires synchronously mid-dlopen on the app thread and
 * could perturb PairIP at the worst moment).
 */
export function installPairipSafeWatcher(
    platform: Platform,
    hookRegistry: HookRegistry,
    getFreshModuleNames: () => Array<string>,
    protocol: RequestedProtocol,
    isTarget: (name: string) => boolean,
    firstDelayMs: number,
    pollIntervalMs: number,
): void {
    let scanScheduled = false;
    const rescan = () => {
        if (scanScheduled) return;
        scanScheduled = true;
        setTimeout(() => {
            scanScheduled = false;
            try {
                ssl_library_loader(platform, hookRegistry, getFreshModuleNames(), "Android", true, protocol);
            } catch (e) {
                devlog_error(`[pairip-safe watcher] rescan error: ${e}`);
            }
        }, 0);
    };

    setTimeout(() => {
        // Hook targets that became resident during the startup quiet period.
        rescan();
        // Event-driven late-load watch (preferred; detachable, no code patch).
        let observed = false;
        try {
            const P: any = Process as any;
            if (typeof P.attachModuleObserver === "function") {
                P.attachModuleObserver({
                    onAdded(m: any) { try { if (m && isTarget(m.name)) rescan(); } catch (e) { /* ignore */ } },
                });
                observed = true;
                devlog("[pairip-safe watcher] late-load watch via Process.attachModuleObserver");
            }
        } catch (e) {
            // fall through to polling
        }
        if (!observed) {
            devlog("[pairip-safe watcher] late-load watch via setInterval poll");
            setInterval(rescan, pollIntervalMs);
        }
    }, firstDelayMs);
}



// ---------------------------------------------------------------------------
// Dynamic Loader Hooking
// ---------------------------------------------------------------------------

export interface DynamicLoaderConfig {
    /** Platform identifier for registry queries */
    platform: Platform;
    /** Human-readable label for log messages (e.g., "Android", "Linux", "iOS") */
    platformLabel: string;
    /** Regex pattern to find the loader module among loaded modules (not needed when resolveViaApi is set) */
    loaderLibrary?: string | RegExp;
    /** Primary function name to hook (e.g., "dlopen", "LoadLibraryExW") */
    functionName: string;
    /** If set, use ApiResolver instead of module export lookup (e.g., "exports:KERNELBASE.dll!*LoadLibraryExW") */
    resolveViaApi?: string;
    /** Check for this export first; fall back to functionName if not found (e.g., "android_dlopen_ext") */
    preferFunction?: string;
    /** If true, resolve modulePath from loaded module in onLeave (for path-based registry filtering) */
    extractModulePath?: boolean;
    /** If true, derive module name from ModuleMap(retval) instead of args[0].readCString() (Windows) */
    moduleFromRetval?: boolean;
    /** Optional callback invoked for each matched module (e.g., Windows lsass log) */
    onMatchExtra?: (moduleName: string) => void;
    /**
     * If true, also hook TLS libraries a dlopen() maps as DEPENDENCIES of the image
     * it names. The loader hook otherwise only sees the requested name: CPython's
     * dlopen(".../_ssl.cpython-3xx-darwin.so") pulls in libssl.3.dylib, which no
     * dlopen() call ever names, so in spawn mode it stayed unhooked (no keys, no
     * plaintext). New images come from Process.attachModuleObserver, so a dlopen()
     * costs no module enumeration (see newImageFeed).
     */
    hookDependencies?: boolean;
}

/**
 * Names of the modules in `loaded` that `known` has not seen yet — i.e. the images a
 * dlopen() just mapped — EXCLUDING the image the call itself requested, which the
 * loader hook handles under its requested name (hooking it again under its module
 * name would install every hook twice). `known` is updated in place.
 */
export function takeNewDependencyModules(
    known: Set<string>,
    loaded: ReadonlyArray<{ name: string; path: string }>,
    requested: string | undefined,
): string[] {
    const fresh: string[] = [];
    for (const module of loaded) {
        if (known.has(module.path)) continue;
        known.add(module.path);
        const isRequested = requested !== undefined && (
            requested === module.path || requested === module.name || requested.endsWith("/" + module.name)
        );
        if (!isRequested) fresh.push(module.name);
    }
    return fresh;
}

type LoadedImage = { name: string; path: string };

/**
 * Images mapped since the previous call (see DynamicLoaderConfig.hookDependencies).
 * Event-driven via Process.attachModuleObserver: onAdded only records the image
 * (hooking inside the loader's add notification would run before the image is
 * initialized); the dlopen() onLeave drains the list. Older Frida without the
 * observer falls back to a full Process.enumerateModules() per call.
 */
function newImageFeed(known: Set<string>): () => ReadonlyArray<LoadedImage> {
    const P: any = Process as any;
    if (typeof P.attachModuleObserver !== "function") {
        return () => Process.enumerateModules();
    }
    const added: LoadedImage[] = [];
    let attaching = true; // onAdded replays every already-loaded module during attach
    P.attachModuleObserver({
        onAdded(m: Module) { if (!attaching) added.push({ name: m.name, path: m.path }); },
        // An unloaded image must count as new again when a later dlopen() remaps it.
        onRemoved(m: Module) { known.delete(m.path); },
    });
    attaching = false;
    return () => added.splice(0, added.length);
}

/**
 * Hook a platform's dynamic loader to intercept library loads and apply registry hooks.
 *
 * Replaces the per-platform hook_<Platform>_Dynamic_Loader() functions with a single
 * configurable implementation.
 *
 * @param config       Platform-specific loader configuration
 * @param hookRegistry The HookRegistry singleton
 * @param moduleNames  Array of currently loaded module names
 * @param is_base_hook Whether this is a base hook or dynamic load
 * @param protocol     Active protocol filter (e.g., "tls", "ssh", "auto")
 */
export function hookDynamicLoader(
    config: DynamicLoaderConfig,
    hookRegistry: HookRegistry,
    moduleNames: Array<string>,
    is_base_hook: boolean,
    protocol?: RequestedProtocol
): void {
    // Primary label for the single-value string contexts (dedup key, tags); the
    // raw `protocol` selection still drives multi-protocol registry filtering.
    const protocolTag = protocolLabel(protocol);
    const dedupKey = `${config.platform}:${config.functionName}:${config.preferFunction ?? ""}:${protocolTag}`;
    if (_installedDynamicLoaders.has(dedupKey)) {
        devlog(`${config.platformLabel} dynamic loader already hooked for protocol=${protocolTag}; skipping duplicate Interceptor.attach.`);
        return;
    }
    try {
        let hookAddress: NativePointer;

        if (config.resolveViaApi) {
            // Windows-style: use ApiResolver to find the function
            const resolver: ApiResolver = new ApiResolver('module');
            const matches = resolver.enumerateMatches(config.resolveViaApi);
            if (matches.length === 0) {
                log(`[-] Missing ${config.platformLabel} dynamic loader!`);
                return;
            }
            hookAddress = matches[0].address;
        } else {
            // Unix-style: find the loader module, then get export
            const loaderRegex = config.loaderLibrary instanceof RegExp
                ? config.loaderLibrary
                : new RegExp(config.loaderLibrary);
            const loaderModule = moduleNames.find(element => element.match(loaderRegex));
            if (loaderModule === undefined) {
                throw `${config.platformLabel} Dynamic loader not found!`;
            }

            // Determine which function to hook (prefer alternative if available)
            let funcName = config.functionName;
            if (config.preferFunction) {
                const exports = Process.getModuleByName(loaderModule).enumerateExports();
                for (const ex of exports) {
                    if (ex.name === config.preferFunction) {
                        funcName = config.preferFunction;
                        break;
                    }
                }
            }

            hookAddress = Process.getModuleByName(loaderModule).getExportByName(funcName);
        }

        // Paths of every image seen so far (see hookDependencies). Paths, not names:
        // two images may share a basename.
        const knownImages: Set<string> | null = config.hookDependencies
            ? new Set(Process.enumerateModules().map(m => m.path))
            : null;
        const takeNewImages = knownImages !== null ? newImageFeed(knownImages) : null;

        Interceptor.attach(hookAddress, {
            onEnter: function (args) {
                if (!config.moduleFromRetval) {
                    this.moduleName = args[0].readCString();
                }
            },
            onLeave: function (retval: any) {
                if (takeNewImages !== null && !retval.isNull()) {
                    const dependencies = takeNewDependencyModules(knownImages!, takeNewImages(), this.moduleName ?? undefined);
                    if (dependencies.length > 0) {
                        // Same registry match / dedup / anti-tamper skip as the initial scan.
                        ssl_library_loader(config.platform, hookRegistry, dependencies, config.platformLabel, is_base_hook, protocol);
                    }
                }

                let moduleName: string | undefined;

                if (config.moduleFromRetval) {
                    // Windows: derive name from return value via ModuleMap
                    const map = new ModuleMap();
                    moduleName = map.findName(retval);
                    if (moduleName === null) return;
                } else {
                    // dlopen() spelling (possibly a symlink) → the mapped module's name.
                    moduleName = this.moduleName == undefined ? undefined : executorModuleName(this.moduleName);
                }

                if (moduleName != undefined) {
                    // Anti-tamper libraries (e.g. PairIP's libpairipcore.so)
                    // detect inline hooks and crash the process; warn the user
                    // and never hook/scan them.
                    if (warnAntiTamper(moduleName)) return;

                    // Optionally resolve module path for registry filtering
                    let modulePath: string | undefined;
                    if (config.extractModulePath) {
                        try {
                            const mod = Process.getModuleByName(moduleName);
                            modulePath = mod.path;
                        } catch (_) {
                            // Module not yet loaded, continue without path
                        }
                    }

                    if (isModuleHooked(moduleName, protocolTag)) {
                        devlog(`${moduleName} already hooked for ${protocolTag}, skipping (dynamic loader)`);
                        return;
                    }

                    // Lazy thunk: only enumerate modules when a candidate hook
                    // declares coveredBySibling — saves the per-dlopen cost on
                    // the common path where no coverage check applies.
                    const { matches, suppressed } = hookRegistry.findAllMatchesWithCoverage(
                        config.platform, moduleName, modulePath, getModuleNames, protocol,
                    );
                    for (const drop of suppressed) {
                        announceSiblingCoverage(drop.moduleName, drop.siblingName, drop.reason, protocolTag);
                    }
                    for (let match of matches) {
                        if (isRowHandled(match, moduleName, protocolTag)) {
                            devlog(`${moduleName}: ${match.library} already installed, skipping (dynamic loader)`);
                            continue;
                        }
                        try {
                            installHookRow(match, moduleName, is_base_hook, protocolTag, modulePath, `was loaded & will be hooked on ${config.platformLabel}`);
                        } catch (error_msg) {
                            devlog(`${config.platformLabel} dynamic loader error: ${error_msg}`);
                        }
                        if (config.onMatchExtra) {
                            config.onMatchExtra(moduleName);
                        }
                    }
                }
            }
        });

        _installedDynamicLoaders.add(dedupKey);
        log(`[*] ${config.platformLabel} dynamic loader hooked.`);
    } catch (error) {
        devlog("Dynamic loader error: " + error);
        log(`No dynamic loader present for hooking on ${config.platformLabel}.`);
    }
}

/**
 * EXPERIMENTAL — Part C of fkie-cad/friTap#64. A code-patch-free alternative to
 * {@link hookDynamicLoader}: instead of `Interceptor.attach`-ing an inline
 * trampoline onto `android_dlopen_ext` (which PairIP detects and SIGSEGVs on),
 * arm a hardware breakpoint on the loader entry (ARM64 debug registers, no byte
 * changes) and, on each call, rescan the live module list and hook any newly
 * loaded TLS library directly via {@link ssl_library_loader} (whose registry
 * dedup + anti-tamper skip we reuse). Hooking the app's own TLS lib is outside
 * PairIP's documented detection set, so this aims to enable spawn-mode capture
 * on protected apps without crashing them.
 *
 * Must be validated on-device (see friTap#64 experiment matrix); see
 * {@link watchFunctionEntries} for the per-thread / coverage caveats.
 *
 * @returns true if the hardware-breakpoint watcher was armed.
 */
export function installStealthDynamicLoader(
    config: DynamicLoaderConfig,
    hookRegistry: HookRegistry,
    getFreshModuleNames: () => Array<string>,
    protocol?: RequestedProtocol
): boolean {
    let loaderAddr: NativePointer;
    try {
        const loaderRegex = config.loaderLibrary instanceof RegExp
            ? config.loaderLibrary
            : new RegExp(config.loaderLibrary as string);
        const loaderModule = getFreshModuleNames().find(n => n.match(loaderRegex));
        if (loaderModule === undefined) {
            log(`[-] stealth loader: ${config.platformLabel} dynamic loader module not found`);
            return false;
        }
        let funcName = config.functionName;
        if (config.preferFunction) {
            for (const ex of Process.getModuleByName(loaderModule).enumerateExports()) {
                if (ex.name === config.preferFunction) { funcName = config.preferFunction; break; }
            }
        }
        loaderAddr = Process.getModuleByName(loaderModule).getExportByName(funcName);
    } catch (e) {
        log("[-] stealth loader: failed to resolve loader entry: " + e);
        return false;
    }

    // Coalesce bursts of dlopen calls into a single deferred rescan on the JS
    // thread (the breakpoint fires on the target's thread; do the hooking work
    // off the exception handler).
    let rescanScheduled = false;
    const armed = watchFunctionEntries(loaderAddr, () => {
        if (rescanScheduled) return;
        rescanScheduled = true;
        setTimeout(() => {
            rescanScheduled = false;
            try {
                ssl_library_loader(config.platform, hookRegistry, getFreshModuleNames(), config.platformLabel, false, protocol);
            } catch (e) { devlog("[stealth loader] rescan failed: " + e); }
        }, 0);
    });
    if (armed) log(`[*] ${config.platformLabel} stealth loader watch armed (hardware breakpoint, no linker patch).`);
    return armed;
}

export function getSocketLibrary(){
    var moduleNames: Array<String> = getModuleNames()
    switch(Process.platform){
        case "linux":
            return moduleNames.find(element => element.match(/libc.*\.so/))
        case "windows":
            return "WS2_32.dll"
        case "darwin":
            return "libSystem.B.dylib"
        default:
            log(`Platform "${Process.platform} currently not supported!`)
            return ""
    }
}

export function getModuleNames(){
    var moduleNames: Array<string> = []
    Process.enumerateModules().forEach(item => moduleNames.push(item.name))
    return moduleNames;
}

export function checkNumberOfExports(moduleName: string): number {
    try {
        // Get the module by name
        const module = Process.getModuleByName(moduleName);

        // Enumerate exports of the module
        const exports = module.enumerateExports();

        // Get the number of exports
        const numberOfExports = exports.length;

        // Log the result
        devlog(`The module "${moduleName}" has ${numberOfExports} exports.`);

        return numberOfExports;
    } catch (error) {
        devlog(`Error checking exports for module "${moduleName}": ${error}`);
        return -1;
    }
}

/**
 * Symbol-vs-pattern heuristic: a module exporting more than five symbols is treated as
 * symbolized (hook by name); fewer means stripped (hook by byte pattern). Shared by both
 * hook paths; agent/legacy/shared/shared_functions_legacy.ts keeps its own copy.
 */
export function hasMoreThanFiveExports(moduleName: string): boolean {
    return checkNumberOfExports(moduleName) > 5;
}

export function readAddresses(moduleName: string, library_method_mapping: { [key: string]: Array<string> }): { [library_name: string]: { [functionName: string]: NativePointer } } {
    const resolver = new ApiResolver("module");
    const addresses: { [library_name: string]: { [functionName: string]: NativePointer } } = {};

    addresses[moduleName] = {};

    // Symbols belonging to `moduleName` that exports couldn't resolve. When the
    // module opted into deep resolution (deep_symbol_resolution.ts) these are
    // retried against the general symbol table (.symtab) in a single
    // enumerateSymbols() pass AFTER the export loop — see below.
    const exportMissesForModule: string[] = [];

    for (const library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            const matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);
            let match_number = 0;
            let method_name = method.toString();

            if (method_name.endsWith("*")) { // this is for the temporary iOS bug using Frida's ApiResolver
                method_name = method_name.substring(0, method_name.length - 1);
            }
            
            if(!matches || matches === null){
                devlog(`Unable to retrieve any matches for statement: exports: ${library_name}!${method}`);
                return
            }

            if (matches.length == 0) {
                // Fallback: on macOS, symbols in umbrella libraries (libSystem.B.dylib)
                // are actually exported by sub-libraries (libsystem_kernel.dylib, etc.)
                // ApiResolver can't find them via the umbrella pattern, but
                // Module.findGlobalExportByName resolves them globally.
                try {
                    const globalAddr = Module.findGlobalExportByName(method_name);
                    if (globalAddr && !globalAddr.isNull()) {
                        devlog(`[readAddresses] Resolved ${method_name} via global export fallback: ${globalAddr}`);
                        addresses[moduleName][method_name] = globalAddr;
                        return;
                    }
                } catch (_) {
                    // findGlobalExportByName not available on older Frida versions
                }
                // Record the export miss so the symbol-table pass below can try
                // it — but only for symbols that live in `moduleName` itself
                // (socket-library symbols are real exports and resolve above).
                if (library_name.includes(moduleName)) {
                    exportMissesForModule.push(method_name);
                }
                devlog(`[readAddresses] Could not find ${library_name}!${method} (deferring to pipeline)`);
                return;
            } else if (matches.length == 1) {
                devlog("Found " + method + " " + matches[0].address);
            } else {
                // Sometimes Frida returns duplicates or it finds more than one result.
                for (let k = 0; k < matches.length; k++) {
                    if (matches[k].name.endsWith(method_name)) {
                        match_number = k;
                        devlog("Found " + method + " " + matches[match_number].address);
                        break;
                    }
                }
            }

            addresses[moduleName][method_name] = matches[match_number].address;
        });
    }

    // Exports-first, then symbol-table fallback (opt-in, per module). One
    // enumerateSymbols() pass fills only the entries that exports missed; it
    // never overwrites an export hit. This lets statically-linked BoringSSL
    // hosts (e.g. libhttpengine.so) that keep SSL_* in .symtab — not .dynsym —
    // still resolve SSL_new / SSL_CTX_set_keylog_callback, so the stealthier
    // heap-write keylog callback can install instead of the .text code patch.
    if (exportMissesForModule.length > 0 && isDeepSymbolResolutionEnabled(moduleName)) {
        const fromSymtab = findNonExportedSymbols(moduleName, exportMissesForModule);
        resetReadableCache();   // mapped ranges can have changed since any earlier walk
        for (const [name, addr] of fromSymtab) {
            // Range-check before recording: enumerateSymbols() can hand back addresses
            // that are not mapped (it reports undefined imports at 0x0, for instance),
            // and every address recorded here is later CALLED via NativeFunction — a
            // native fault that no JS try/catch can recover.
            if (addr && !addr.isNull() && isReadable(addr, 1)) {
                devlog(`[readAddresses] Resolved ${name} via symbol-table fallback: ${addr}`);
                addresses[moduleName][name] = addr;
            } else if (addr && !addr.isNull()) {
                devlog(`[readAddresses] Rejected ${name} from symbol-table fallback: ${addr} is not mapped`);
            }
        }
    }

    return addresses;
}






/**
 * Returns the base address of a given module
 * @param {string} moduleName Name of module to return base address from
 * @returns
 */
 export function getBaseAddress(moduleName: String): NativePointer | null {
    devlog("Module to find: "+moduleName);
    try {
        return Process.getModuleByName(moduleName as string).base;
    } catch (e) {
        return null;
    }
}


// Re-export the sockaddr decoders (imported at top) so existing importers of
// shared_functions.js (nss.ts, quiche.ts, google_quiche.ts) keep working unchanged.
export { decodeSockaddr, readSockaddrFamily };
export type { DecodedSockaddr, ByteOrderFns };


// Cache for NativeFunction wrappers (created once, reused per call)
let _cachedSocketFns: {
    getpeername: NativeFunction<number, [number, NativePointer, NativePointer]>;
    getsockname: NativeFunction<number, [number, NativePointer, NativePointer]>;
    ntohs: NativeFunction<number, [number]>;
    ntohl: NativeFunction<number, [number]>;
} | null = null;
let _cachedAddrBuf: NativePointer | null = null;
let _cachedAddrLenBuf: NativePointer | null = null;

// Armed once, lazily, on the first getPortsAndAddresses call. Evicting a blacklisted fd when
// it is close()d makes the blacklist self-healing: a reused fd number starts fresh instead of
// being permanently dropped. Lives here (not in the fd-recovery tracker) because EVERY caller
// of getPortsAndAddresses writes the blacklist, but only some install the tracker.
let _unwantedFdEvictionInstalled = false;
let _closedFdObserver: NativeSocketObserver | null = null;
function installUnwantedFdEviction(): void {
    if (_unwantedFdEvictionInstalled) return;
    _unwantedFdEvictionInstalled = true;
    const observer = nativeSocketObserver();
    if (observer !== null && observer.armClosedFdConsumer(CLOSED_FD_CONSUMER.unwantedFds)) {
        _closedFdObserver = observer;
        return;
    }
    const closeAddr = Module.findGlobalExportByName(fdCloseFunction());
    if (!closeAddr) return;
    Interceptor.attach(closeAddr, {
        onEnter(args) { unwantedFDs.delete(args[0].toInt32()); },
    });
}

/** Native observer: evict the fds closed since the last call; clear all when the ring overran. */
function evictClosedUnwantedFds(): void {
    if (_closedFdObserver === null) return;
    const closed = _closedFdObserver.drainClosedFds(CLOSED_FD_CONSUMER.unwantedFds);
    if (closed === "lost") unwantedFDs.clear();
    else for (const fd of closed) unwantedFDs.delete(fd);
}

/** --enable_default_fd: the loopback "local" (client) side of the placeholder tuple. */
export const DEFAULT_FD_LOCAL_PORT = 1234;
/** --enable_default_fd: the loopback "peer" (server) side of the placeholder tuple. */
export const DEFAULT_FD_PEER_PORT = 2345;
const DEFAULT_FD_LOOPBACK_ADDR = 0x7F000001;

/**
 * The --enable_default_fd placeholder 127.0.0.1:1234 <-> 127.0.0.1:2345, oriented like a real
 * peer lookup: a write goes local -> peer, a read peer -> local, so direction survives.
 */
export function defaultFdPlaceholderTuple(isRead: boolean): { [key: string]: string | number } {
    const localPort = DEFAULT_FD_LOCAL_PORT;
    const peerPort = DEFAULT_FD_PEER_PORT;
    return {
        src_port: isRead ? peerPort : localPort,
        src_addr: DEFAULT_FD_LOOPBACK_ADDR,
        dst_port: isRead ? localPort : peerPort,
        dst_addr: DEFAULT_FD_LOOPBACK_ADDR,
        ss_family: "AF_INET",
    };
}

/**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {int} sockfd The file descriptor of the socket to inspect.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port"; null when the fd is not usable (negative without enable_default_fd,
*     blacklisted, non-IP, or getsockname/getpeername failed — then the placeholder tuple
*     under enable_default_fd).
*/
/**
 * True when `fd` was marked as a non-IP socket (AF_UNIX etc.) by getPortsAndAddresses:
 * lets a caller tell "unwanted fd" (drop the record) from a failed lookup (null too).
 */
export function isUnwantedFd(fd: number): boolean {
    evictClosedUnwantedFds();
    return unwantedFDs.has(fd);
}

export function getPortsAndAddresses(sockfd: number, isRead: boolean, methodAddresses: { [key: string]: NativePointer }, enable_default_fd : boolean): { [key: string]: string | number } {

    if (!_unwantedFdEvictionInstalled) installUnwantedFdEviction();
    evictClosedUnwantedFds();

    var message: { [key: string]: string | number } = {}
    if (enable_default_fd && (sockfd < 0)){
        return defaultFdPlaceholderTuple(isRead)
    }
    // No socket: nothing to query. Never blacklisted (a negative fd is not a socket that
    // could ever be closed, so its unwantedFDs entry would never be evicted).
    if (sockfd < 0) {
        return null;
    }

    // Check if this fd is already marked as unwanted
    if (unwantedFDs.has(sockfd)) {
        return null; // Skip further processing
    }

    if (!_cachedSocketFns) {
        _cachedSocketFns = {
            getpeername: new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"]),
            getsockname: new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"]),
            ntohs: new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]),
            ntohl: new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]),
        };
        _cachedAddrLenBuf = Memory.alloc(4);
        _cachedAddrBuf = Memory.alloc(128);
    }
    var getpeername = _cachedSocketFns.getpeername;
    var getsockname = _cachedSocketFns.getsockname;
    var addrlen = _cachedAddrLenBuf;
    var addr = _cachedAddrBuf;
    var src_dst = ["src", "dst"]
    for (let i = 0; i < src_dst.length; i++) {
        addrlen.writeU32(128)
        const status = ((src_dst[i] == "src") !== isRead)
            ? getsockname(sockfd, addr, addrlen)
            : getpeername(sockfd, addr, addrlen)
        if (status !== 0) {
            // Closed, reused or not-yet-connected fd: `addr` still holds the PREVIOUS call's
            // sockaddr, so decoding it would stamp another connection's tuple on this record.
            // Not blacklisted: the failure may be transient (a socket not connected yet).
            return enable_default_fd ? defaultFdPlaceholderTuple(isRead) : null;
        }

        // Byte math by default; flip to `true` to route through the cached ntohs/ntohl.
        // addr is a real OS sockaddr from libc getpeername/getsockname — BSD layout on
        // darwin (sa_len@0, AF_INET6=30). bsdSockaddr=true is a no-op on Linux/Windows.
        const decoded = decodeSockaddr(addr, false, _cachedSocketFns, true);
        if (!decoded) {
            // only uncomment this if you really need to debug this
            //const familyName = AddressFamilyMapping[addr.readU16()] || `UNKNOWN`;
            //devlog("[-] getPortsAndAddresses resolving error: Only supporting IPv4/6");
            //devlog(`[-] Inspecting fd: ${sockfd}, Address family: ${addr.readU16()} (${familyName})`);
            unwantedFDs.add(sockfd); // Mark this fd as unwanted (auto-evicted when the fd is close()d; see installUnwantedFdEviction)
            return null;
        }
        message[src_dst[i] + "_port"] = decoded.port;
        message[src_dst[i] + "_addr"] = decoded.addr;
        message["ss_family"] = decoded.family;
    }

    return message
}



/**
 * Resolve offset-based addresses for both socket and library offsets.
 * Replaces the duplicated offset resolution block found in every SSL library constructor.
 *
 * @param addresses The addresses dictionary to populate (modified in place)
 * @param moduleName The module name key in the addresses dictionary
 * @param socket_library The socket library name (e.g., libc)
 * @param offsetKey The key in the offsets object for this library (e.g., "gnutls", "wolfssl", "openssl")
 */
export function resolveOffsets(
    addresses: { [key: string]: { [functionName: string]: NativePointer } },
    moduleName: string,
    socket_library: String,
    offsetKey: string
): void {
    // @ts-ignore
    if (offsets == "{OFFSETS}" || offsets[offsetKey] == null) {
        return;
    }

    if ((offsets as any).sockets != null) {
        const socketBaseAddress = getBaseAddress(socket_library);
        for (const method of Object.keys((offsets as any).sockets)) {
            const methodOffset = (offsets as any).sockets[method];
            const methodAddress = ptr(methodOffset.address);
            if (methodOffset.absolute || socketBaseAddress == null) {
                addresses[moduleName][method] = methodAddress;
            } else {
                addresses[moduleName][method] = socketBaseAddress.add(methodAddress);
            }
        }
    }

    const libraryBaseAddress = getBaseAddress(moduleName);
    if (libraryBaseAddress == null) {
        log("Unable to find library base address! Given address values will be interpreted as absolute ones!");
    }

    const libraryOffsets = (offsets as any)[offsetKey];
    for (const method of Object.keys(libraryOffsets)) {
        const methodOffset = libraryOffsets[method];
        const methodAddress = ptr(methodOffset.address);
        if (methodOffset.absolute || libraryBaseAddress == null) {
            addresses[moduleName][method] = methodAddress;
        } else {
            addresses[moduleName][method] = libraryBaseAddress.add(methodAddress);
        }
    }
}


/**
 * Convert a Java byte array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
export function byteArrayToString(byteArray: any) {
    return Array.from(byteArray, function (byte: number) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('')
}

// toHexString now lives in the side-effect-free util/hex module (so the scan
// engine and other pure callers can use it without importing this heavy module).
// Imported at the top and re-exported here so every existing caller — and this
// module's own format_key_for_wireshark below — keeps working unchanged.
export { toHexString };

/**
 * Convert a Java Reflection array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
export function reflectionByteArrayToString(byteArray: any) {
    var result = ""
    var arrayReflect = Java.use("java.lang.reflect.Array")
    for (var i = 0; i < arrayReflect.getLength(byteArray); i++) {
        result += ('0' + (arrayReflect.get(byteArray, i) & 0xFF).toString(16)).slice(-2);
    }
    return result
}

/**
 * Convert a Java byte arry to number (Big Endian)
 * @param byteArray The array to convert
 * @returns {number} The resulting number
 */
export function byteArrayToNumber(byteArray: any) {
    var value = 0;
    for (var i = 0; i < byteArray.length; i++) {
        value = (value * 256) + (byteArray[i] & 0xFF);
    }
    return value;
}
/**
 * Access an attribute of a Java Class
 * @param Instance The instace you want to access
 * @param fieldName The name of the attribute
 * @returns The value of the attribute of the requested field
 */
export function getAttribute(Instance: JavaWrapper, fieldName: string) {
    var clazz = Java.use("java.lang.Class")
    var field = Java.cast(Instance.getClass(), clazz).getDeclaredField(fieldName)
    field.setAccessible(true)
    return field.get(Instance)
}

/**
 * 
 * @param moduleName String of the name of the module e.g. libssl.so
 * @param symbolName the symbol where we do our check e.g. SSL_write_ex
 * @returns 
 */
export function isSymbolAvailable(moduleName: string, symbolName: string): boolean {
    const resolver = new ApiResolver("module");
    const matches = resolver.enumerateMatches("exports:" + moduleName + "!" + symbolName);
    //devlog(`Matches content: ${matches}`);

    if (matches && matches.length > 0) {
        return true;
    }

    // Exports-first, then symbol-table fallback (opt-in, per module). Mirrors
    // readAddresses: a module that opted into deep resolution may carry the
    // symbol only in .symtab, so the export check above misses it.
    if (isDeepSymbolResolutionEnabled(moduleName)) {
        return findNonExportedSymbol(moduleName, symbolName) !== null;
    }

    return false;
}


export function get_hex_string_from_byte_array(keyData: ArrayBuffer | Uint8Array): string{
    return toHexString(keyData).toUpperCase();
}


/**
 * Find a non-exported symbol in a module using Module.enumerateSymbols().
 * Useful for internal symbols (e.g., LibreSSL's tls1_PRF, tls13_hkdf_expand_label)
 * that are present in the symbol table but not in the export table.
 *
 * @param moduleName Name of the module to search
 * @param symbolName Exact symbol name to find
 * @returns The symbol's address, or null if not found
 */
export function findNonExportedSymbol(moduleName: string, symbolName: string): NativePointer | null {
    try {
        const mod = Process.getModuleByName(moduleName);
        const symbols = mod.enumerateSymbols().filter(s => s.name === symbolName);
        return symbols.length > 0 ? symbols[0].address : null;
    } catch (e) {
        devlog(`[findNonExportedSymbol] ${symbolName} in ${moduleName}: ${e}`);
        return null;
    }
}

/**
 * Symbol-name variants to try when matching against enumerateSymbols /
 * DebugSymbol results across platforms. Linux Itanium ABI mangling starts
 * with a single leading underscore (`_ZN...`); Mach-O prepends an extra one
 * (`__ZN...`). Frida normalizes these inconsistently across versions, so
 * lookups try [as-given, with-extra-underscore, without-leading-underscore].
 */
export function underscoreVariants(name: string): string[] {
    const variants = [name, "_" + name];
    if (name.length > 1 && name.startsWith("_")) variants.push(name.slice(1));
    return variants;
}

/**
 * Batch-find multiple non-exported symbols in a single Module.enumerateSymbols() pass.
 * Much more efficient than calling findNonExportedSymbol() repeatedly for the same module.
 *
 * Matching is underscore-tolerant via {@link underscoreVariants}: callers pass the
 * base symbol name (e.g. linux mangling `_ZN...`) and the function also matches
 * Mach-O-style `__ZN...` and the bare `ZN...` form. The result map is keyed by the
 * ORIGINAL input name regardless of which variant matched.
 *
 * @param moduleName Name of the module to search
 * @param symbolNames Array of exact symbol names to find
 * @returns Map of symbolName → address (only includes found symbols)
 */
export function findNonExportedSymbols(moduleName: string, symbolNames: string[]): Map<string, NativePointer> {
    const result = new Map<string, NativePointer>();
    const variantToInput = new Map<string, string>();
    for (const name of symbolNames) {
        for (const variant of underscoreVariants(name)) {
            if (!variantToInput.has(variant)) variantToInput.set(variant, name);
        }
    }
    try {
        const wanted = new Set(symbolNames);
        const mod = Process.getModuleByName(moduleName);
        for (const sym of mod.enumerateSymbols()) {
            const input = variantToInput.get(sym.name);
            if (input && wanted.has(input)) {
                result.set(input, sym.address);
                wanted.delete(input);
                if (wanted.size === 0) break;
            }
        }
    } catch (e) {
        devlog(`[findNonExportedSymbols] in ${moduleName}: ${e}`);
    }
    return result;
}

export function dumpMemory(ptrValue,size) {
    //var size = 0x100;
    try {
        devlog("[!] dumping memory at address: "+ptrValue);

        var data = ptrValue.readByteArray(size);
        devlog(hexdump(data));
        return data;
    } catch (error) {
        devlog("Error dumping memory at: " + ptrValue + " - " + error);
        return null;
    }
}

export function calculateZeroBytePercentage(hexStr: string): number {
    if (hexStr.length % 2 !== 0) {
        devlog_error("Hex string length must be even.");
        return -1; // Invalid hex string
    }

    const totalBytes = hexStr.length / 2;
    let zeroCount = 0;

    for (let i = 0; i < hexStr.length; i += 2) {
        if (hexStr.substring(i, i + 2) === "00") {
            zeroCount++;
        }
    }

    return Math.round((zeroCount / totalBytes) * 100);
}

/** One named hook-installation step for runInstallPhases(). */
export interface InstallPhase {
    label: string;
    fn: () => void;
}

/**
 * Run hook-installation phases with per-phase containment and a setTimeout(0)
 * yield between them.
 *
 * Three properties, each learned the hard way:
 *  - CONTAINMENT: a phase that throws is logged and skipped, so one failing
 *    library cannot cost the user every later hook (previously a single throw
 *    inside load_*_hooking_agent() abandoned the rest of the install).
 *  - ATTRIBUTION: a breadcrumb is emitted before each phase, so when the target
 *    dies NATIVELY — no JS exception for Frida to report — the host's crash
 *    message can still name the phase (fkie-cad/friTap#65).
 *  - YIELDING: each yield releases the Frida runtime so the target's own threads
 *    make progress between bursts of Interceptor.attach work, which is what keeps
 *    an attach to a busy process from stalling it.
 *
 * `runFirstSync` keeps phase 0 inside script.load(), so the base TLS hooks are
 * live before the host resumes a spawned process. Pass false to dispatch every
 * phase on a later tick (the pre-existing Android/Linux behaviour).
 */
export function runInstallPhases(platformLabel: string, phases: InstallPhase[], runFirstSync: boolean = true): void {
    const run = (i: number) => {
        if (i >= phases.length) return;
        hookBreadcrumb(`install-phase: ${platformLabel}/${phases[i].label}`);
        try {
            phases[i].fn();
        } catch (e) {
            devlog(`[${platformLabel}] install phase ${phases[i].label} threw: ${e}`);
        }
        setTimeout(() => run(i + 1), 0);
    };
    if (runFirstSync) {
        run(0);
    } else {
        setTimeout(() => run(0), 0);
    }
}
