// agent/core/loader.ts
//
// Dispatcher that consumes a HookDefinition and installs all hooks.

import { HookDefinition, ResolvedFunctions } from "./hook_definition.js";
import { readAddresses, resolveOffsets } from "../shared/shared_functions.js";
import { resolveWithPipelineAsync } from "../shared/pipeline_utils.js";
import { installReadHook, installWriteHook } from "./executors/read_write.js";
import { installKeylogHook } from "./executors/keylog_callback.js";
import { installBoringSSLKeylogChain } from "../shared/boringssl_hook_chain.js";
import { patterns, keylog_enabled } from "../fritap_agent.js";
import { devlog, log } from "../util/log.js";
import { activeRecordProtocol, runHookExecutor } from "../shared/record_protocol.js";

/**
 * Execute a data-driven hook definition:
 * 1. Build library_method_mapping from def.functions
 * 2. Resolve addresses via readAddresses() + resolveOffsets()
 * 3. Create NativeFunction wrappers from def.nativeFunctions
 * 4. Install read/write hooks via generic executors
 * 5. Dispatch keylog hook based on def.keylog.kind
 * 6. Run extraHooks if present
 *
 * Resolves to the row's installed verdict (ModuleHookingType): `true` when an extra
 * hook installed something or the definition has hooks of its own, where a "custom"
 * keylog counts only once its (sync or async) install reports success; `false` for a
 * definition whose only hooks (extraHooks, custom keylog) all installed nothing.
 */
export async function executeFromDefinition(
    def: HookDefinition,
    moduleName: string,
    socketLibrary: string,
    isBaseHook: boolean,
    enableDefaultFd: boolean,
): Promise<boolean> {
    // The row's record protocol is bound only while the executor runs synchronously
    // (record_protocol.ts); capture it here and re-bind it for the hooks installed
    // after the pipeline await below, or under --protocol auto/all every SSH/IPsec/QUIC
    // record of a definition-driven lib would fall back to "tls".
    const recordProtocol = activeRecordProtocol();
    // 1. Build library_method_mapping
    const mapping: { [key: string]: string[] } = {};
    mapping[`*${moduleName}*`] = def.functions.librarySymbols;
    mapping[`*${socketLibrary}*`] = def.functions.socketSymbols;
    if (def.functions.auxiliaryLibraries) {
        for (const aux of def.functions.auxiliaryLibraries) {
            mapping[aux.pattern] = aux.symbols;
        }
    }

    // 2. Resolve addresses
    const addresses = readAddresses(moduleName, mapping);
    resolveOffsets(addresses, moduleName, socketLibrary, def.offsetKey);

    // 2b. Pre-resolution hook for non-standard symbols (e.g. Go embedded
    //     package paths). Merges resolved pointers into addresses[moduleName]
    //     before NativeFunction wrapping. No-op when symbolResolver is unset.
    if (def.symbolResolver) {
        const preResolved = def.symbolResolver(moduleName);
        for (const sym of Object.keys(preResolved)) {
            const addr = preResolved[sym];
            if (addr && !addr.isNull()) {
                addresses[moduleName] = addresses[moduleName] || {};
                if (!addresses[moduleName][sym] || addresses[moduleName][sym].isNull()) {
                    addresses[moduleName][sym] = addr;
                }
            }
        }
    }

    // 2c. Fill symbols still missing after exports/offsets via the hooking
    //     pipeline (user --patterns byte-scan). resolveWithPipelineAsync only
    //     fills missing/null entries and never overwrites, so existing
    //     resolution is untouched. No-op when no pattern data was supplied
    //     (only the symbol strategy is registered, which already failed above).
    const pipelineSymbols = [
        ...def.functions.librarySymbols,
        ...def.nativeFunctions.map(spec => spec.symbol),
    ];
    await resolveWithPipelineAsync(addresses, moduleName, def.offsetKey, pipelineSymbols);

    const install = () => installResolvedDefinition(def, addresses, moduleName, isBaseHook, enableDefaultFd);
    if (recordProtocol === undefined) return install();
    return runHookExecutor(recordProtocol, install);
}

/** Whether the definition has hooks of its own whose verdict does not wait on a custom keylog install. */
function hasUnconditionalOwnHooks(def: HookDefinition): boolean {
    return !!def.readHook || !!def.writeHook || (def.keylog.kind !== "custom" && def.keylog.kind !== "none");
}

/**
 * Run a "custom" keylog installer (it may be async: NSS, Fizz) and settle its verdict:
 * a throw or a rejection counts as nothing installed.
 */
async function settleCustomKeylog(
    keylog: Extract<HookDefinition["keylog"], { kind: "custom" }>,
    addresses: { [lib: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
): Promise<boolean> {
    try {
        const installed = await keylog.install(addresses, moduleName, resolvedFns, enableDefaultFd);
        devlog(installed
            ? `[*] ${moduleName}: custom keylog install settled: installed`
            : `[-] ${moduleName}: custom keylog install settled: nothing installed`);
        return installed === true;
    } catch (e) {
        devlog(`[loader] custom keylog install failed on ${moduleName}: ${e}`);
        return false;
    }
}

/**
 * Steps 3-8: wrap NativeFunctions and attach every hook of a resolved definition.
 * Returns the installed verdict documented on executeFromDefinition.
 */
function installResolvedDefinition(
    def: HookDefinition,
    addresses: { [lib: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    isBaseHook: boolean,
    enableDefaultFd: boolean,
): Promise<boolean> {
    // 3. Create NativeFunction wrappers
    const resolvedFns: ResolvedFunctions = {};
    for (const spec of def.nativeFunctions) {
        let addr: NativePointer | undefined;
        // First try the main module
        addr = addresses[moduleName]?.[spec.symbol];
        // Then search all address maps
        if (!addr || addr.isNull()) {
            for (const key of Object.keys(addresses)) {
                const candidate = addresses[key]?.[spec.symbol];
                if (candidate && !candidate.isNull()) {
                    addr = candidate;
                    break;
                }
            }
        }
        if (addr && !addr.isNull()) {
            resolvedFns[spec.symbol] = new NativeFunction(
                addr,
                spec.retType as any,
                spec.argTypes as any[],
            );
        } else {
            devlog(`[loader] Could not resolve ${spec.symbol} for ${def.libraryId}`);
        }
    }

    // 4. Notify definition that NativeFunctions are ready
    if (def.onNativeFunctionsResolved) {
        def.onNativeFunctionsResolved(resolvedFns);
    }

    // 5. Install read/write hooks
    installReadHook(def, addresses, moduleName, resolvedFns, enableDefaultFd);
    installWriteHook(def, addresses, moduleName, resolvedFns, enableDefaultFd);

    // 6. Install keylog hook.
    //    BoringSSL libs run the three-tier chain in agent/shared/boringssl_hook_chain.ts:
    //      tier 1 (default): SSL_CTX_set_keylog_callback
    //      tier 2:           bssl::ssl_log_secret symbol
    //      tier 3:           pattern.json byte-pattern scan
    //    def.keylogPriority swaps tiers 1 and 2 (Cronet-derived libs set
    //    "symbol-first" because they bypass SSL_new internally). Tier 3 is
    //    always last. Non-BoringSSL defs use the single-shot dispatcher.
    //
    //    Symmetric counterpart to the pcap_enabled gate: this single install-time
    //    gate skips the whole keylog install (callback/symbol/pattern) for every
    //    data-driven lib when keys aren't wanted (BoringSSL self-gates too).
    //    A "custom" installer (rustls, s2ntls, libressl, NSS, gotls, Fizz) emits its
    //    own banner; it is started here and its verdict joins the row's below.
    let customKeylog: Promise<boolean> = Promise.resolve(false);
    if (!keylog_enabled) {
        devlog(`[loader] ${moduleName}: keylog install skipped (keylog_enabled=false)`);
    } else if (def.libraryType === "boringssl") {
        try {
            installBoringSSLKeylogChain(def, addresses, moduleName, resolvedFns, enableDefaultFd, patterns);
        } catch (e) {
            devlog(`[loader] BoringSSL chain threw for ${moduleName}: ${e}`);
        }
    } else if (def.keylog.kind === "custom") {
        customKeylog = settleCustomKeylog(def.keylog, addresses, moduleName, resolvedFns, enableDefaultFd);
    } else {
        try {
            const installed = installKeylogHook(def, addresses, moduleName, resolvedFns, enableDefaultFd);
            // Per-library install banner for non-BoringSSL paths. The keylog
            // dispatcher returns true/false based on whether at least one
            // Interceptor.attach reached, which is the right signal for the banner.
            if (installed && def.keylog.kind !== "none") {
                log(`[*] ${moduleName}: keylog hooks installed via callback (${def.keylog.kind})`);
            }
        } catch (e) {
            devlog(`[loader] primary keylog install threw on ${moduleName}: ${e}`);
        }
    }

    // 7. Run extra hooks
    let extraInstalled = false;
    if (def.extraHooks) {
        for (const extra of def.extraHooks) {
            extraInstalled = extra.install(addresses, moduleName, resolvedFns, enableDefaultFd) !== false || extraInstalled;
        }
    }

    // 8. Store init_addresses for base hooks
    if (isBaseHook) {
        try {
            const initAddresses = addresses[moduleName];
            if (initAddresses && Object.keys(initAddresses).length > 0) {
                (globalThis as any).init_addresses[moduleName] = initAddresses;
            }
        } catch (e) {
            devlog(`[loader] base-hook address store error: ${e}`);
        }
    }
    // The custom keylog decides the verdict only when nothing else installed.
    return extraInstalled || hasUnconditionalOwnHooks(def) ? Promise.resolve(true) : customKeylog;
}
