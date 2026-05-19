// agent/core/loader.ts
//
// Dispatcher that consumes a HookDefinition and installs all hooks.

import { HookDefinition, ResolvedFunctions } from "./hook_definition.js";
import { readAddresses, resolveOffsets } from "../shared/shared_functions.js";
import { installReadHook, installWriteHook } from "./executors/read_write.js";
import { installKeylogHook } from "./executors/keylog_callback.js";
import { installBoringSSLKeylogChain } from "../shared/boringssl_hook_chain.js";
import { patterns } from "../fritap_agent.js";
import { devlog, log } from "../util/log.js";

/**
 * Execute a data-driven hook definition:
 * 1. Build library_method_mapping from def.functions
 * 2. Resolve addresses via readAddresses() + resolveOffsets()
 * 3. Create NativeFunction wrappers from def.nativeFunctions
 * 4. Install read/write hooks via generic executors
 * 5. Dispatch keylog hook based on def.keylog.kind
 * 6. Run extraHooks if present
 */
export function executeFromDefinition(
    def: HookDefinition,
    moduleName: string,
    socketLibrary: string,
    isBaseHook: boolean,
    enableDefaultFd: boolean,
): void {
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
    if (def.libraryType === "boringssl") {
        try {
            installBoringSSLKeylogChain(def, addresses, moduleName, resolvedFns, enableDefaultFd, patterns);
        } catch (e) {
            devlog(`[loader] BoringSSL chain threw for ${moduleName}: ${e}`);
        }
    } else {
        try {
            const installed = installKeylogHook(def, addresses, moduleName, resolvedFns, enableDefaultFd);
            // Per-library install banner for non-BoringSSL paths. The "custom"
            // kind (rustls, s2ntls, libressl, NSS, gotls) emits its own banner
            // inside the install closure where it has richer context — skip
            // here to avoid duplicates. The keylog dispatcher itself returns
            // true/false based on whether at least one Interceptor.attach
            // reached, which is the right signal for the banner.
            if (installed && def.keylog.kind !== "custom" && def.keylog.kind !== "none") {
                log(`[*] ${moduleName}: keylog hooks installed via callback (${def.keylog.kind})`);
            }
        } catch (e) {
            devlog(`[loader] primary keylog install threw on ${moduleName}: ${e}`);
        }
    }

    // 7. Run extra hooks
    if (def.extraHooks) {
        for (const extra of def.extraHooks) {
            extra.install(addresses, moduleName, resolvedFns, enableDefaultFd);
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
}
