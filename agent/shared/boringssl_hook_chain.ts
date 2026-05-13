// agent/shared/boringssl_hook_chain.ts
//
// Three-tier keylog install chain for libraryType: "boringssl" definitions.
// Tier 1 (default): SSL_CTX_set_keylog_callback. Tier 2: bssl::ssl_log_secret
// symbol. Tier 3: pattern.json byte-pattern scan. def.keylogPriority swaps
// tier 1 and tier 2; tier 3 is always last.
//
// "Failure" is STATIC (symbol unresolved, Interceptor.attach threw), not
// runtime (zero keys captured). Cronet-derived libs that bypass SSL_new
// internally must set keylogPriority="symbol-first" — otherwise tier 1
// installs cleanly but never fires.

import { HookDefinition, ResolvedFunctions } from "../core/hook_definition.js";
import { installKeylogHook } from "../core/executors/keylog_callback.js";
import { installBoringSSLSymbolHook, boringSslDumpKeys } from "./boringssl_symbol_hook.js";
import { installBoringSSLPatternHook } from "./boringssl_pattern_hook.js";
import { devlog, devlog_debug, devlog_error } from "../util/log.js";

export type BoringSSLHookOutcome = "callback" | "symbol" | "pattern" | "none";

type Tier12 = "callback" | "symbol";

function runTier(name: string, moduleName: string, fn: () => boolean): boolean {
    try {
        const ok = fn();
        devlog_debug(`[bssl-chain] ${moduleName}: tier=${name} ${ok ? "installed" : "skipped"}`);
        return ok;
    } catch (e) {
        devlog_error(`[bssl-chain] ${moduleName}: tier=${name} threw: ${e}`);
        return false;
    }
}

export function installBoringSSLKeylogChain(
    def: HookDefinition,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
    patternsJson?: string,
): BoringSSLHookOutcome {
    const priority = def.keylogPriority ?? "callback-first";
    const order: Tier12[] = priority === "symbol-first"
        ? ["symbol", "callback"]
        : ["callback", "symbol"];

    devlog_debug(`[bssl-chain] ${moduleName}: priority=${priority} order=${order.join(",")}`);

    for (const tier of order) {
        const ok = tier === "callback"
            ? runTier("callback", moduleName,
                () => installKeylogHook(def, addresses, moduleName, resolvedFns, enableDefaultFd))
            : runTier("symbol", moduleName,
                () => installBoringSSLSymbolHook(moduleName, boringSslDumpKeys));
        if (ok) return tier;
    }

    const patternOk = runTier("pattern", moduleName, () => {
        const r = installBoringSSLPatternHook(moduleName, patternsJson, boringSslDumpKeys);
        if (!r.scheduled) {
            devlog_debug(`[bssl-chain] ${moduleName}: tier=pattern reason=${r.reason}`);
        }
        return r.scheduled;
    });
    if (patternOk) return "pattern";

    devlog(`[bssl-chain] ${moduleName}: all tiers failed — no keylog installed`);
    return "none";
}
