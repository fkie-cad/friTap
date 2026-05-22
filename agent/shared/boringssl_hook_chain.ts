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
import { installBoringSSLSymbolHook, makeBoringSslDumpKeys, attemptSymbolFallback, KEYLOG_NOT_INSTALLED_MSG } from "./boringssl_symbol_hook.js";
import { installBoringSSLPatternHook } from "./boringssl_pattern_hook.js";
import { detectBoringSSLFamily } from "./boringssl_family_detect.js";
import { devlog, devlog_debug, devlog_error, log } from "../util/log.js";
import { keylog_enabled } from "../fritap_agent.js";

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
    // Skip key extraction entirely in plaintext-only mode — saves the pattern-scan cost.
    if (!keylog_enabled) {
        devlog_debug(`[bssl-chain] ${moduleName}: skipped (keylog_enabled=false)`);
        return "none";
    }

    const priority = def.keylogPriority ?? "callback-first";
    const order: Tier12[] = priority === "symbol-first"
        ? ["symbol", "callback"]
        : ["callback", "symbol"];

    devlog_debug(`[bssl-chain] ${moduleName}: priority=${priority} order=${order.join(",")}`);

    const dumpKeysCb = makeBoringSslDumpKeys(moduleName);

    for (const tier of order) {
        const ok = tier === "callback"
            ? runTier("callback", moduleName,
                () => installKeylogHook(def, addresses, moduleName, resolvedFns, enableDefaultFd))
            : runTier("symbol", moduleName,
                () => installBoringSSLSymbolHook(moduleName, dumpKeysCb));
        if (ok) {
            // The symbol tier self-announces in installBoringSSLSymbolHook; the
            // callback sub-installers (agent/core/executors/keylog_callback.ts)
            // do not, so emit a chain-level banner here for callback success.
            // `def.keylog.kind` is callback_on_init / callback_on_ssl_new /
            // manual_on_connect / custom / none — enough to tell the user
            // which strategy actually ran.
            if (tier === "callback") {
                log(`[*] ${moduleName}: keylog hooks installed via callback (${def.keylog.kind})`);
            }
            return tier;
        }
    }

    // Tier 3: byte-pattern scan with a 4-sub-tier cascade
    //   3a — pattern.json exact module key
    //   3b — pattern.json family alias keys
    //   3c — bundled per-family patterns (agent/shared/bundled_cronet_patterns.ts)
    //   3d — bundled openssl.<arch>.ssl_log_secret[] floor
    // The async settled promise lets us retry via the symbol resolver if every
    // sub-tier exhausts — the counterpart of scheduleBoringSSLSymbolFallback
    // in the legacy executor.
    const family = def.family ?? detectBoringSSLFamily(moduleName);
    const libraryType = def.libraryType ?? "boringssl";
    const patternResult = installBoringSSLPatternHook(
        moduleName,
        patternsJson,
        dumpKeysCb,
        "libcronet.so",
        { family, libraryType },
    );
    if (!patternResult.scheduled) {
        devlog_debug(`[bssl-chain] ${moduleName}: tier=pattern reason=${patternResult.reason}`);
        devlog(KEYLOG_NOT_INSTALLED_MSG(moduleName, `tier 3 not scheduled (${patternResult.reason})`));
        return "none";
    }

    patternResult.settled.then((matched) => {
        if (matched) {
            devlog_debug(`[bssl-chain] ${moduleName}: pattern tier matched (family=${family})`);
            return;
        }
        devlog(
            `[bssl-chain] ${moduleName}: tier 3 exhausted (family=${family}); falling back to symbol re-scan`,
        );
        attemptSymbolFallback(moduleName, dumpKeysCb, "bssl-chain");
    }).catch((e) => {
        devlog_error(`[bssl-chain] ${moduleName}: settled-promise rejected: ${e}`);
    });

    return "pattern";
}
