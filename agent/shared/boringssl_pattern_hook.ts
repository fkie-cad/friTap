// agent/shared/boringssl_pattern_hook.ts
//
// Thin wrapper so the chain doesn't depend on PatternBasedHooking directly.
// Memory.scan is asynchronous, so `scheduled: true` does NOT mean keys have
// been captured — PatternBasedHooking emits its own devlog when a pattern
// actually matches.

import { PatternBasedHooking } from "../tls/shared/pattern_based_hooking.js";
import { DumpKeysCb } from "./boringssl_symbol_hook.js";
import { lenArg } from "./keylog_length.js";
import { devlog_debug, devlog_error } from "../util/log.js";

export interface PatternHookResult {
    scheduled: boolean;
    reason: string;
}

export function installBoringSSLPatternHook(
    moduleName: string,
    patternsJson: string | undefined,
    dumpKeys: DumpKeysCb,
    fallbackJsonName: string = "libcronet.so",
): PatternHookResult {
    if (!patternsJson || patternsJson.length === 0) {
        return { scheduled: false, reason: "no patterns configured" };
    }

    let mod: Module | null = null;
    try {
        mod = Process.findModuleByName(moduleName);
    } catch (e) {
        return { scheduled: false, reason: `Process.findModuleByName threw: ${e}` };
    }
    if (!mod) {
        return { scheduled: false, reason: `module not loaded: ${moduleName}` };
    }

    try {
        const hooker = new PatternBasedHooking(mod);
        hooker.hook_DumpKeys(
            moduleName,
            fallbackJsonName,
            patternsJson,
            (args: any[]) => {
                // ssl_log_secret(SSL*, label, secret.data, secret.size)
                dumpKeys(args[1], args[0], args[2], lenArg(args[3]) ?? 0);
            },
        );
        devlog_debug(`[bssl-pattern] ${moduleName}: hook_DumpKeys scheduled (Memory.scan async)`);
        return { scheduled: true, reason: "scan-scheduled" };
    } catch (e) {
        devlog_error(`[bssl-pattern] ${moduleName}: hook_DumpKeys threw: ${e}`);
        return { scheduled: false, reason: `hook_DumpKeys threw: ${e}` };
    }
}
