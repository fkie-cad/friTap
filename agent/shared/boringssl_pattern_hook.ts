// Thin wrapper around PatternBasedHooking that surfaces the true async outcome
// via `settled: Promise<boolean>`. The chain attaches a `.then` to retry via
// the symbol resolver when every pattern variant exhausts without a match.

import { PatternBasedHooking } from "../tls/shared/pattern_based_hooking.js";
import { DumpKeysCb } from "./boringssl_symbol_hook.js";
import { lenArg } from "./keylog_length.js";
import { devlog_debug, devlog_error } from "../util/log.js";

export interface PatternHookResult {
    scheduled: boolean;
    reason: string;
    /** Resolves true iff any pattern variant matched; false on exhaustion or timeout. */
    settled: Promise<boolean>;
}

// Exceeds the legacy PATTERN_HOOKING_SETTLE_MS=1000 so a slow scan still
// completes before we declare failure.
const POLL_INTERVAL_MS = 100;
const POLL_TIMEOUT_MS = 1500;
const POLL_GRACE_MS = 200;

export function installBoringSSLPatternHook(
    moduleName: string,
    patternsJson: string | undefined,
    dumpKeys: DumpKeysCb,
    fallbackJsonName: string = "libcronet.so",
): PatternHookResult {
    if (!patternsJson || patternsJson.length === 0) {
        return notScheduled("no patterns configured");
    }

    let mod: Module | null = null;
    try {
        mod = Process.findModuleByName(moduleName);
    } catch (e) {
        return notScheduled(`Process.findModuleByName threw: ${e}`);
    }
    if (!mod) {
        return notScheduled(`module not loaded: ${moduleName}`);
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
        return { scheduled: true, reason: "scan-scheduled", settled: pollPatternOutcome(hooker, moduleName) };
    } catch (e) {
        devlog_error(`[bssl-pattern] ${moduleName}: hook_DumpKeys threw: ${e}`);
        return notScheduled(`hook_DumpKeys threw: ${e}`);
    }
}

function notScheduled(reason: string): PatternHookResult {
    return { scheduled: false, reason, settled: Promise.resolve(false) };
}

// `no_hooking_success` starts at true and only flips to false on a match, so
// the grace window prevents a false "exhausted" verdict on the first tick.
function pollPatternOutcome(hooker: PatternBasedHooking, moduleName: string): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
        const t0 = Date.now();
        let done = false;
        const finish = (matched: boolean) => {
            if (done) return;
            done = true;
            resolve(matched);
        };

        const tick = (): void => {
            if (done) return;

            if (hooker.found_ssl_log_secret) {
                devlog_debug(`[bssl-pattern] ${moduleName}: pattern match detected`);
                finish(true);
                return;
            }

            const elapsed = Date.now() - t0;
            if (elapsed >= POLL_TIMEOUT_MS) {
                devlog_debug(`[bssl-pattern] ${moduleName}: poll timeout after ${elapsed}ms`);
                finish(false);
                return;
            }

            if (elapsed >= POLL_GRACE_MS && hooker.no_hooking_success && !hooker.found_ssl_log_secret) {
                devlog_debug(`[bssl-pattern] ${moduleName}: cascade exhausted at ${elapsed}ms`);
                finish(false);
                return;
            }

            setTimeout(tick, POLL_INTERVAL_MS);
        };

        setTimeout(tick, POLL_INTERVAL_MS);
    });
}
