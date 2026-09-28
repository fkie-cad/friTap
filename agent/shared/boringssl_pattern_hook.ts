// Thin wrapper around PatternBasedHooking that resolves the best available
// pattern source UP-FRONT (synchronously) and fires a SINGLE asynchronous
// Memory.scan cascade — mirroring the legacy Cronet executor at
// agent/legacy/tls/platforms/android/cronet_android.ts:82-113.
//
// Resolution priority (first hit wins, then we stop):
//   3a — pattern.json: exact module-name key
//   3b — pattern.json: ordered family alias keys
//        (e.g. monochrome → ["libmainlinecronet.so", "libcronet.so"])
//   3c — bundled per-family hardcoded patterns
//        (agent/shared/bundled_cronet_patterns.ts)
//   3d — bundled openssl.<arch>.ssl_log_secret[] (the widest BoringSSL net)
//
// CRITICAL: We deliberately DO NOT fan out parallel scans. An earlier draft
// ran each tier as its own PatternBasedHooking and polled for outcome with a
// 1500 ms timeout; on a ~200 MB monolith like libmonochrome_64.so the polling
// resolved false long before Frida's Memory.scan finished, and the next tier
// kicked off ANOTHER concurrent scan with the same module range. The result
// was 2–3 simultaneous Memory.scan operations competing for Frida's scanner
// (and each PatternBasedHooking having its own `rescannedRanges` Set, so the
// same memory ranges got re-scanned over and over). Legacy works because it
// runs ONE scan, lets it finish, and the eventual second_fallback match
// installs the hook. We do the same here.

import { PatternBasedHooking } from "../tls/shared/pattern_based_hooking.js";
// Type-only: boringssl_symbol_hook.ts imports pollPatternOutcome from here,
// so a value import would form a runtime cycle.
import type { DumpKeysCb } from "./boringssl_symbol_hook.js";
import { lenArg } from "./keylog_length.js";
import {
    ArchKey,
    ArchPatterns,
    BUNDLED_OPENSSL_SSL_LOG_SECRET,
    FamilyKey,
    currentArchKey,
    getBundledPatterns,
} from "./bundled_cronet_patterns.js";
import { detectBoringSSLFamily, familyAliases } from "./boringssl_family_detect.js";
import { guardKeylogDumpKeys } from "./boringssl_keylog_outcome.js";
import { devlog, devlog_debug, devlog_error, _isShuttingDownNow } from "../util/log.js";

export interface PatternHookResult {
    scheduled: boolean;
    reason: string;
    /**
     * Resolves true iff the (single) pattern cascade matched; false once it
     * completed without a match, or is still unmatched at the poll's hard bound
     * (see pollPatternOutcome — the soft timeout alone never resolves it).
     */
    settled: Promise<boolean>;
}

export interface InstallPatternHookOpts {
    /**
     * Library family marker (see agent/shared/bundled_cronet_patterns.ts).
     * When omitted, derived from `moduleName` via detectBoringSSLFamily().
     */
    family?: FamilyKey;
    /**
     * Used by the 3d fallback to pick the bundled libraryType-level patterns
     * (currently only "boringssl" / "openssl" are wired; other values opt
     * the tier out gracefully).
     */
    libraryType?: string;
}

const POLL_INTERVAL_MS = 100;
// libmonochrome_64.so is ~200 MB; Frida's Memory.scan onError fallback enumerates
// every readable range and runs primary/fallback/second_fallback in series — the
// full cascade comfortably exceeds 5 s on cold caches.
//
// POLL_SOFT_TIMEOUT_MS is NOT a verdict: a scan still running at that point is
// reported as "still scanning" and the poll keeps waiting (with backoff) for the
// real outcome. Declaring a total miss there started tier 4 while the original
// scan was still running; a later match then hooked ssl_log_secret a second time
// next to a stale "[!] no BoringSSL keylog hook" warning.
const POLL_SOFT_TIMEOUT_MS = 10000;
// The only point where an unfinished scan is given up on. Also the bound for the
// LEGACY PatternBasedHooking, which has no `cascadeCompleted` flag and so can
// only settle via a match or this bound. A match after it is still deduplicated
// by the per-module ownership guard (boringssl_keylog_outcome.ts).
const POLL_HARD_TIMEOUT_MS = 120000;
const POLL_MAX_INTERVAL_MS = 2000;
const POLL_GRACE_MS = 200;

type ResolvedPatternSource =
    | { kind: "json"; via: string; jsonKey: string }
    | { kind: "bundled"; via: string; patterns: ArchPatterns };

export function installBoringSSLPatternHook(
    moduleName: string,
    patternsJson: string | undefined,
    dumpKeys: DumpKeysCb,
    fallbackJsonName: string = "libcronet.so",
    opts: InstallPatternHookOpts = {},
): PatternHookResult {
    let mod: Module | null = null;
    try {
        mod = Process.findModuleByName(moduleName);
    } catch (e) {
        return notScheduled(`Process.findModuleByName threw: ${e}`);
    }
    if (!mod) {
        return notScheduled(`module not loaded: ${moduleName}`);
    }

    const family: FamilyKey = opts.family ?? detectBoringSSLFamily(moduleName);
    const arch = currentArchKey();
    const libraryType = opts.libraryType ?? "boringssl";

    // Pre-parse the patterns JSON once so the source resolver can answer
    // existence questions without re-parsing on every probe.
    let parsed: any = null;
    if (patternsJson && patternsJson.length > 0) {
        try {
            parsed = JSON.parse(patternsJson);
        } catch (e) {
            devlog_debug(`[bssl-pattern] ${moduleName}: patterns JSON parse failed: ${e}`);
        }
    }

    const source = resolveBestSource({
        parsed,
        moduleName,
        family,
        arch,
        libraryType,
        fallbackJsonName,
    });
    if (!source) {
        return notScheduled(`no pattern source available (family=${family} arch=${arch})`);
    }

    devlog(`[bssl-pattern] ${moduleName}: pattern source=${source.via} family=${family} arch=${arch}`);

    // Single onMatch wrapper. Identical arg order to legacy
    // cronet_android.ts:104-107: (label=args[1], ssl=args[0], secret.data=args[2],
    // secret.size=args[3]).
    //
    // Per-secret install marker mirrors legacy's dumpKeys-callback log so
    // `-do` users see the same diagnostic stream on the modern path. Use
    // `devlog` (debug-level) to keep default-verbosity stdout clean — the
    // one-time install banner emitted by the chain / pattern_based_hooking
    // covers users who haven't enabled debug output.
    // The install banner is emitted ONCE on the first secret, not per secret.
    // It previously logged inside this hot callback, which fires on every
    // ssl_log_secret() call — flooding the JS→Python channel during active QUIC
    // key derivation and stalling detach. dumpKeys still runs per call (that is
    // the actual keylog work); only the diagnostic is throttled.
    let installLogged = false;
    // Guarded: if another tier (tier 4, a parallel symbol hook) already owns
    // this module's keylog, a late pattern match must not emit every secret twice.
    const guardedDumpKeys = guardKeylogDumpKeys(moduleName, "pattern", dumpKeys);
    const onMatch = (args: any[]): void => {
        if (!installLogged) {
            installLogged = true;
            devlog(`Installed ssl_log_secret() hooks using byte patterns for module ${moduleName}.`);
        }
        guardedDumpKeys(args[1], args[0], args[2], lenArg(args[3]) ?? 0);
    };

    let hooker: PatternBasedHooking;
    try {
        hooker = new PatternBasedHooking(mod);
        if (source.kind === "json") {
            // hook_DumpKeys' internal lookup tries parsed.modules[moduleName] then
            // parsed.modules[jsonKey]. Passing the real module name as the first
            // arg keeps tier 3a working when moduleName === jsonKey; the alias
            // path (3b) is taken when they differ. The hooker scans `this.module`
            // (the loaded Frida Module), not jsonKey.
            hooker.hook_DumpKeys(moduleName, source.jsonKey, patternsJson!, onMatch);
        } else {
            hooker.hookModuleByPattern(source.patterns, onMatch);
        }
    } catch (e) {
        devlog_error(`[bssl-pattern] ${moduleName}: scan kickoff threw: ${e}`);
        return notScheduled(`hook setup threw: ${e}`);
    }

    return {
        scheduled: true,
        reason: `scan-scheduled (${source.via})`,
        settled: pollPatternOutcome(hooker, moduleName),
    };
}

function notScheduled(reason: string): PatternHookResult {
    return { scheduled: false, reason, settled: Promise.resolve(false) };
}

interface ResolverInput {
    parsed: any;
    moduleName: string;
    family: FamilyKey;
    arch: ArchKey | null;
    libraryType: string;
    fallbackJsonName: string;
}

function resolveBestSource(input: ResolverInput): ResolvedPatternSource | null {
    const { parsed, moduleName, family, arch, libraryType, fallbackJsonName } = input;

    // 3a — pattern.json: exact module key.
    if (parsed?.modules?.[moduleName]) {
        return { kind: "json", via: "3a-exact", jsonKey: moduleName };
    }

    // 3b — pattern.json: family alias keys, plus the caller's legacy default
    // as the last alias so callers passing it explicitly still see it tried.
    const aliasList = dedupePreservingOrder([...familyAliases(family), fallbackJsonName]);
    for (const alias of aliasList) {
        if (!alias || alias === moduleName) continue;
        if (parsed?.modules?.[alias]) {
            return { kind: "json", via: `3b-alias-${alias}`, jsonKey: alias };
        }
    }

    // 3c — bundled per-family hardcoded patterns.
    if (arch) {
        const bundle = getBundledPatterns(family, arch);
        if (bundle) {
            return { kind: "bundled", via: `3c-bundled-${family}`, patterns: bundle };
        }
    }

    // 3d — bundled openssl.<arch>.ssl_log_secret[] floor. Only fires for
    // BoringSSL/OpenSSL libraryTypes; other libs opt out cleanly.
    if (arch && (libraryType === "boringssl" || libraryType === "openssl")) {
        const list = BUNDLED_OPENSSL_SSL_LOG_SECRET[arch];
        if (list && list.length > 0) {
            const synth: ArchPatterns = {
                primary: list[0],
                fallback: list[1] ?? list[0],
                second_fallback: list[2],
            };
            return { kind: "bundled", via: "3d-bundled-openssl", patterns: synth };
        }
    }

    return null;
}

function dedupePreservingOrder(items: string[]): string[] {
    const seen = new Set<string>();
    const out: string[] = [];
    for (const it of items) {
        if (it && !seen.has(it)) {
            seen.add(it);
            out.push(it);
        }
    }
    return out;
}

/**
 * The hooker state the poll reads. Structural so the LEGACY PatternBasedHooking
 * (agent/legacy/tls/shared/pattern_based_hooking.ts, no `cascadeCompleted`) can
 * be awaited too: without that flag only a match or the hard bound settles it.
 */
export interface PatternOutcomeSource {
    found_ssl_log_secret: boolean;
    cascadeCompleted?: boolean;
}

/** Poll timing; overridable for tests. */
export interface PatternPollTiming {
    intervalMs: number;
    maxIntervalMs: number;
    graceMs: number;
    softTimeoutMs: number;
    hardTimeoutMs: number;
}

const DEFAULT_POLL_TIMING: PatternPollTiming = {
    intervalMs: POLL_INTERVAL_MS,
    maxIntervalMs: POLL_MAX_INTERVAL_MS,
    graceMs: POLL_GRACE_MS,
    softTimeoutMs: POLL_SOFT_TIMEOUT_MS,
    hardTimeoutMs: POLL_HARD_TIMEOUT_MS,
};

/**
 * One poll step's verdict:
 *   matched     — the scan installed the hook
 *   no-match    — the cascade SETTLED without a match (a real miss)
 *   gave-up     — still unmatched at the hard bound (scan may still be running)
 *   still-scanning — keep waiting
 */
export type PatternPollVerdict = "matched" | "no-match" | "gave-up" | "still-scanning";

/** Pure decision for one poll tick (exported for unit tests). */
export function classifyPatternPoll(
    hooker: PatternOutcomeSource, elapsedMs: number, timing: PatternPollTiming = DEFAULT_POLL_TIMING,
): PatternPollVerdict {
    if (hooker.found_ssl_log_secret) return "matched";
    // Gate on `cascadeCompleted` — set true only when every outer cascade branch
    // has terminated (see hookModuleByPattern). Reading `no_hooking_success` was
    // wrong: it is `true` from the constructor onward, so the check fired
    // BEFORE Memory.scan had started on slow targets like libmonochrome_64.so.
    if (elapsedMs >= timing.graceMs && hooker.cascadeCompleted === true) return "no-match";
    if (elapsedMs >= timing.hardTimeoutMs) return "gave-up";
    return "still-scanning";
}

/** Delay before the next tick: fixed until the soft timeout, then doubling up to the cap. */
export function nextPatternPollDelay(
    elapsedMs: number, previousDelayMs: number, timing: PatternPollTiming = DEFAULT_POLL_TIMING,
): number {
    if (elapsedMs < timing.softTimeoutMs) return timing.intervalMs;
    return Math.min(Math.max(previousDelayMs * 2, timing.intervalMs), timing.maxIntervalMs);
}

/**
 * Poll the hooker's flags for outcome.
 *
 * Resolves true once `found_ssl_log_secret` flips; false once the cascade
 * completed without a match (past the grace window), or once the hard bound
 * elapses with the scan still unmatched. Passing the SOFT timeout only logs
 * "still scanning" and backs the poll off — it never resolves: a false there
 * used to make every caller declare a total miss and start tier 4 while the
 * scan was still running.
 *
 * Even after a hard-bound false the scan is not cancelled and may still match;
 * the per-module ownership guard (guardKeylogDumpKeys) keeps that late match
 * from emitting secrets a second time.
 */
export function pollPatternOutcome(
    hooker: PatternOutcomeSource, moduleName: string, timing: PatternPollTiming = DEFAULT_POLL_TIMING,
): Promise<boolean> {
    return new Promise<boolean>((resolve) => {
        const t0 = Date.now();
        let delay = timing.intervalMs;
        let softTimeoutLogged = false;

        const tick = (): void => {
            // Stop rescheduling once teardown begins — this recurring setTimeout
            // would otherwise keep the JS message loop alive across script.unload(),
            // contributing to the detach hang.
            if (_isShuttingDownNow()) {
                resolve(false);
                return;
            }
            const elapsed = Date.now() - t0;
            const verdict = classifyPatternPoll(hooker, elapsed, timing);
            if (verdict !== "still-scanning") {
                devlog_debug(`[bssl-pattern] ${moduleName}: pattern outcome ${verdict} after ${elapsed}ms`);
                resolve(verdict === "matched");
                return;
            }
            if (!softTimeoutLogged && elapsed >= timing.softTimeoutMs) {
                softTimeoutLogged = true;
                devlog(`[bssl-pattern] ${moduleName}: pattern scan still running after ${elapsed}ms; waiting for it to finish (up to ${timing.hardTimeoutMs}ms)`);
            }
            delay = nextPatternPollDelay(elapsed, delay, timing);
            setTimeout(tick, delay);
        };

        setTimeout(tick, delay);
    });
}
