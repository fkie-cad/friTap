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
import { DumpKeysCb } from "./boringssl_symbol_hook.js";
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
import { devlog, devlog_debug, devlog_error, _isShuttingDownNow } from "../util/log.js";

export interface PatternHookResult {
    scheduled: boolean;
    reason: string;
    /** Resolves true iff the (single) pattern cascade matched; false on exhaustion or timeout. */
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
// full cascade comfortably exceeds 5 s on cold caches. Polling timeout no longer
// pre-empts the chain into a wasted symbol re-scan; it only delays the chain's
// "fall back to symbol re-resolve" log. The underlying scan continues regardless.
const POLL_TIMEOUT_MS = 10000;
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
    const onMatch = (args: any[]): void => {
        if (!installLogged) {
            installLogged = true;
            devlog(`Installed ssl_log_secret() hooks using byte patterns for module ${moduleName}.`);
        }
        dumpKeys(args[1], args[0], args[2], lenArg(args[3]) ?? 0);
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
 * Poll the hooker's flags for outcome.
 *
 * Resolves true once `found_ssl_log_secret` flips, false once
 * `no_hooking_success` is true past the grace window or POLL_TIMEOUT_MS
 * elapses.
 *
 * IMPORTANT: When this resolves false on timeout, the underlying Memory.scan
 * is still running. We do NOT fire another scan — the chain will (uselessly)
 * try `attemptSymbolFallback` on `.settled.then(false)` and then give up, but
 * the still-running scan can match later and install the hook. This is the
 * same async-success-after-timeout behaviour the legacy executor relies on
 * (via scheduleBoringSSLSymbolFallback at PATTERN_HOOKING_SETTLE_MS=1000).
 */
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

            // Stop rescheduling once teardown begins — this recurring setTimeout
            // would otherwise keep the JS message loop alive across script.unload(),
            // contributing to the detach hang.
            if (_isShuttingDownNow()) {
                finish(false);
                return;
            }

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

            // Gate on `cascadeCompleted` — set true only when every outer
            // cascade branch has terminated (see hookModuleByPattern). Reading
            // `no_hooking_success` here was wrong: the field is `true` from the
            // constructor onward and remains `true` until a match flips it, so
            // the grace check used to fire BEFORE Memory.scan had started,
            // logging a premature "tier 3 exhausted" / "No keylog hook installed"
            // on slow targets like libmonochrome_64.so.
            if (elapsed >= POLL_GRACE_MS && hooker.cascadeCompleted && !hooker.found_ssl_log_secret) {
                devlog_debug(`[bssl-pattern] ${moduleName}: cascade completed at ${elapsed}ms without match`);
                finish(false);
                return;
            }

            setTimeout(tick, POLL_INTERVAL_MS);
        };

        setTimeout(tick, POLL_INTERVAL_MS);
    });
}
