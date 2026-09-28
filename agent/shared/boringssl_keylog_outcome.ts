// agent/shared/boringssl_keylog_outcome.ts
//
// Where the BoringSSL keylog tier chain reports a TOTAL MISS: the callback
// (SSL_CTX_set_keylog_callback), symbol (bssl::ssl_log_secret) and pattern
// (byte-pattern Memory.scan) tiers all failed for one module.
//
// Used by all three chains that own a BoringSSL module:
//   - legacy boring_execute        (agent/legacy/tls/platforms/android/openssl_boringssl_android.ts)
//   - legacy cronet_execute        (via scheduleBoringSSLSymbolFallback, agent/shared/boringssl_symbol_hook.ts,
//                                   or runForcedAnchorTier under --boringssl-anchor-only)
//   - modern installBoringSSLKeylogChain (agent/shared/boringssl_hook_chain.ts)
//
// Success is NOT reported here: every tier already prints its own default-
// verbosity banner ("[*] <module>: keylog hooks installed via callback|symbol|
// pattern (...)"), so a second success line would only duplicate it.
//
// Kept free of Frida-API and fritap_agent imports so it can be unit tested
// under Node (see boringssl_keylog_outcome.test.ts).

import { devlog, log } from "../util/log.js";
import type { DumpKeysCb } from "./boringssl_symbol_hook.js";

export const ALL_KEYLOG_TIERS_MISSED_MSG = (moduleName: string, detail?: string): string =>
    `[!] ${moduleName}: no BoringSSL keylog hook could be installed ` +
    `(callback, symbol and pattern tiers all missed${detail ? `; ${detail}` : ""})`;

/** Modules already reported, so a module that goes through two chains warns once. */
const reportedModules = new Set<string>();
/** Modules whose total-miss WARNING was actually printed (tier 4 missed too). */
const warnedModules = new Set<string>();

/* ------------------------------------------------------------------------- *
 *  Per-module keylog-hook ownership (double-install guard)
 *
 *  Several tiers can end up hooking the SAME bssl::ssl_log_secret of one
 *  module: a pattern Memory.scan still running when the chain gave up on it
 *  (poll hard timeout) can match after tier 4 already installed, and the legacy
 *  Cronet chain runs the symbol tier in parallel with a still-running pattern
 *  scan. Without a guard every secret is then emitted twice.
 *
 *  The FIRST tier to claim a module owns it; the others' dumpKeys become
 *  no-ops. A tier claims either when it delivers its first secret (the
 *  dumpKeys wrapper below) or, for tier 4, when it reports a successful
 *  install (its ctx-write path emits through a keylog_callback, not dumpKeys).
 * ------------------------------------------------------------------------- */

export type KeylogHookTier = "symbol" | "pattern" | "anchor";

const keylogHookOwners = new Map<string, KeylogHookTier>();

/** The tier that owns `moduleName`'s keylog hook, if any. */
export function keylogHookOwner(moduleName: string): KeylogHookTier | undefined {
    return keylogHookOwners.get(moduleName);
}

/**
 * Claim `moduleName` for `tier`. True iff `tier` owns it afterwards (first
 * claim, or a repeat claim by the owner). A late first claim on a module whose
 * total-miss warning was already printed says so, so the earlier warning is
 * not left standing uncorrected.
 */
export function claimKeylogHook(moduleName: string, tier: KeylogHookTier): boolean {
    const owner = keylogHookOwners.get(moduleName);
    if (owner !== undefined) return owner === tier;
    keylogHookOwners.set(moduleName, tier);
    if (warnedModules.has(moduleName)) {
        log(`[*] ${moduleName}: the ${tier} tier installed a keylog hook after all (supersedes the earlier "no BoringSSL keylog hook" warning)`);
    }
    return true;
}

/**
 * Wrap a tier's dumpKeys so it only emits while `tier` owns `moduleName`.
 * The first secret claims the module; a tier that lost the race drops its
 * secrets (the winner emits the same ones) and says so once at debug level.
 */
export function guardKeylogDumpKeys(moduleName: string, tier: KeylogHookTier, dumpKeys: DumpKeysCb): DumpKeysCb {
    let dropLogged = false;
    return (label, ssl, data, len) => {
        if (claimKeylogHook(moduleName, tier)) {
            dumpKeys(label, ssl, data, len);
            return;
        }
        if (!dropLogged) {
            dropLogged = true;
            devlog(`[bssl-keylog] ${moduleName}: ${tier} hook fired but the ${keylogHookOwner(moduleName)} tier owns this module; dropping its duplicate secrets`);
        }
    };
}

/**
 * Tier 4 (the anchor locator) is injected rather than imported so this module
 * stays free of the Frida API and unit-testable under Node. boringssl_anchor_
 * locator.ts self-registers its runner at load time.
 *
 * The runner may be ASYNC (the real one is: its xref scan yields to the event
 * loop between chunks so the agent stays responsive). A plain boolean is still
 * accepted and handled synchronously.
 */
export type Tier4Runner = (moduleName: string, dumpKeys: DumpKeysCb, detail?: string) => boolean | Promise<boolean>;
let tier4Runner: Tier4Runner | null = null;

/** Install the tier-4 runner (called once by boringssl_anchor_locator.ts). */
export function registerBoringSSLTier4(runner: Tier4Runner): void {
    tier4Runner = runner;
}

function isThenable(v: unknown): v is Promise<boolean> {
    return typeof v === "object" && v !== null && typeof (v as any).then === "function";
}

/** The total-miss warning, naming tier 4 when it ran. */
function warnTotalMiss(moduleName: string, detail: string | undefined, tier4Ran: boolean): void {
    const finalDetail = tier4Ran
        ? (detail ? `${detail}; anchor-locator (tier 4) also missed` : "anchor-locator (tier 4) also missed")
        : detail;
    warnedModules.add(moduleName);
    log(ALL_KEYLOG_TIERS_MISSED_MSG(moduleName, finalDetail));
}

/**
 * Tier 4's outcome: on success claim the module (so a late pattern match
 * stays silent; tier 4 prints its own banner), else the warning.
 */
function reportTier4Outcome(moduleName: string, detail: string | undefined, installed: boolean): void {
    if (!installed) {
        warnTotalMiss(moduleName, detail, true);
        return;
    }
    if (!claimKeylogHook(moduleName, "anchor")) {
        devlog(`[bssl-keylog] ${moduleName}: tier 4 installed, but the ${keylogHookOwner(moduleName)} tier already owns this module`);
    }
}

/** Why the tier chain missed, as reported by the calling chain. */
export interface KeylogMissReport {
    /** Appended to the total-miss warning. */
    detail?: string;
    /** --pairip-safe disabled the pattern tier; tier 4 (also a memory scan) is then skipped too. */
    pairipDisabled: boolean;
}

/**
 * TIER-4 HOOK POINT. Called exactly when tiers 1-3 have all missed for
 * `moduleName` (callback absent, symbol unresolved, pattern scan exhausted,
 * still unmatched at the poll hard bound, not schedulable or disabled by
 * --pairip-safe).
 *
 * It tries tier 4 (the registered anchor locator) FIRST and emits the warning
 * only if that also misses — in which case the warning names tier 4 too.
 * `dumpKeys` is the chain's own per-secret callback, passed through so tier 4's
 * field-dump fallback hooks ssl_log_secret with the same keylog formatting as
 * tiers 2/3. Tier 4 is a memory scan, so it is skipped when the pattern tier was
 * disabled by --pairip-safe (`report.pairipDisabled`).
 *
 * When tier 4 is async this returns immediately with a promise that settles
 * once the outcome (success banner or warning) has been reported; callers may
 * ignore it. The module is claimed up front, so a second chain reporting the
 * same module while the scan runs neither starts a second scan nor warns: the
 * "warn once per module" rule holds across the async gap.
 */
export function onAllKeylogTiersMissed(
    moduleName: string, dumpKeys: DumpKeysCb, report: KeylogMissReport,
): void | Promise<void> {
    if (reportedModules.has(moduleName)) return;
    reportedModules.add(moduleName);
    // Another tier already delivered secrets for this module (e.g. a pattern
    // scan that matched after the chain stopped waiting): not a miss at all.
    if (keylogHookOwners.has(moduleName)) return;

    const { detail, pairipDisabled } = report;
    // --pairip-safe disables the pattern tier (a memory scan); tier 4 scans too,
    // so honour the same gate.
    if (tier4Runner === null || pairipDisabled) {
        warnTotalMiss(moduleName, detail, false);
        return;
    }

    let result: boolean | Promise<boolean>;
    try {
        result = tier4Runner(moduleName, guardKeylogDumpKeys(moduleName, "anchor", dumpKeys), detail);
    } catch (e) {
        log(`[!] ${moduleName}: tier-4 anchor locator threw: ${e}`);
        result = false;
    }
    if (!isThenable(result)) {
        reportTier4Outcome(moduleName, detail, result === true);
        return;
    }
    return result.then(
        (installed) => reportTier4Outcome(moduleName, detail, installed === true),
        (e) => {
            log(`[!] ${moduleName}: tier-4 anchor locator threw: ${e}`);
            reportTier4Outcome(moduleName, detail, false);
        },
    );
}

/** Total-miss detail used when --boringssl-anchor-only skipped the pattern tier. */
export const FORCED_ANCHOR_ONLY_DETAIL = "forced by --boringssl-anchor-only";

/**
 * --boringssl-anchor-only for the LEGACY chains (boring_execute, cronet_execute),
 * mirroring the guard in the modern chain (boringssl_hook_chain.ts): the
 * byte-pattern tier is skipped, the symbol tier still runs first (as it does in
 * the modern chain, so an exported ssl_log_secret is never hooked twice), and a
 * symbol miss goes straight to onAllKeylogTiersMissed, i.e. tier 4.
 * `trySymbolTier` is injected so this stays Frida-free and unit-testable.
 */
export function runForcedAnchorTier(
    moduleName: string,
    dumpKeys: DumpKeysCb,
    trySymbolTier: () => boolean,
): void | Promise<void> {
    let symbolInstalled = false;
    try {
        symbolInstalled = trySymbolTier();
    } catch (e) {
        log(`[!] ${moduleName}: symbol tier threw under --boringssl-anchor-only: ${e}`);
    }
    if (!symbolInstalled) return onAllKeylogTiersMissed(moduleName, dumpKeys, { detail: FORCED_ANCHOR_ONLY_DETAIL, pairipDisabled: false });
}

/** Test-only: forget which modules were reported / owned and drop the tier-4 runner. */
export function _resetKeylogOutcomeReportsForTests(): void {
    reportedModules.clear();
    warnedModules.clear();
    keylogHookOwners.clear();
    tier4Runner = null;
}
