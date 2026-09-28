/**
 * hook_contributors.ts — generic registration seam for optional, separately
 * bundled hook units.
 *
 * The public agent bundle ships only the core hooks wired directly into each
 * platform agent. A FULL build additionally imports one or more private units
 * (e.g. a messenger E2E unit) BEFORE the agent entry; each such unit calls
 * `registerHookContributor(...)` at module-load time to add its hook rows, and
 * `registerProtocolImplication(...)` to declare companion-protocol implications
 * (e.g. "this protocol's traffic is TLS-wrapped, so selecting it also needs the
 * TLS hooks").
 *
 * The platform agent appends `...collectContributedHooks()` to the hook table it
 * registers, and the registry consults `contributedImplications()` when deciding
 * whether a hook should install for a requested protocol. In the public build no
 * unit registers, so both accessors return empty — the core behaves exactly as
 * before. The public core never names a private protocol; the contributor does.
 *
 * This module has NO import side effects and (by `import type`) no runtime
 * dependency on the registry, so importing it never triggers hook installation.
 */
import type { HookRegistry } from "./registry.js";
import { Platform, PLATFORM_WINE, PLATFORM_WINDOWS } from "./shared_structures.js";

/**
 * A contributed hook row. Same shape the platform agents pass to
 * `hookRegistry.registerAll(...)`: `platform`/`pattern`/`hookFn`/`library` are
 * mandatory; `protocol` (default "tls") and `priority` (default 100) are filled
 * in by the registry.
 */
export type HookContribution = Parameters<HookRegistry["registerAll"]>[0][number];

const _contributedHooks: HookContribution[] = [];
const _protocolImplications: Record<string, string[]> = {};

/** Register one hook row, or several at once. */
export function registerHookContributor(rows: HookContribution | HookContribution[]): void {
    if (Array.isArray(rows)) {
        _contributedHooks.push(...rows);
    } else {
        _contributedHooks.push(rows);
    }
}

/** All contributed hook rows, in registration order. */
export function collectContributedHooks(): HookContribution[] {
    return _contributedHooks.slice();
}

/**
 * Contributor rows a given platform agent should register, applying
 * platform-inheritance at the contributor seam.
 *
 * Windows-DLL contributor rows (e.g. the `--protocol rc4` unit's BCrypt /
 * CryptoAPI / OpenSSL RC4 hooks) register under platform "windows". A Wine
 * target intercepts DLL loads under PLATFORM_WINE and the registry filters
 * strictly by platform, so those rows would never match on Wine. For
 * PLATFORM_WINE this returns a copy of each windows-platform contributor row
 * re-tagged to wine so it becomes reachable — CONTRIBUTOR rows only; the
 * TLS/QUIC core rows are declared natively by wine.ts. The "windows"-tagged
 * originals are left untouched for real Windows targets, and protocol
 * filtering keeps the rc4 rows out of default TLS runs. Every other platform
 * gets the contributor rows verbatim.
 *
 * LSASS/NCrypt is a Windows-service concept only (keys live in lsass.exe, hooked
 * via a dedicated load_windows_lsass_agent session — never a Wine target), so
 * such a row must never be re-tagged to wine even if a future contributor unit
 * registers one. `isLsassOrNcryptRow` excludes those rows from the wine remap
 * explicitly; today no contributor registers one, so this is purely defensive.
 */
function isLsassOrNcryptRow(row: HookContribution): boolean {
    if (row.libraryType === "lsass") {
        return true;
    }
    const library = (row.library ?? "").toLowerCase();
    if (library.includes("lsass") || library.includes("ncrypt")) {
        return true;
    }
    return /ncrypt/i.test(row.pattern.source);
}

export function contributedHooksFor(platform?: Platform): HookContribution[] {
    if (platform === PLATFORM_WINE) {
        return _contributedHooks
            .filter(row => row.platform === PLATFORM_WINDOWS && !isLsassOrNcryptRow(row))
            .map(row => ({ ...row, platform: PLATFORM_WINE }));
    }
    return _contributedHooks.slice();
}

/**
 * Declare that selecting `requested` should also install hooks registered for
 * the `implies` protocol (idempotent).
 */
export function registerProtocolImplication(requested: string, implies: string): void {
    const list = _protocolImplications[requested] ?? (_protocolImplications[requested] = []);
    if (!list.includes(implies)) {
        list.push(implies);
    }
}

/** Map of requested-protocol → list of implied protocols contributed so far. */
export function contributedImplications(): Record<string, string[]> {
    return _protocolImplications;
}
