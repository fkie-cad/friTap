// agent/platforms/wine_row_selection.ts
//
// Which registry rows the Wine DLL loaders (agent/platforms/wine.ts) run for one DLL.
// Kept out of wine.ts so it can be unit-tested under Node.

import type { HookRegistration } from "../shared/registry.js";

/**
 * The registry rows a Wine loader runs for one DLL: the first match (Wine has always hooked
 * one registration per DLL) plus every later SUPPLEMENTARY match. Supplementary rows are
 * add-ons that extract no TLS keys and are deduplicated under their own tag, so they never
 * compete with the primary row — e.g. NSS HPKE (OHTTP) on a folded nss3.dll that the NSS
 * row also matches. Primary rows after the first are still skipped, as before.
 */
export function wineRowsToHook(matches: HookRegistration[]): HookRegistration[] {
    if (matches.length === 0) return [];
    return [matches[0], ...matches.slice(1).filter((m) => m.supplementary === true)];
}
