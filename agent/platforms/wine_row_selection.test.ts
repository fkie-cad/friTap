// Unit tests for agent/platforms/wine_row_selection.ts: the Wine DLL loaders run the
// first matching row per DLL plus every later supplementary row, so NSS HPKE (OHTTP)
// installs on a folded nss3.dll that the NSS row also claims.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { wineRowsToHook } from "./wine_row_selection.js";

const row = (library: string, supplementary?: boolean): any =>
    ({ platform: "wine", pattern: /x/, hookFn: () => {}, library, supplementary });

test("no match -> nothing to hook", () => {
    assert.deepEqual(wineRowsToHook([]), []);
});

test("only the first primary row is hooked (unchanged Wine behaviour)", () => {
    const nss = row("NSS"), other = row("Other");
    assert.deepEqual(wineRowsToHook([nss, other]), [nss]);
});

test("supplementary rows after the first are hooked too (folded nss3.dll: NSS + HPKE)", () => {
    const nss = row("NSS"), hpke = row("NSS HPKE (OHTTP)", true), other = row("Other");
    assert.deepEqual(wineRowsToHook([nss, other, hpke]), [nss, hpke]);
});

test("a supplementary first match (unfolded nss3.dll: NSS row rejected) is hooked alone", () => {
    const hpke = row("NSS HPKE (OHTTP)", true);
    assert.deepEqual(wineRowsToHook([hpke]), [hpke]);
});
