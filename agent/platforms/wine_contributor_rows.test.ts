// Unit test for the Wine contributor-row reachability fix (agent/platforms/wine.ts).
//
// Run: npm run test:agent
//
// WHY THIS FILE EXISTS
// --------------------
// Windows-DLL contributor rows (e.g. the `--protocol rc4` unit's BCrypt /
// CryptoAPI / OpenSSL RC4 hooks) are registered under platform "windows". Wine
// intercepts DLL loads under PLATFORM_WINE, and HookRegistry.getHooks() filters
// STRICTLY by `h.platform === platform`, so those rows never matched on a Wine
// target on either the legacy or modern path. wine.ts now re-tags a copy of each
// windows-platform contributor row to PLATFORM_WINE.
//
// This test locks down (a) the strict-platform root cause and (b) that the real
// contributedHooksFor(PLATFORM_WINE) seam makes an otherwise-unreachable windows
// contributor row match under Wine, without disturbing the "windows"-tagged
// original.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/etc. BEFORE registry.js loads (registry ->
// non_tls_libs -> log touches Frida globals).
import "../shared/frida-test-stubs.js";

import { HookRegistry } from "../shared/registry.js";
import { PLATFORM_WINE, PLATFORM_WINDOWS } from "../shared/shared_structures.js";
import { registerHookContributor, contributedHooksFor } from "../shared/hook_contributors.js";

// A stand-in for a windows-platform RC4 contributor row (same shape as
// agent/rc4/index.ts registers).
function makeWindowsRc4Row() {
    return {
        platform: PLATFORM_WINDOWS,
        pattern: /bcrypt\.dll/i,
        hookFn: (_m: string, _b: boolean) => { /* no-op */ },
        library: "Windows CNG RC4 (BCryptGenerateSymmetricKey)",
        libraryType: "rc4" as const,
        protocol: "rc4",
    };
}

test("root cause: windows contributor row is unreachable under PLATFORM_WINE", () => {
    const reg = new HookRegistry();
    reg.registerAll([makeWindowsRc4Row()]);

    // It matches on Windows...
    assert.equal(
        reg.findAllMatches(PLATFORM_WINDOWS, "bcrypt.dll", undefined, "rc4").length,
        1,
        "windows row should match on windows",
    );
    // ...but not on Wine, because getHooks filters strictly by platform.
    assert.equal(
        reg.findAllMatches(PLATFORM_WINE, "bcrypt.dll", undefined, "rc4").length,
        0,
        "windows row must NOT match under wine before remap",
    );
});

test("fix: contributedHooksFor(PLATFORM_WINE) re-tags windows rows to be reachable", () => {
    // Register a windows-platform contributor row through the real seam, exactly
    // as an optional unit (e.g. agent/rc4/index.ts) does at module-load time.
    registerHookContributor(makeWindowsRc4Row());

    const reg = new HookRegistry();
    // The original windows-tagged rows (verbatim for non-wine platforms)...
    reg.registerAll(contributedHooksFor(PLATFORM_WINDOWS));
    // ...plus what wine.ts registers: the same rows re-tagged to wine.
    reg.registerAll(contributedHooksFor(PLATFORM_WINE));

    // Now it matches under Wine (rc4 protocol)...
    const wineMatches = reg.findAllMatches(PLATFORM_WINE, "bcrypt.dll", undefined, "rc4");
    assert.equal(wineMatches.length, 1, "remapped row should match under wine");
    assert.equal(wineMatches[0].library, "Windows CNG RC4 (BCryptGenerateSymmetricKey)");

    // ...and the original windows-tagged row is untouched for real Windows targets.
    assert.equal(
        reg.findAllMatches(PLATFORM_WINDOWS, "bcrypt.dll", undefined, "rc4").length,
        1,
        "original windows row must still match on windows",
    );

    // The rc4 rows stay out of a default TLS run (protocol filtering).
    assert.equal(
        reg.findAllMatches(PLATFORM_WINE, "bcrypt.dll", undefined, "tls").length,
        0,
        "rc4 row must not match under a tls-only selection",
    );
});

// LSASS is a Windows-service concept only: its keys live in lsass.exe, hooked by
// a dedicated load_windows_lsass_agent session. Even if a future contributor
// unit registered an LSASS/NCrypt row under platform "windows", it must NEVER be
// re-tagged to wine. contributedHooksFor(PLATFORM_WINE) excludes such rows.
function makeWindowsLsassRow() {
    return {
        platform: PLATFORM_WINDOWS,
        pattern: /ncrypt*\.dll/i,
        hookFn: (_m: string, _b: boolean) => { /* no-op */ },
        library: "LSASS NCrypt",
        libraryType: "lsass" as const,
        protocol: "tls",
    };
}

test("safety: contributedHooksFor(PLATFORM_WINE) never includes lsass/ncrypt rows", () => {
    // A defensive scenario: a contributor unit registers a windows LSASS row.
    registerHookContributor(makeWindowsLsassRow());

    // The wine seam must drop it entirely (neither re-tagged nor passed through).
    const wineRows = contributedHooksFor(PLATFORM_WINE);
    assert.equal(
        wineRows.filter(r =>
            r.libraryType === "lsass" ||
            /lsass|ncrypt/i.test(r.library ?? "") ||
            /ncrypt/i.test(r.pattern.source),
        ).length,
        0,
        "no lsass/ncrypt row may reach a wine target",
    );

    // And it must not become reachable through the registry under Wine.
    const reg = new HookRegistry();
    reg.registerAll(contributedHooksFor(PLATFORM_WINE));
    assert.equal(
        reg.findAllMatches(PLATFORM_WINE, "ncrypt.dll", undefined, "tls").length,
        0,
        "lsass/ncrypt must never match under a wine target",
    );

    // The windows-tagged original is still available verbatim for real Windows.
    const winRows = contributedHooksFor(PLATFORM_WINDOWS);
    assert.ok(
        winRows.some(r => r.libraryType === "lsass"),
        "the windows lsass row is left untouched for real Windows targets",
    );
});
