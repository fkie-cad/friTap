// Unit tests for `supplementary` registry rows (agent/shared/registry.ts) and how
// the loaders / scanner treat them (shared_functions.ts, library_scanner.ts).
//
// Run: npm run test:agent
//
// WHY THIS FILE EXISTS
// --------------------
// On Android Chrome the only registry row matching libchrome.so used to be the
// Google QUICHE one. google_quiche_execute installs QUIC stream hooks only (and
// returns early without plaintext pcap) — it extracts no keys — yet the loader
// still called markModuleHooked(libchrome.so, "tls"). That blocked every rescue
// path (scan-results pass, dynamic loader, --library-scan), so Chrome yielded no
// keys at all. The fix:
//   * a Cronet (Chrome) BoringSSL row for libchrome.so, and
//   * `supplementary: true` on QUIC-stream-only rows: they still install and
//     report library_detected, but are recorded under `${tag}:supplementary:${library}`
//     and ignored by the "already matched by the registry" filters.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Interceptor/etc. BEFORE agent modules load.
import "./frida-test-stubs.js";
import { HookRegistry, hookRegistry } from "./registry.js";
// Android registers its rows under "linux" (android.ts: plattform_name = PLATFORM_LINUX).
import { PLATFORM_LINUX as PLATFORM_ANDROID } from "./shared_structures.js";
import { isModuleHooked, installTagFor, processScanResults } from "./library_scanner.js";
import { ssl_library_loader, hookDynamicLoader } from "./shared_functions.js";

const G = globalThis as any;
const sent: any[] = [];
G.send = (msg: any) => { sent.push(msg); };

// Every module "exists" and has a path; getExportByName feeds hookDynamicLoader.
G.Process.getModuleByName = (name: string) => ({
    name, path: `/data/app/${name}`, base: G.ptr(1),
    ensureInitialized: () => { },
    enumerateExports: () => [],
    getExportByName: () => G.ptr(1),
});

/** Counts hookFn invocations per registry row. */
function makeCounter() {
    const calls: string[] = [];
    return { calls, hookFn: (moduleName: string, _base: boolean) => { calls.push(moduleName); } };
}

/**
 * Mirrors the libchrome.so rows of agent/platforms/android.ts: the new Cronet
 * (Chrome) BoringSSL row and the supplementary Google QUICHE (Chrome) row.
 * Built by hand — importing android.ts would pull in every TLS implementation.
 */
function registerChromeRows(reg: HookRegistry, pattern: RegExp) {
    const cronet = makeCounter();
    const quiche = makeCounter();
    reg.registerAll([
        { platform: PLATFORM_ANDROID, pattern, hookFn: cronet.hookFn, library: "Cronet (Chrome)", libraryType: "boringssl", protocol: "tls" },
        { platform: PLATFORM_ANDROID, pattern, hookFn: quiche.hookFn, library: "Google QUICHE (Chrome)", libraryType: "google_quiche", protocol: "tls", supplementary: true },
    ]);
    return { cronet, quiche };
}

/** Registers only a supplementary QUICHE row (the pre-fix libchrome.so shape). */
function registerQuicheOnly(reg: HookRegistry, pattern: RegExp) {
    const quiche = makeCounter();
    reg.registerAll([
        { platform: PLATFORM_ANDROID, pattern, hookFn: quiche.hookFn, library: "Google QUICHE", libraryType: "google_quiche", protocol: "tls", supplementary: true },
    ]);
    return quiche;
}

test("libchrome.so matches both the Cronet (Chrome) row and the supplementary QUICHE row", () => {
    const reg = new HookRegistry();
    registerChromeRows(reg, /.*libchrome\.so/);
    const matches = reg.findAllMatches(PLATFORM_ANDROID, "libchrome.so", "/data/app/libchrome.so", "tls");
    assert.deepEqual(matches.map(m => m.library), ["Cronet (Chrome)", "Google QUICHE (Chrome)"]);
    assert.equal(reg.findPrimaryMatch(PLATFORM_ANDROID, "libchrome.so", "", "tls")?.library, "Cronet (Chrome)");
});

test("findPrimaryMatch ignores supplementary-only matches; findMatch still sees them", () => {
    const reg = new HookRegistry();
    registerQuicheOnly(reg, /.*libquiche_only\.so/);
    assert.equal(reg.findMatch(PLATFORM_ANDROID, "libquiche_only.so", "", "tls")?.library, "Google QUICHE");
    assert.equal(reg.findPrimaryMatch(PLATFORM_ANDROID, "libquiche_only.so", "", "tls"), undefined);
});

test("installTagFor: supplementary rows get their own dedup tag", () => {
    const reg = new HookRegistry();
    registerChromeRows(reg, /.*libtag\.so/);
    const [primary, supp] = reg.findAllMatches(PLATFORM_ANDROID, "libtag.so", "", "tls");
    assert.equal(installTagFor(primary, "tls"), "tls");
    assert.equal(installTagFor(supp, "tls"), "tls:supplementary:Google QUICHE (Chrome)");
});

test("installTagFor: the supplementary tag is per row, not per module", () => {
    const reg = new HookRegistry();
    const a = makeCounter();
    const b = makeCounter();
    reg.registerAll([
        { platform: PLATFORM_ANDROID, pattern: /.*libtwo_supp\.so/, hookFn: a.hookFn, library: "Supp A", libraryType: "google_quiche", protocol: "tls", supplementary: true },
        { platform: PLATFORM_ANDROID, pattern: /.*libtwo_supp\.so/, hookFn: b.hookFn, library: "Supp B", libraryType: "google_quiche", protocol: "tls", supplementary: true },
    ]);
    const [rowA, rowB] = reg.findAllMatches(PLATFORM_ANDROID, "libtwo_supp.so", "", "tls");
    assert.notEqual(installTagFor(rowA, "tls"), installTagFor(rowB, "tls"));
});

test("ssl_library_loader: two supplementary rows on one module both install, once each", () => {
    const reg = new HookRegistry();
    const a = makeCounter();
    const b = makeCounter();
    reg.registerAll([
        { platform: PLATFORM_ANDROID, pattern: /.*libsupp_two\.so/, hookFn: a.hookFn, library: "Supp A", libraryType: "google_quiche", protocol: "tls", supplementary: true },
        { platform: PLATFORM_ANDROID, pattern: /.*libsupp_two\.so/, hookFn: b.hookFn, library: "Supp B", libraryType: "google_quiche", protocol: "tls", supplementary: true },
    ]);
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_two.so"], "Android", true, "tls");
    assert.deepEqual(a.calls, ["libsupp_two.so"]);
    assert.deepEqual(b.calls, ["libsupp_two.so"], "the second supplementary row must not be skipped");
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_two.so"], "Android", false, "tls");
    assert.equal(a.calls.length, 1);
    assert.equal(b.calls.length, 1);
    assert.equal(isModuleHooked("libsupp_two.so", "tls"), false);
});

test("ssl_library_loader: a supplementary match does NOT mark the module hooked for tls, but still reports library_detected", () => {
    const reg = new HookRegistry();
    const quiche = registerQuicheOnly(reg, /.*libsupp_a\.so/);
    sent.length = 0;
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_a.so"], "Android", true, "tls");
    assert.deepEqual(quiche.calls, ["libsupp_a.so"]);
    assert.equal(isModuleHooked("libsupp_a.so", "tls"), false);
    assert.equal(isModuleHooked("libsupp_a.so", "tls:supplementary:Google QUICHE"), true);
    assert.ok(sent.some(m => m.contentType === "library_detected" && m.library === "libsupp_a.so"));
});

test("ssl_library_loader: a normal match marks the module hooked for tls (both rows install once)", () => {
    const reg = new HookRegistry();
    const { cronet, quiche } = registerChromeRows(reg, /.*libchrome_a\.so/);
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libchrome_a.so"], "Android", true, "tls");
    assert.deepEqual(cronet.calls, ["libchrome_a.so"]);
    assert.deepEqual(quiche.calls, ["libchrome_a.so"]);
    assert.equal(isModuleHooked("libchrome_a.so", "tls"), true);
    // A second pass is fully short-circuited by the module-level tls check.
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libchrome_a.so"], "Android", false, "tls");
    assert.equal(cronet.calls.length, 1);
    assert.equal(quiche.calls.length, 1);
});

test("ssl_library_loader: a second pass does not reinstall the same supplementary hook", () => {
    const reg = new HookRegistry();
    const quiche = registerQuicheOnly(reg, /.*libsupp_b\.so/);
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_b.so"], "Android", true, "tls");
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_b.so"], "Android", false, "tls");
    assert.equal(quiche.calls.length, 1);
});

test("ssl_library_loader: a later primary hook still installs after a supplementary-only first pass", () => {
    const reg = new HookRegistry();
    const quiche = registerQuicheOnly(reg, /.*libsupp_c\.so/);
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_c.so"], "Android", true, "tls");
    const cronet = makeCounter();
    reg.register({ platform: PLATFORM_ANDROID, pattern: /.*libsupp_c\.so/, hookFn: cronet.hookFn, library: "BoringSSL (auto-detected)", libraryType: "boringssl" });
    ssl_library_loader(PLATFORM_ANDROID, reg, ["libsupp_c.so"], "Android", false, "tls");
    assert.deepEqual(cronet.calls, ["libsupp_c.so"]);
    assert.equal(quiche.calls.length, 1, "supplementary hook must not be reinstalled");
    assert.equal(isModuleHooked("libsupp_c.so", "tls"), true);
});

test("hookDynamicLoader: a repeated dlopen of the same module does not reinstall the supplementary hook", () => {
    const reg = new HookRegistry();
    const quiche = registerQuicheOnly(reg, /.*libsupp_d\.so/);
    let callbacks: any;
    const originalAttach = G.Interceptor.attach;
    G.Interceptor.attach = (_addr: any, cb: any) => { callbacks = cb; return { detach: () => { } }; };
    try {
        hookDynamicLoader(
            { platform: PLATFORM_ANDROID, platformLabel: "Android", loaderLibrary: /libdl\.so/, functionName: "supp_test_dlopen" } as any,
            reg, ["libdl.so"], false, "tls",
        );
    } finally {
        G.Interceptor.attach = originalAttach;
    }
    assert.ok(callbacks, "loader hook must be attached");
    const fireDlopen = () => {
        const ctx: any = {};
        callbacks.onEnter.call(ctx, [{ readCString: () => "libsupp_d.so" }]);
        callbacks.onLeave.call(ctx, G.ptr(1));
    };
    fireDlopen();
    fireDlopen();
    assert.equal(quiche.calls.length, 1);
    assert.equal(isModuleHooked("libsupp_d.so", "tls"), false);
});

test("processScanResults: a supplementary-only registry match does not suppress the library_type hook", () => {
    const quiche = registerQuicheOnly(hookRegistry, /.*libscan_supp\.so/);
    const boring = makeCounter();
    hookRegistry.register({ platform: PLATFORM_ANDROID, pattern: /^never-matches-by-name$/, hookFn: boring.hookFn, library: "BoringSSL (scan)", libraryType: "boringssl", protocol: "tls" });
    const entry = { name: "libscan_supp.so", path: "/data/app/libscan_supp.so", base_address: "0x1", library_type: "boringssl", matched_exports: [], detected_version: "" };
    processScanResults(JSON.stringify([entry]), PLATFORM_ANDROID, false, "tls");
    assert.deepEqual(boring.calls, ["libscan_supp.so"]);
    assert.equal(quiche.calls.length, 0, "the scanner installs by library_type only");
    assert.equal(isModuleHooked("libscan_supp.so", "tls"), true);
});

test("processScanResults: a primary registry match still suppresses the library_type hook", () => {
    const { cronet } = registerChromeRows(hookRegistry, /.*libscan_primary\.so/);
    const entry = { name: "libscan_primary.so", path: "/data/app/libscan_primary.so", base_address: "0x1", library_type: "boringssl", matched_exports: [], detected_version: "" };
    processScanResults(JSON.stringify([entry]), PLATFORM_ANDROID, false, "tls");
    assert.equal(cronet.calls.length, 0);
    assert.equal(isModuleHooked("libscan_primary.so", "tls"), false);
});
