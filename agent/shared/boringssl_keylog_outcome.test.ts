// Unit tests for the BoringSSL keylog total-miss report
// (agent/shared/boringssl_keylog_outcome.ts), the future tier-4 hook point.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
const sent: any[] = [];
G.send = (msg: any) => { sent.push(msg); };

import {
    onAllKeylogTiersMissed,
    ALL_KEYLOG_TIERS_MISSED_MSG,
    _resetKeylogOutcomeReportsForTests,
    registerBoringSSLTier4,
    runForcedAnchorTier,
    FORCED_ANCHOR_ONLY_DETAIL,
    claimKeylogHook,
    guardKeylogDumpKeys,
    keylogHookOwner,
} from "./boringssl_keylog_outcome.js";

const noDump = () => { };
const NO_PAIRIP = { pairipDisabled: false };
const consoleLines = () => sent.filter((m) => m.contentType === "console").map((m) => m.console);

beforeEach(() => {
    sent.length = 0;
    _resetKeylogOutcomeReportsForTests();
});

test("a total miss emits one default-verbosity warning naming the module", () => {
    onAllKeylogTiersMissed("libhttpengine.so", noDump, NO_PAIRIP);
    assert.deepEqual(consoleLines(), [
        "[!] libhttpengine.so: no BoringSSL keylog hook could be installed (callback, symbol and pattern tiers all missed)",
    ]);
});

test("the warning fires once per module even when several chains report", () => {
    onAllKeylogTiersMissed("libhttpengine.so", noDump, NO_PAIRIP);
    onAllKeylogTiersMissed("libhttpengine.so", noDump, { detail: "pattern tier disabled by --pairip-safe", pairipDisabled: true });
    assert.equal(consoleLines().length, 1);
});

test("different modules are reported independently", () => {
    onAllKeylogTiersMissed("libhttpengine.so", noDump, NO_PAIRIP);
    onAllKeylogTiersMissed("libchrome.so", noDump, NO_PAIRIP);
    assert.equal(consoleLines().length, 2);
});

test("detail is appended inside the parentheses", () => {
    assert.equal(
        ALL_KEYLOG_TIERS_MISSED_MSG("libx.so", "pattern tier disabled by --pairip-safe"),
        "[!] libx.so: no BoringSSL keylog hook could be installed (callback, symbol and pattern tiers all missed; pattern tier disabled by --pairip-safe)",
    );
});

test("--boringssl-anchor-only: a symbol miss goes straight to tier 4 with the forced detail", () => {
    const tier4Calls: any[] = [];
    registerBoringSSLTier4((mod, _dump, detail) => { tier4Calls.push([mod, detail]); return true; });
    runForcedAnchorTier("libhttpengine.so", noDump, () => false);
    assert.deepEqual(tier4Calls, [["libhttpengine.so", FORCED_ANCHOR_ONLY_DETAIL]]);
    assert.deepEqual(consoleLines(), []); // tier 4 installed: no total-miss warning
});

test("--boringssl-anchor-only: a symbol hit skips tier 4", () => {
    let tier4Ran = false;
    registerBoringSSLTier4(() => { tier4Ran = true; return true; });
    runForcedAnchorTier("libcronet.so", noDump, () => true);
    assert.equal(tier4Ran, false);
    assert.deepEqual(consoleLines(), []);
});

test("--boringssl-anchor-only: a throwing symbol tier still reaches tier 4", () => {
    let tier4Ran = false;
    registerBoringSSLTier4(() => { tier4Ran = true; return false; });
    runForcedAnchorTier("libx.so", noDump, () => { throw new Error("boom"); });
    assert.equal(tier4Ran, true);
    assert.ok(consoleLines().some((l) => l.includes(FORCED_ANCHOR_ONLY_DETAIL) && l.includes("tier 4")));
});

test("--pairip-safe skips tier 4 and warns without naming it", () => {
    let tier4Ran = false;
    registerBoringSSLTier4(() => { tier4Ran = true; return true; });
    onAllKeylogTiersMissed("libx.so", noDump, { detail: "pattern tier disabled by --pairip-safe", pairipDisabled: true });
    assert.equal(tier4Ran, false);
    assert.deepEqual(consoleLines(), [ALL_KEYLOG_TIERS_MISSED_MSG("libx.so", "pattern tier disabled by --pairip-safe")]);
});

test("pairip state comes from the flag, not the detail text", () => {
    let tier4Ran = false;
    registerBoringSSLTier4(() => { tier4Ran = true; return true; });
    onAllKeylogTiersMissed("libx.so", noDump, { detail: "module not loaded: libpairipcore.so", pairipDisabled: false });
    assert.equal(tier4Ran, true);
});

// ---- async tier 4 (the real anchor locator scans in the background) -------

test("async tier 4 that installs: no warning, and the returned promise settles", async () => {
    registerBoringSSLTier4(async () => true);
    const p = onAllKeylogTiersMissed("libchrome.so", noDump, NO_PAIRIP);
    assert.ok(p instanceof Promise, "an async runner yields a promise");
    await p;
    assert.deepEqual(consoleLines(), []);
});

test("async tier 4 that misses: the warning (naming tier 4) comes only after it settles", async () => {
    let finish: (v: boolean) => void = () => { };
    registerBoringSSLTier4(() => new Promise<boolean>((r) => { finish = r; }));
    const p = onAllKeylogTiersMissed("libchrome.so", noDump, { detail: FORCED_ANCHOR_ONLY_DETAIL, pairipDisabled: false });
    assert.deepEqual(consoleLines(), [], "no warning while the scan is still running");
    finish(false);
    await p;
    assert.deepEqual(consoleLines(), [ALL_KEYLOG_TIERS_MISSED_MSG("libchrome.so",
        `${FORCED_ANCHOR_ONLY_DETAIL}; anchor-locator (tier 4) also missed`)]);
});

test("while tier 4 is in flight, a second chain neither rescans nor warns", async () => {
    let calls = 0;
    let finish: (v: boolean) => void = () => { };
    registerBoringSSLTier4(() => { calls++; return new Promise<boolean>((r) => { finish = r; }); });
    const p = onAllKeylogTiersMissed("libchrome.so", noDump, NO_PAIRIP);
    assert.equal(onAllKeylogTiersMissed("libchrome.so", noDump, NO_PAIRIP), undefined);
    finish(false);
    await p;
    assert.equal(calls, 1);
    assert.equal(consoleLines().length, 1, "warned exactly once");
});

test("a rejecting async tier 4 is reported and still warns once", async () => {
    registerBoringSSLTier4(async () => { throw new Error("scan aborted"); });
    await onAllKeylogTiersMissed("libchrome.so", noDump, NO_PAIRIP);
    const lines = consoleLines();
    assert.equal(lines.length, 2);
    assert.ok(lines[0].includes("tier-4 anchor locator threw") && lines[0].includes("scan aborted"));
    assert.ok(lines[1].includes("anchor-locator (tier 4) also missed"));
});

test("--boringssl-anchor-only passes the async tier-4 promise through", async () => {
    registerBoringSSLTier4(async () => false);
    const p = runForcedAnchorTier("libhttpengine.so", noDump, () => false);
    assert.ok(p instanceof Promise);
    await p;
    assert.equal(consoleLines().length, 1);
});

test("a sync tier 4 keeps the synchronous contract (warning emitted before return)", () => {
    registerBoringSSLTier4(() => false);
    assert.equal(onAllKeylogTiersMissed("libx.so", noDump, NO_PAIRIP), undefined);
    assert.equal(consoleLines().length, 1);
});

// ---- per-module keylog-hook ownership (A3 double-install guard) ------------

const P = (n: number) => n as any; // stand-in NativePointers; the guard never reads them

test("the first tier to claim a module owns it; others are refused", () => {
    assert.equal(claimKeylogHook("libcronet.so", "anchor"), true);
    assert.equal(claimKeylogHook("libcronet.so", "anchor"), true, "repeat claim by the owner");
    assert.equal(claimKeylogHook("libcronet.so", "pattern"), false);
    assert.equal(keylogHookOwner("libcronet.so"), "anchor");
    assert.equal(claimKeylogHook("libother.so", "pattern"), true, "ownership is per module");
});

test("guarded dumpKeys: only the owning tier emits each secret", () => {
    const emitted: string[] = [];
    const pattern = guardKeylogDumpKeys("libcronet.so", "pattern", () => emitted.push("pattern"));
    const symbol = guardKeylogDumpKeys("libcronet.so", "symbol", () => emitted.push("symbol"));
    // Both interceptors fire on the same ssl_log_secret call.
    symbol(P(1), P(2), P(3), 32);
    pattern(P(1), P(2), P(3), 32);
    symbol(P(1), P(2), P(3), 32);
    pattern(P(1), P(2), P(3), 32);
    assert.deepEqual(emitted, ["symbol", "symbol"]);
    assert.equal(keylogHookOwner("libcronet.so"), "symbol");
});

test("tier 4 success claims the module, so a late pattern match stays silent", () => {
    registerBoringSSLTier4(() => true);
    onAllKeylogTiersMissed("libmonochrome_64.so", noDump, NO_PAIRIP);
    assert.equal(keylogHookOwner("libmonochrome_64.so"), "anchor");
    const emitted: string[] = [];
    const latePattern = guardKeylogDumpKeys("libmonochrome_64.so", "pattern", () => emitted.push("pattern"));
    latePattern(P(1), P(2), P(3), 32);
    assert.deepEqual(emitted, []);
    assert.deepEqual(consoleLines(), [], "no contradictory banner or warning");
});

test("tier 4's field-dump dumpKeys is guarded too", () => {
    let tier4Dump: any = null;
    registerBoringSSLTier4((_m, dump) => { tier4Dump = dump; return true; });
    const emitted: string[] = [];
    onAllKeylogTiersMissed("libx.so", () => emitted.push("anchor"), NO_PAIRIP);
    tier4Dump(P(1), P(2), P(3), 32);
    assert.deepEqual(emitted, ["anchor"]);
});

test("a module whose keylog is already owned is not a miss: no tier 4, no warning", () => {
    let tier4Ran = false;
    registerBoringSSLTier4(() => { tier4Ran = true; return false; });
    claimKeylogHook("libcronet.so", "pattern");
    onAllKeylogTiersMissed("libcronet.so", noDump, NO_PAIRIP);
    assert.equal(tier4Ran, false);
    assert.deepEqual(consoleLines(), []);
});

test("a claim after the total-miss warning prints a superseding note", () => {
    registerBoringSSLTier4(() => false);
    onAllKeylogTiersMissed("libx.so", noDump, NO_PAIRIP);
    assert.equal(consoleLines().length, 1);
    const late = guardKeylogDumpKeys("libx.so", "pattern", noDump);
    late(P(1), P(2), P(3), 32);
    late(P(1), P(2), P(3), 32);
    const lines = consoleLines();
    assert.equal(lines.length, 2, "the note is printed once");
    assert.ok(lines[1].includes("libx.so") && lines[1].includes("pattern tier") && lines[1].includes("supersedes"));
});
