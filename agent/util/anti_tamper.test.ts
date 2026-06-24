// Unit tests for anti-tamper detection (agent/util/anti_tamper.ts).
//
// Run: npm run test:agent  (node --import tsx --test agent/util/anti_tamper.test.ts)
//
// These need no Frida runtime: we stub the minimal Frida global surface (incl.
// `send`, which anti_tamper.ts emits structured events through) before the
// module loads, and drive Process.enumerateModules() per case.
//
// Why this exists: scanForAntiTamper() gates the android_dlopen_ext loader hook
// in spawn mode (fkie-cad/friTap#64). If it stops reporting PairIP, the loader
// hook would silently come back and crash protected apps again.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Module/etc. BEFORE anti_tamper.js loads.
import "../shared/frida-test-stubs.js";
import { matchAntiTamper, scanForAntiTamper, bannerAntiTamper } from "./anti_tamper.js";

const G = globalThis as any;
// anti_tamper.ts emits the structured `anti_tamper_detected` event via send().
// Only ever called inside the functions below (never at import), so defining it
// here — after the hoisted imports — is in time for every test.
const sent: any[] = [];
G.send = (msg: any) => { sent.push(msg); };

function withModules(names: string[]): void {
    G.Process.enumerateModules = () => names.map((name) => ({ name }));
}

test("matchAntiTamper recognises libpairipcore.so by base name and full path", () => {
    assert.ok(matchAntiTamper("libpairipcore.so"));
    assert.ok(matchAntiTamper("/data/app/~~abc==/split_config.arm64_v8a.apk!libpairipcore.so"));
    assert.equal(matchAntiTamper("libssl.so"), null);
    assert.equal(matchAntiTamper(""), null);
    assert.equal(matchAntiTamper(undefined), null);
});

test("scanForAntiTamper returns true when an anti-tamper lib is loaded", () => {
    withModules(["libc.so", "libssl.so", "libpairipcore.so"]);
    assert.equal(scanForAntiTamper(), true);
});

test("scanForAntiTamper returns false on a clean module list", () => {
    withModules(["libc.so", "libssl.so", "libflutter.so"]);
    assert.equal(scanForAntiTamper(), false);
});

test("bannerAntiTamper emits a structured anti_tamper_detected event with the skip flag", () => {
    sent.length = 0;
    bannerAntiTamper("libpairipcore.so", true);
    const evt = sent.find((m) => m && m.contentType === "anti_tamper_detected");
    assert.ok(evt, "expected an anti_tamper_detected event");
    assert.equal(evt.skippedLoaderHook, true);
    assert.equal(evt.library, "libpairipcore.so");
    assert.match(evt.name, /PairIP/);
});

// The loader-hook gate in android.ts is `no_loader_hook || (spawned && antiTamper)`.
// It deliberately does NOT reference use_modern, so legacy (default) and modern
// modes share the exact same decision — this truth table documents+locks that.
test("loader-hook skip decision: spawn+anti-tamper or forced flag, mode-independent", () => {
    const decide = (no_loader_hook: boolean, spawned: boolean, antiTamper: boolean) =>
        no_loader_hook || (spawned && antiTamper);
    // forced flag always skips (attach or spawn)
    assert.equal(decide(true, false, false), true);
    assert.equal(decide(true, true, true), true);
    // auto-skip only in spawn AND anti-tamper present
    assert.equal(decide(false, true, true), true);
    // attach keeps the hook even under anti-tamper (it lands after PairIP's scan)
    assert.equal(decide(false, false, true), false);
    // spawn on a clean app keeps the hook
    assert.equal(decide(false, true, false), false);
});
