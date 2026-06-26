// Unit tests for the OS-aware non-TLS library skip list (agent/util/non_tls_libs.ts).
//
// Run: npm run test:agent  (node --import tsx --test agent/util/non_tls_libs.test.ts)
//
// No Frida runtime needed: we side-effect import the Frida stubs (which set
// Process.platform = "linux", Java.available = false) before the module loads,
// and pass explicit OS keys to matchNonTLSLibrary() for deterministic scoping.
//
// Why this exists: these two WebView siblings are caught by the broad Android
// hook pattern /.*libwebviewchromium.*\.so/ but carry no TLS. If the skip stops
// firing, friTap would waste a Memory.scan on them (and risk tripping target
// protections); if it ever caught the real libwebviewchromium.so, we would lose
// WebView/Cronet TLS capture entirely. Both directions are locked below.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Java/etc. BEFORE non_tls_libs.js loads.
import "../shared/frida-test-stubs.js";
import { matchNonTLSLibrary, noteNonTLSLibrary } from "./non_tls_libs.js";

const G = globalThis as any;
// non_tls_libs.ts emits a devlog via send() on the host bridge in some builds;
// stub it so noteNonTLSLibrary() is safe to call.
G.send = G.send ?? ((_msg: any) => { });

test("skips the two WebView non-TLS siblings on android and linux", () => {
    for (const os of ["android", "linux"] as const) {
        assert.ok(matchNonTLSLibrary("libwebviewchromium_plat_support.so", os), `plat_support on ${os}`);
        assert.ok(matchNonTLSLibrary("libwebviewchromium_loader.so", os), `loader on ${os}`);
        // Full-path form (Frida sometimes reports the apk!lib path).
        assert.ok(matchNonTLSLibrary("/data/app/~~x==/base.apk!libwebviewchromium_loader.so", os));
    }
});

test("never matches the real TLS-bearing libwebviewchromium.so monolith", () => {
    for (const os of ["android", "linux"] as const) {
        assert.equal(matchNonTLSLibrary("libwebviewchromium.so", os), null);
    }
});

test("does not match unrelated TLS libraries", () => {
    assert.equal(matchNonTLSLibrary("libssl.so", "android"), null);
    assert.equal(matchNonTLSLibrary("libflutter.so", "android"), null);
    assert.equal(matchNonTLSLibrary("", "android"), null);
    assert.equal(matchNonTLSLibrary(undefined, "android"), null);
    assert.equal(matchNonTLSLibrary(null, "android"), null);
});

test("is OS-scoped: the WebView .so skip does not apply on windows/macos/ios", () => {
    for (const os of ["windows", "macos", "ios"] as const) {
        assert.equal(matchNonTLSLibrary("libwebviewchromium_loader.so", os), null, `must not skip on ${os}`);
        assert.equal(matchNonTLSLibrary("libwebviewchromium_plat_support.so", os), null);
    }
});

test("default OS path resolves from Frida globals (stub => linux) and still skips", () => {
    // No explicit platform arg → uses the memoized current OS. The Frida stub
    // sets Process.platform = "linux" with no Android runtime module, so the
    // detector resolves to "linux".
    assert.ok(matchNonTLSLibrary("libwebviewchromium_loader.so"));
    assert.equal(matchNonTLSLibrary("libssl.so"), null);
});

test("noteNonTLSLibrary returns true for a known lib and false otherwise", () => {
    assert.equal(noteNonTLSLibrary("libwebviewchromium_plat_support.so"), true);
    assert.equal(noteNonTLSLibrary("libssl.so"), false);
});
