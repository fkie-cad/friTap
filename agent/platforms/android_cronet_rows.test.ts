// Unit test for the primary Android Cronet registry row (agent/platforms/android.ts).
//
// Run: npm run test:agent
//
// WHY THIS FILE EXISTS
// --------------------
// The primary "Cronet" row was /^libcronet([_.]|\.\d).*\.so$/, which does NOT
// match a plain `libcronet.so`: only the key-less supplementary QUICHE row did,
// so apps shipping libcronet.so got no TLS keys.
//
// android.ts cannot be imported under Node (it pulls in the whole Frida-bound
// agent), so the row's regex is read from the source text. The row is located
// by its unique `library: "Cronet",` label.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
    CRONET_PLAINTEXT_MODULE_PATTERN, FLUTTER_PLAINTEXT_MODULE_PATTERN, SIGNAL_MODULE_EXCLUDE_PATTERN, SIGNAL_MODULE_PATTERN,
    flutterPlaintextRowCovers, matchesCronetHookerPlaintextRow,
} from "../tls/shared/chromium_plaintext_coverage.js";

const ANDROID_TS = join(dirname(fileURLToPath(import.meta.url)), "android.ts");

function rowPattern(libraryLabel: string): RegExp {
    const line = readFileSync(ANDROID_TS, "utf8")
        .split("\n")
        .find((l) => l.includes(`library: "${libraryLabel}",`));
    assert.ok(line, `no android.ts row labelled "${libraryLabel}"`);
    const m = line.match(/pattern: \/(.+?)\/,/);
    assert.ok(m, `row "${libraryLabel}" has no inline regex literal`);
    return new RegExp(m[1]);
}

const primary = rowPattern("Cronet");

test("primary Cronet row matches plain, versioned and suffixed libcronet", () => {
    for (const name of ["libcronet.so", "libcronet.148.0.7778.167.so", "libcronet_x.so", "libcronet_quic.so"]) {
        assert.ok(primary.test(name), `${name} should match the primary Cronet row`);
    }
});

test("primary Cronet row keeps its exclusions", () => {
    for (const name of [
        "libmainlinecronet.140.0.so",   // own "Cronet (mainline runtime)" row
        "stable_cronet_libssl.so",      // standalone BoringSSL, owned by the libssl row
        "stable_cronet_libcrypto.so",
        "libcronetfoo.so",              // not a Cronet build name
        "libcronet.so.bak",
        "xlibcronet.so",                // anchored at the basename start
    ]) {
        assert.ok(!primary.test(name), `${name} must not match the primary Cronet row`);
    }
});

test("supplementary QUICHE row still covers libcronet.so", () => {
    assert.ok(rowPattern("Google QUICHE (Cronet)").test("libcronet.so"));
});

test("supplementary QUICHE row covers libhttpengine.so alongside its BoringSSL row", () => {
    const source = readFileSync(ANDROID_TS, "utf8");
    const quicheRow = source.split("\n").find((l) => l.includes(`library: "Google QUICHE (HttpEngine)",`));
    assert.ok(quicheRow);
    assert.match(quicheRow, /hookFn: google_quiche_execute,.*libraryType: "google_quiche", protocol: "tls", supplementary: true/);
    assert.ok(rowPattern("Google QUICHE (HttpEngine)").test("libhttpengine.so"));
    // The primary (key-extracting) row is unchanged and NOT supplementary.
    const primaryRow = source.split("\n").find((l) => l.includes(`library: "httpengine (BoringSSL)",`));
    assert.ok(primaryRow && !primaryRow.includes("supplementary"));
    assert.ok(rowPattern("httpengine (BoringSSL)").test("libhttpengine.so"));
});

test("supplementary Cronet plaintext row matches libcronet builds and stays supplementary", () => {
    const source = readFileSync(ANDROID_TS, "utf8");
    const row = source.split("\n").find((l) => l.includes(`library: "BoringSSL plaintext (Cronet)",`));
    assert.ok(row);
    assert.match(row, /hookFn: chromium_plaintext_execute,.*protocol: "tls", supplementary: true/);
    // The row shares its regex with the Cronet hooker's notice suppression.
    assert.match(row, /pattern: CRONET_PLAINTEXT_MODULE_PATTERN,/);
    const pattern = CRONET_PLAINTEXT_MODULE_PATTERN;
    for (const name of ["libcronet.so", "libcronet.143.0.7445.0.so", "libcronet.157.0.8103.14.so"]) {
        assert.ok(pattern.test(name), `${name} must match the Cronet plaintext row`);
    }
    for (const name of ["libmainlinecronet.150.so", "stable_cronet_libssl.so", "xlibcronet.so"]) {
        assert.ok(!pattern.test(name), `${name} must not match the Cronet plaintext row`);
    }
});

test("supplementary Flutter plaintext row routes libflutter.so to chromium_plaintext_execute", () => {
    const source = readFileSync(ANDROID_TS, "utf8");
    const row = source.split("\n").find((l) => l.includes(`library: "BoringSSL plaintext (Flutter)",`));
    assert.ok(row);
    assert.match(row, /hookFn: chromium_plaintext_execute,.*protocol: "tls", supplementary: true/);
    assert.match(row, /pattern: FLUTTER_PLAINTEXT_MODULE_PATTERN,/);
    assert.ok(FLUTTER_PLAINTEXT_MODULE_PATTERN.test("libflutter.so"));
    for (const name of ["libapp.so", "libflutter.so.bak", "xlibflutter.so"]) {
        assert.ok(!FLUTTER_PLAINTEXT_MODULE_PATTERN.test(name), `${name} must not match the Flutter plaintext row`);
    }
    // The key-extracting Flutter row is unchanged and NOT supplementary.
    const primaryRow = source.split("\n").find((l) => l.includes(`library: "Flutter BoringSSL",`));
    assert.ok(primaryRow && !primaryRow.includes("supplementary"));
});

test("flutterPlaintextRowCovers: arm64 libflutter.so only", () => {
    assert.equal(flutterPlaintextRowCovers("libflutter.so", "arm64"), true);
    assert.equal(flutterPlaintextRowCovers("libflutter.so", "x64"), false);
    assert.equal(flutterPlaintextRowCovers("libapp.so", "arm64"), false);
});

test("supplementary Signal plaintext row routes libsignal_jni.so to chromium_plaintext_execute", () => {
    const source = readFileSync(ANDROID_TS, "utf8");
    const row = source.split("\n").find((l) => l.includes(`library: "BoringSSL plaintext (Signal)",`));
    assert.ok(row);
    assert.match(row, /hookFn: chromium_plaintext_execute,.*protocol: "tls", supplementary: true/);
    assert.match(row, /pattern: SIGNAL_MODULE_PATTERN,/);
    // Keys stay with the "Cronet (Signal)" row, which matches the same modules.
    const keylogRow = source.split("\n").find((l) => l.includes(`library: "Cronet (Signal)",`));
    assert.ok(keylogRow);
    assert.match(keylogRow, /pattern: SIGNAL_MODULE_PATTERN,/);
});

test("SIGNAL_MODULE_PATTERN: libsignal_jni, ABI-suffixed and versioned builds, not the _testing build", () => {
    for (const name of ["libsignal_jni.so", "libsignal_jni_arm64.so", "libsignal_jni.12.so"]) {
        assert.ok(SIGNAL_MODULE_PATTERN.test(name), name);
    }
    for (const name of ["libsignal_jni_testing.so", "libringrtc_rffi.so"]) {
        assert.ok(!SIGNAL_MODULE_PATTERN.test(name), `${name} must not match the Signal rows`);
    }
});

test("both Signal rows keep the _testing exclusion", () => {
    const source = readFileSync(ANDROID_TS, "utf8");
    for (const library of ["Cronet (Signal)", "BoringSSL plaintext (Signal)"]) {
        const row = source.split("\n").find((l) => l.includes(`library: "${library}",`));
        assert.ok(row, library);
        assert.match(row, /excludePattern: SIGNAL_MODULE_EXCLUDE_PATTERN,/);
    }
    assert.ok(SIGNAL_MODULE_EXCLUDE_PATTERN.test("libsignal_jni_arm64_testing.so"));
    assert.ok(!SIGNAL_MODULE_EXCLUDE_PATTERN.test("libsignal_jni_arm64.so"));
});

test("matchesCronetHookerPlaintextRow: Cronet and libsignal_jni, not Flutter or mainline", () => {
    for (const name of ["libcronet.so", "libcronet.143.0.so", "libsignal_jni.so", "libsignal_jni_arm64.so"]) {
        assert.equal(matchesCronetHookerPlaintextRow(name), true, name);
    }
    for (const name of ["libflutter.so", "libmainlinecronet.150.so", "libsignal_jni_testing.so", "libsignal_jni_arm64_testing.so"]) {
        assert.equal(matchesCronetHookerPlaintextRow(name), false, name);
    }
});
