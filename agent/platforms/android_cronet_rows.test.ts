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
