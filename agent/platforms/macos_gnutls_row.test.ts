// Unit test for the macOS GnuTLS registry row (agent/platforms/macos.ts).
//
// Run: npm run test:agent
//
// WHY: macOS had no GnuTLS row at all, so a Homebrew-GnuTLS client (gnutls-cli, wget,
// anything linking libgnutls.30.dylib) was never hooked in either mode. macos.ts cannot
// be imported under Node (it pulls in the whole Frida-bound agent), so the row's regex
// is read from the source text, located by its unique `library: "GnuTLS",` label.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const MACOS_TS = join(dirname(fileURLToPath(import.meta.url)), "macos.ts");
const row = readFileSync(MACOS_TS, "utf8").split("\n").find((l) => l.includes('library: "GnuTLS",'));

test("macOS has a GnuTLS row with both executors", () => {
    assert.ok(row, 'no macos.ts row labelled "GnuTLS"');
    assert.match(row!, /use_modern \? gnutls_execute_modern : gnutls_execute/);
    assert.match(row!, /libraryType: "gnutls"/);
});

test("the GnuTLS row matches libgnutls dylibs but not the C++ wrapper", () => {
    const pattern = new RegExp(row!.match(/pattern: \/(.+?)\/,/)![1]);
    for (const name of ["libgnutls.30.dylib", "libgnutls.dylib", "/opt/homebrew/opt/gnutls/lib/libgnutls.30.dylib"]) {
        assert.ok(pattern.test(name), `${name} should match`);
    }
    for (const name of ["libgnutlsxx.30.dylib", "libgnutls-dane.0.dylib", "libgnutls.so.30"]) {
        assert.ok(!pattern.test(name), `${name} must not match`);
    }
});
