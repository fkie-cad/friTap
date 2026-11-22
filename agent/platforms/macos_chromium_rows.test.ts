// Unit test for the macOS Chrome / Electron registry rows (agent/platforms/macos.ts).
//
// Run: npm run test:agent
//
// macos.ts cannot be imported under Node (it pulls in the Frida-bound agent), so
// the rows are read from the source text by their unique `library:` labels.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { CHROMIUM_FRAMEWORK_MODULE_PATTERN } from "../tls/shared/chromium_plaintext_coverage.js";

const MACOS_TS = join(dirname(fileURLToPath(import.meta.url)), "macos.ts");

function rowLine(libraryLabel: string): string {
    const line = readFileSync(MACOS_TS, "utf8").split("\n").find((l) => l.includes(`library: "${libraryLabel}",`));
    assert.ok(line, `no macos.ts row labelled "${libraryLabel}"`);
    return line;
}

test("CHROMIUM_FRAMEWORK_MODULE_PATTERN: Chrome and Electron framework binaries only", () => {
    for (const name of ["Google Chrome Framework", "Electron Framework"]) {
        assert.ok(CHROMIUM_FRAMEWORK_MODULE_PATTERN.test(name), name);
    }
    for (const name of ["Google Chrome Helper (Aperitif)", "Google Chrome", "Electron", "Squirrel",
                        "Google Chrome Framework.framework", "libEGL.dylib", "XElectron Framework"]) {
        assert.ok(!CHROMIUM_FRAMEWORK_MODULE_PATTERN.test(name), name);
    }
});

test("keylog row: primary (not supplementary) tier-4 executor on the framework pattern", () => {
    const line = rowLine("BoringSSL (Chromium Framework)");
    assert.match(line, /pattern: CHROMIUM_FRAMEWORK_MODULE_PATTERN,/);
    assert.match(line, /hookFn: chromium_boringssl_hook\(false\)/);
    assert.match(line, /libraryType: "boringssl"/);
    assert.doesNotMatch(line, /supplementary/);
});

test("plaintext and QUICHE rows: supplementary on the framework pattern", () => {
    for (const [label, fn] of [["BoringSSL plaintext (Chromium Framework)", "chromium_plaintext_execute"],
                               ["Google QUICHE (Chrome)", "google_quiche_execute"]]) {
        const line = rowLine(label);
        assert.match(line, /pattern: CHROMIUM_FRAMEWORK_MODULE_PATTERN,/, label);
        assert.match(line, new RegExp(`hookFn: ${fn},`), label);
        assert.match(line, /supplementary: true/, label);
    }
});
