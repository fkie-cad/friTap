// Static import-graph check for the whole modern TLS tree (agent/tls/**, agent/core/**).
// Two hook paths coexist until they are merged — legacy (default; agent/legacy/**) and
// modern (--modern; agent/tls/**, agent/core/**) — and the modern one must not borrow
// legacy hookers. Shared helpers (agent/shared/**, agent/util/**) are fine.
// go_tree_isolation.test.ts holds the Go-specific checks; this file generalises them.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");

// TODO(modern-merge): the modern platform files below are still thin re-export shims of the
// legacy executor (no modern implementation yet). Remove an entry once its library gets a
// self-contained modern path (as Go and rustls did); the test fails on stale entries.
const KNOWN_LEGACY_SHIMS = [
    "tls/platforms/android/android_java_tls_libs.ts -> legacy/tls/platforms/android/android_java_tls_libs.ts",
    "tls/platforms/android/bouncycastle.ts -> legacy/tls/platforms/android/bouncycastle.ts",
    "tls/platforms/android/conscrypt.ts -> legacy/tls/platforms/android/conscrypt.ts",
    "tls/platforms/android/flutter_android.ts -> legacy/tls/platforms/android/flutter_android.ts",
    "tls/platforms/android/metartc.ts -> legacy/tls/platforms/android/metartc.ts",
    "tls/platforms/android/mono_btls_android.ts -> legacy/tls/platforms/android/mono_btls_android.ts",
    "tls/platforms/android/pattern_android.ts -> legacy/tls/platforms/android/pattern_android.ts",
    "tls/platforms/ios/cronet_ios.ts -> legacy/tls/platforms/ios/cronet_ios.ts",
    "tls/platforms/ios/flutter_ios.ts -> legacy/tls/platforms/ios/flutter_ios.ts",
    "tls/platforms/linux/cronet_linux.ts -> legacy/tls/platforms/linux/cronet_linux.ts",
    "tls/platforms/linux/matrixssl_linux.ts -> legacy/tls/platforms/linux/matrixssl_linux.ts",
    "tls/platforms/macos/cronet_macos.ts -> legacy/tls/platforms/macos/cronet_macos.ts",
    "tls/platforms/windows/cronet_windows.ts -> legacy/tls/platforms/windows/cronet_windows.ts",
    "tls/platforms/windows/lsass.ts -> legacy/tls/platforms/windows/lsass.ts",
    "tls/platforms/windows/matrixssl_windows.ts -> legacy/tls/platforms/windows/matrixssl_windows.ts",
    "tls/platforms/windows/sspi.ts -> legacy/tls/platforms/windows/sspi.ts",
];

/** Libraries whose modern path is self-contained: no exception may name them. */
const SELF_CONTAINED = /rustls|gotls|go_/i;

const isLegacy = (p: string) => p.startsWith("legacy/");

/** Relative imports of an agent source file, as agent-relative .ts paths. */
function importsOf(file: string): string[] {
    const src = readFileSync(join(AGENT, file), "utf8");
    const specs = [...src.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+["'](\.[^"']+)["']/gms)].map((m) => m[1]);
    return specs.map((s) => relative(AGENT, resolve(AGENT, dirname(file), s.replace(/\.js$/, ".ts"))))
        .filter((p) => existsSync(join(AGENT, p)));
}

/** Non-test .ts sources under an agent-relative directory. */
function sourcesUnder(dir: string): string[] {
    return readdirSync(join(AGENT, dir), { withFileTypes: true, recursive: true })
        .filter((e) => e.isFile() && e.name.endsWith(".ts") && !e.name.endsWith(".test.ts"))
        .map((e) => relative(AGENT, join(e.parentPath ?? (e as any).path, e.name)))
        .sort();
}

function modernToLegacyEdges(): string[] {
    const edges: string[] = [];
    for (const file of [...sourcesUnder("tls"), ...sourcesUnder("core")]) {
        for (const dep of importsOf(file).filter(isLegacy)) edges.push(`${file} -> ${dep}`);
    }
    return edges.sort();
}

test("modern TLS tree: the only imports of agent/legacy/** are the listed re-export shims", () => {
    assert.deepEqual(modernToLegacyEdges(), [...KNOWN_LEGACY_SHIMS].sort());
});

test("self-contained modern libraries (rustls, Go) are not on the shim list", () => {
    assert.deepEqual(KNOWN_LEGACY_SHIMS.filter((e) => SELF_CONTAINED.test(e)), []);
});

test("modern rustls executors use the modern definition and RusTLS class; legacy rows the legacy class", () => {
    for (const plat of ["linux", "android"]) {
        const modern = importsOf(`tls/platforms/${plat}/rustls_${plat}.ts`);
        assert.ok(modern.includes("tls/definitions/rustls.ts"), `${plat}: modern definition`);
        assert.ok(modern.includes("tls/libs/rustls.ts"), `${plat}: modern RusTLS class-based fallback`);
        assert.deepEqual(modern.filter(isLegacy), [], `${plat}: modern rustls imports nothing from agent/legacy`);

        const legacy = importsOf(`legacy/tls/platforms/${plat}/rustls_${plat}.ts`);
        const modernHookers = legacy.filter((p) => /^tls\/(libs|platforms|definitions)\//.test(p));
        assert.deepEqual(modernHookers, [], `${plat}: legacy rustls imports a modern-tree hooker`);
        assert.ok(legacy.includes("legacy/tls/libs/rustls.ts"), `${plat}: legacy rustls uses the legacy RusTLS`);

        // The platform row table wires each path to its own tree (no modern re-export of legacy).
        const rows = importsOf(`platforms/${plat}.ts`);
        assert.ok(rows.includes(`legacy/tls/platforms/${plat}/rustls_${plat}.ts`), `${plat}.ts imports the legacy executor directly`);
        assert.ok(rows.includes(`tls/platforms/${plat}/rustls_${plat}.ts`), `${plat}.ts imports the modern executor`);
    }
});
