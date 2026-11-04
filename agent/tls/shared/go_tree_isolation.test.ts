// Static import-graph check: the modern Go executor (--modern) is self-contained in the
// modern tree. Two hook paths coexist until they are merged — legacy (agent/legacy/**) and
// modern (agent/tls/**, agent/core/**) — and neither may borrow the other's hookers.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const MODERN_GO_PLATFORM_ENTRIES = [
    "tls/platforms/linux/gotls_linux.ts",
    "tls/platforms/android/gotls_android.ts",
    "tls/platforms/macos/gotls_macos.ts",
    "tls/platforms/windows/gotls_windows.ts",
];
const MODERN_GO_ENTRIES = [
    ...MODERN_GO_PLATFORM_ENTRIES,
    "tls/definitions/gotls.ts",
    "tls/libs/gotls.ts",
];
const LEGACY_GO_ENTRIES = [
    "legacy/tls/platforms/linux/gotls_linux.ts",
    "legacy/tls/platforms/android/gotls_android.ts",
    "legacy/tls/platforms/macos/gotls_macos.ts",
    "legacy/tls/platforms/windows/gotls_windows.ts",
    "legacy/tls/libs/gotls.ts",
    "legacy/tls/libs/gotls_native.ts",
];

/** Relative imports of an agent source file, as agent-relative .ts paths. */
function importsOf(file: string): string[] {
    const src = readFileSync(join(AGENT, file), "utf8");
    const specs = [...src.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+["'](\.[^"']+)["']/gms)].map((m) => m[1]);
    return specs.map((s) => relative(AGENT, resolve(AGENT, dirname(file), s.replace(/\.js$/, ".ts"))))
        .filter((p) => existsSync(join(AGENT, p)));
}

/** Transitive imports from `entries`, following only edges that stay inside `tree`. */
function closure(entries: string[], tree: (p: string) => boolean): Map<string, string[]> {
    const edges = new Map<string, string[]>();
    const todo = [...entries];
    while (todo.length) {
        const file = todo.pop()!;
        if (edges.has(file)) continue;
        const deps = importsOf(file);
        edges.set(file, deps);
        todo.push(...deps.filter(tree));
    }
    return edges;
}

const isLegacy = (p: string) => p.startsWith("legacy/");
const isModernTls = (p: string) => p.startsWith("tls/") || p.startsWith("core/");

test("modern Go executor: no file in its modern-tree import closure imports agent/legacy/**", () => {
    const offenders: string[] = [];
    for (const [file, deps] of closure(MODERN_GO_ENTRIES, isModernTls)) {
        if (!/go|gotls/i.test(file)) continue; // other libs' cross-tree imports are reported separately
        for (const dep of deps.filter(isLegacy)) offenders.push(`${file} -> ${dep}`);
    }
    assert.deepEqual(offenders, []);
});

test("modern Go executors fall back to the modern class (tls/libs/gotls.ts), not the legacy executor", () => {
    for (const entry of MODERN_GO_PLATFORM_ENTRIES) {
        const deps = importsOf(entry);
        assert.ok(deps.includes("tls/libs/gotls.ts"), `${entry} uses the modern GoTLS class`);
        assert.deepEqual(deps.filter(isLegacy), [], `${entry} imports nothing from agent/legacy`);
    }
});

test("legacy Go executors use only the legacy GoTLS class (no modern-tree hooker)", () => {
    for (const entry of LEGACY_GO_ENTRIES) {
        const deps = importsOf(entry);
        const modernHookers = deps.filter((p) => p.startsWith("tls/libs/") || p.startsWith("tls/platforms/") || p.startsWith("tls/definitions/"));
        assert.deepEqual(modernHookers, [], `${entry} imports a modern-tree hooker`);
    }
});

test("legacy Go executors' import closure stays in agent/legacy/** plus shared helpers (never a modern hooker)", () => {
    const offenders: string[] = [];
    for (const [file, deps] of closure(LEGACY_GO_ENTRIES, isLegacy)) {
        for (const dep of deps) {
            if (/^tls\/(libs|platforms|definitions)\//.test(dep) || dep.startsWith("core/")) offenders.push(`${file} -> ${dep}`);
        }
    }
    assert.deepEqual(offenders, []);
});

test("every Go entry file exists (the lists above track real files)", () => {
    for (const entry of [...MODERN_GO_ENTRIES, ...LEGACY_GO_ENTRIES]) assert.ok(existsSync(join(AGENT, entry)), entry);
});
