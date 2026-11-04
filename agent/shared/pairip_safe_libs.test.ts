// Unit tests for the --pairip-safe allowlist (agent/shared/pairip_safe_libs.ts)
// and its per-hook-path executor binding (agent/platforms/android.ts).
//
// Run: npm run test:agent
//
// The allowlist names executor FAMILIES; android.ts injects the legacy table by
// default and the modern table under --modern. agent/shared must not import
// agent/legacy/** (nor the modern hookers) -- the two paths stay separate.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildPairipSafeRegistrations, matchPairipSafeLib, PAIRIP_SAFE_LIBS, PairipExecutorKey, PairipExecutorTable } from "./pairip_safe_libs.js";

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p: string) => readFileSync(resolve(AGENT, p), "utf8");
const KEYS: PairipExecutorKey[] = ["boringssl", "httpengine", "conscrypt", "unity_mbedtls"];

function fakeTable(tag: string): PairipExecutorTable {
    const t = {} as PairipExecutorTable;
    for (const k of KEYS) t[k] = Object.assign(() => {}, { tag: `${tag}:${k}` });
    return t;
}

test("registrations bind every entry to the injected table's executor", () => {
    for (const tag of ["legacy", "modern"]) {
        const table = fakeTable(tag);
        const regs = buildPairipSafeRegistrations("linux", table);
        assert.equal(regs.length, PAIRIP_SAFE_LIBS.length);
        regs.forEach((r, i) => {
            assert.equal(r.hookFn, table[PAIRIP_SAFE_LIBS[i].executor]);
            assert.equal(r.pattern, PAIRIP_SAFE_LIBS[i].pattern);
            assert.equal(r.library, PAIRIP_SAFE_LIBS[i].library);
        });
    }
});

test("allowlist families match the previous per-library executor choice", () => {
    const fam = (m: string) => matchPairipSafeLib(m)?.executor;
    assert.equal(fam("libssl.so"), "boringssl");
    assert.equal(fam("libjavacrypto.so"), "boringssl");
    assert.equal(fam("libwebviewchromium.so"), "boringssl");
    assert.equal(fam("libhttpengine.so"), "httpengine");
    assert.equal(fam("libcommerce_http_client.so"), "httpengine");
    assert.equal(fam("libconscrypt_jni.so"), "conscrypt");
    assert.equal(fam("libconscrypt_gmscore_jni.so"), "conscrypt");
    assert.equal(fam("libunity.so"), "unity_mbedtls");
    assert.equal(matchPairipSafeLib("libcronet.so"), undefined);
});

test("pairip_safe_libs.ts imports no hooker from either tree", () => {
    const src = read("shared/pairip_safe_libs.ts");
    assert.doesNotMatch(src, /from\s+"[^"]*\/legacy\//);
    assert.doesNotMatch(src, /from\s+"[^"]*\/tls\/(platforms|libs)\//);
});

/** identifier -> import source, from android.ts's import lines. */
function importSources(src: string): Map<string, string> {
    const m = new Map<string, string>();
    for (const [, names, from] of src.matchAll(/import\s*\{([^}]*)\}\s*from\s*"([^"]+)"/g)) {
        for (const n of names.split(",").map((x) => x.trim()).filter(Boolean)) m.set(n, from);
    }
    return m;
}

function tableEntries(src: string, name: string): Record<string, string> {
    const body = src.match(new RegExp(`${name}: PairipExecutorTable = \\{([^}]*)\\}`))?.[1];
    assert.ok(body, `${name} found in android.ts`);
    return Object.fromEntries([...body.matchAll(/(\w+):\s*(\w+)/g)].map(([, k, v]) => [k, v]));
}

test("android.ts: legacy table uses legacy executors, modern table uses modern-tree executors", () => {
    const src = read("platforms/android.ts");
    const from = importSources(src);
    const legacy = tableEntries(src, "LEGACY_PAIRIP_EXECUTORS");
    const modern = tableEntries(src, "MODERN_PAIRIP_EXECUTORS");
    assert.deepEqual(Object.keys(legacy).sort(), [...KEYS].sort());
    assert.deepEqual(Object.keys(modern).sort(), [...KEYS].sort());
    // Same executors as before the refactor (legacy behaviour unchanged).
    assert.deepEqual(legacy, { boringssl: "boring_execute", httpengine: "httpengine_execute", conscrypt: "conscrypt_native_execute", unity_mbedtls: "unity_mbedtls_execute" });
    assert.deepEqual(modern, { boringssl: "boring_execute_modern", httpengine: "httpengine_execute_modern", conscrypt: "conscrypt_execute_modern", unity_mbedtls: "unity_mbedtls_execute_modern" });
    for (const [k, fn] of Object.entries(modern)) {
        assert.match(from.get(fn) ?? "", /^\.\.\/tls\//, `modern ${k} (${fn}) comes from agent/tls/**`);
    }
    for (const [k, fn] of Object.entries(legacy)) {
        // unity_mbedtls has a single implementation shared by both paths.
        const want = k === "unity_mbedtls" ? /^\.\.\/tls\/platforms\/android\/unity_mbedtls_android\.js$/ : /^\.\.\/legacy\//;
        assert.match(from.get(fn) ?? "", want, `legacy ${k} (${fn})`);
    }
    assert.match(src, /buildPairipSafeRegistrations\(plattform_name, pairipSafeExecutors\(use_modern\)\)/);
    assert.match(src, /return modern \? MODERN_PAIRIP_EXECUTORS : LEGACY_PAIRIP_EXECUTORS;/);
});
