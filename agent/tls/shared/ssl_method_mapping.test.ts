// Unit tests for the shared OpenSSL_BoringSSL method-mapping helpers
// (agent/tls/shared/ssl_method_mapping.ts) and the legacy re-export
// (agent/legacy/tls/libs/ssl_method_mapping.ts). Behavioural coverage of the
// gate itself lives in agent/legacy/tls/libs/ssl_method_mapping.test.ts, which
// now exercises this implementation through the re-export.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import * as shared from "./ssl_method_mapping.js";
import * as legacy from "../../legacy/tls/libs/ssl_method_mapping.js";

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const read = (p: string) => readFileSync(resolve(AGENT, p), "utf8");

test("legacy module re-exports the exact shared functions (same identity)", () => {
    assert.deepEqual(Object.keys(legacy).sort(), Object.keys(shared).sort());
    for (const name of Object.keys(shared) as Array<keyof typeof shared>) {
        assert.equal(legacy[name], shared[name], name);
    }
});

test("shared helpers behave identically through both import paths", () => {
    assert.deepEqual(
        legacy.buildDefaultSslMethodMapping("libssl.so", "libc.so", 10),
        shared.buildDefaultSslMethodMapping("libssl.so", "libc.so", 10));
    assert.equal(legacy.hasResolvableSslSurface("libx.so", 1), shared.hasResolvableSslSurface("libx.so", 1));
});

test("modern openssl_boringssl imports the shared mapping, not agent/legacy/**", () => {
    const src = read("tls/libs/openssl_boringssl.ts");
    assert.match(src, /from\s+"\.\.\/shared\/ssl_method_mapping\.js"/);
    assert.doesNotMatch(src, /from\s+"[^"]*\/legacy\//);
});

test("legacy openssl_boringssl keeps its legacy import path (re-export)", () => {
    assert.match(read("legacy/tls/libs/openssl_boringssl.ts"), /from\s+"\.\/ssl_method_mapping\.js"/);
});

test("the shared implementation imports nothing from agent/legacy/**", () => {
    assert.doesNotMatch(read("tls/shared/ssl_method_mapping.ts"), /from\s+"[^"]*\/legacy\//);
});
