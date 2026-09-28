// Unit tests for the legacy OpenSSL_BoringSSL method-mapping gate
// (agent/legacy/tls/libs/ssl_method_mapping.ts).
//
// Run: npm run test:agent
//
// Why this exists: libhttpengine.so (tethering APEX) exports only JNI_OnLoad.
// The legacy gate was `checkNumberOfExports() > 2` alone, so the SSL_* mapping
// was never created, deep symbol resolution never ran, and the following
// `.push("SSL_CTX_new")` on the missing key was a latent TypeError.

import { test } from "node:test";
import assert from "node:assert/strict";
import { enableDeepSymbolResolution } from "../../../shared/deep_symbol_resolution.js";
import { buildDefaultSslMethodMapping, addModuleMethod, hasResolvableSslSurface, isResolvedAddress } from "./ssl_method_mapping.js";

test("deep resolution with a single export still creates the SSL mapping", () => {
    enableDeepSymbolResolution("libhttpengine.so");
    const mapping = buildDefaultSslMethodMapping("libhttpengine.so", "libc.so", 1);
    assert.ok(mapping["*libhttpengine.so*"]?.includes("SSL_CTX_set_keylog_callback"));
    assert.deepEqual(mapping["*libc.so*"], ["getpeername", "getsockname", "ntohs", "ntohl"]);
});

test("without deep resolution a module with <= 2 exports gets no SSL mapping", () => {
    assert.equal(hasResolvableSslSurface("libfew_exports.so", 2), false);
    const mapping = buildDefaultSslMethodMapping("libfew_exports.so", "libc.so", 2);
    assert.equal(mapping["*libfew_exports.so*"], undefined);
    assert.ok(mapping["*libc.so*"]);
});

test("enough dynamic exports create the mapping as before", () => {
    assert.ok(buildDefaultSslMethodMapping("libssl.so", "libc.so", 3)["*libssl.so*"]);
});

test("addModuleMethod skips a missing module key instead of throwing", () => {
    const mapping = buildDefaultSslMethodMapping("libfew_exports.so", "libc.so", 0);
    assert.equal(addModuleMethod(mapping, "libfew_exports.so", "SSL_CTX_new"), false);
    assert.equal(mapping["*libfew_exports.so*"], undefined);
});

test("addModuleMethod appends to an existing entry", () => {
    const mapping = buildDefaultSslMethodMapping("libssl.so", "libc.so", 10);
    assert.equal(addModuleMethod(mapping, "libssl.so", "SSL_read_ex"), true);
    assert.equal(mapping["*libssl.so*"].at(-1), "SSL_read_ex");
});

test("fresh mappings do not share method arrays", () => {
    const a = buildDefaultSslMethodMapping("libssl.so", "libc.so", 10);
    addModuleMethod(a, "libssl.so", "SSL_write_ex");
    const b = buildDefaultSslMethodMapping("libssl.so", "libc.so", 10);
    assert.ok(!b["*libssl.so*"].includes("SSL_write_ex"));
});

// A2: the constructor's read/write-NativeFunction gate now uses the same
// predicate as the mapping gate, so a deep-resolved module with <= 2 dynsym
// exports (libhttpengine.so) gets plaintext hooks, not keys only.
test("deep-resolved module passes the read/write gate despite <= 2 exports", () => {
    enableDeepSymbolResolution("libhttpengine_rw.so");
    assert.equal(hasResolvableSslSurface("libhttpengine_rw.so", 1), true);
    assert.equal(hasResolvableSslSurface("libhttpengine_rw.so", 0), true);
});

test("isResolvedAddress rejects undefined, null and NULL pointers", () => {
    const ptrLike = (isNull: boolean) => ({ isNull: () => isNull });
    assert.equal(isResolvedAddress(undefined), false);
    assert.equal(isResolvedAddress(null), false);
    assert.equal(isResolvedAddress(ptrLike(true)), false);
    assert.equal(isResolvedAddress(ptrLike(false)), true);
});
