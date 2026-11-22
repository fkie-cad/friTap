// Unit tests for the pure/arch-neutral parts of nss_keylog_locator.ts: writer
// selection, label/version/shape helpers, miss fingerprint, backend registry.
// (The Interceptor hook and scan paths have no injection seam; see report.)
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import {
    isKnownLabel, isSecItemShape, NSS_DIRECT_WRITER_LABELS, NSS_KEYLOG_LABELS, NSS_KEYLOG_WRITER_MISS_FINGERPRINT,
    NSS_TLS13_LABELS, nssLocatorBackendFor, parseNssVersion, pickKeylogWriter, SECITEM_MAX_LEN, secretSourceFor,
    writerTakesSecItem, LABEL_MISMATCH_LIMIT, learnedWriterVerdict,
} from "./nss_keylog_locator.js";
import { missFingerprint } from "./learned_module_cache.js";
import { DECODE_UNREADABLE } from "./keylog_guards.js";
import { arm64NssLocatorBackend } from "./nss_keylog_backend_arm64.js";

// ---- pickKeylogWriter ---------------------------------------------------------

const decodeOnly = (...ok: string[]) => (c: string) => (ok.includes(c) ? { clientRandomOff: 0x650 } : null);

test("exactly one decoding candidate is picked", () => {
    const picked = pickKeylogWriter(["a", "b", "c"], decodeOnly("b"));
    assert.deepEqual(picked, { candidate: "b", decoded: { clientRandomOff: 0x650 } });
});

test("no decoding candidate and an empty list yield null", () => {
    assert.equal(pickKeylogWriter(["a", "b"], decodeOnly()), null);
    assert.equal(pickKeylogWriter([], decodeOnly("a")), null);
});

test("two distinct decoding candidates are ambiguous -> null", () => {
    assert.equal(pickKeylogWriter(["a", "b", "c"], decodeOnly("a", "c")), null);
});

test("duplicates of the same candidate count once", () => {
    const picked = pickKeylogWriter(["a", "b", "a", "a"], decodeOnly("a"));
    assert.equal(picked?.candidate, "a");
});

test("duplicates are decided by keyOf, not identity", () => {
    const objs = [{ id: "x" }, { id: "x" }];
    const picked = pickKeylogWriter(objs, () => ({ clientRandomOff: 8 }), (o) => o.id);
    assert.equal(picked?.candidate, objs[0]);
    assert.equal(pickKeylogWriter(objs, () => ({ clientRandomOff: 8 }), (o) => o.id + Math.random()), null);
});

test("a depth-1 candidate decoding while the direct one does not is picked", () => {
    // writerCandidates() puts direct callees first, then their depth-1 callees.
    const picked = pickKeylogWriter(["direct", "depth1"], decodeOnly("depth1"));
    assert.equal(picked?.candidate, "depth1");
});

// ---- TLS 1.3 votes ------------------------------------------------------------

test("only CLIENT_RANDOM/ECH_SECRET/ECH_CONFIG are direct writer labels", () => {
    assert.deepEqual([...NSS_DIRECT_WRITER_LABELS], ["CLIENT_RANDOM", "ECH_SECRET", "ECH_CONFIG"]);
});

test("NSS_KEYLOG_LABELS lists the direct labels first, so slice(0, 3) feeds candidates", () => {
    assert.deepEqual(NSS_KEYLOG_LABELS.slice(0, NSS_DIRECT_WRITER_LABELS.length), [...NSS_DIRECT_WRITER_LABELS]);
    assert.deepEqual(NSS_KEYLOG_LABELS.slice(NSS_DIRECT_WRITER_LABELS.length), [...NSS_TLS13_LABELS]);
    assert.equal(NSS_TLS13_LABELS.length, 7);
});

// ---- isKnownLabel -------------------------------------------------------------

test("isKnownLabel accepts all 10 labels", () => {
    assert.equal(NSS_KEYLOG_LABELS.length, 10);
    for (const l of NSS_KEYLOG_LABELS) assert.equal(isKnownLabel(l), true, l);
});

test("isKnownLabel rejects null, empty, near-misses and lowercase", () => {
    for (const l of [null, "", "CLIENT_RANDOMX", "client_random", "CLIENT_RANDO", " CLIENT_RANDOM"]) {
        assert.equal(isKnownLabel(l), false, String(l));
    }
});

// ---- isSecItemShape -----------------------------------------------------------

test("isSecItemShape accepts readable data with len 1..512", () => {
    for (const len of [1, 48, SECITEM_MAX_LEN]) assert.equal(isSecItemShape(true, len), true, String(len));
});

test("isSecItemShape rejects 0, 513, null len and unreadable data", () => {
    assert.equal(isSecItemShape(true, 0), false);
    assert.equal(isSecItemShape(true, SECITEM_MAX_LEN + 1), false);
    assert.equal(isSecItemShape(true, null), false);
    assert.equal(isSecItemShape(false, 48), false);
});

// ---- parseNssVersion / writerTakesSecItem -------------------------------------

test("parseNssVersion parses major.minor and ignores the rest", () => {
    assert.deepEqual(parseNssVersion("3.132"), { major: 3, minor: 132 });
    assert.deepEqual(parseNssVersion("3.90.1 Basic ECC"), { major: 3, minor: 90 });
    assert.deepEqual(parseNssVersion("  3.115 "), { major: 3, minor: 115 });
});

test("parseNssVersion returns null for null, empty and garbage", () => {
    for (const t of [null, "", "abc", "3", ".5"]) assert.equal(parseNssVersion(t), null, String(t));
});

test("writerTakesSecItem switches at 3.115", () => {
    assert.equal(writerTakesSecItem({ major: 3, minor: 114 }), false);
    assert.equal(writerTakesSecItem({ major: 3, minor: 115 }), true);
    assert.equal(writerTakesSecItem({ major: 3, minor: 132 }), true);
    assert.equal(writerTakesSecItem({ major: 4, minor: 0 }), true);
});

// ---- secretSourceFor ----------------------------------------------------------

test("secretSourceFor matrix", () => {
    const v114 = { major: 3, minor: 114 };
    const v132 = { major: 3, minor: 132 };
    assert.equal(secretSourceFor(null, true), "secitem");
    assert.equal(secretSourceFor(null, false), null);
    assert.equal(secretSourceFor(v132, true), "secitem");
    assert.equal(secretSourceFor(v132, false), null);
    assert.equal(secretSourceFor(v114, true), null);
    assert.equal(secretSourceFor(v114, false), "symkey");
});

// ---- miss fingerprint ---------------------------------------------------------

test("miss fingerprint equals the revision-1 fingerprint and changes with the revision", () => {
    assert.equal(NSS_KEYLOG_WRITER_MISS_FINGERPRINT, missFingerprint([...NSS_KEYLOG_LABELS, "revision", "1"]));
    assert.notEqual(NSS_KEYLOG_WRITER_MISS_FINGERPRINT, missFingerprint([...NSS_KEYLOG_LABELS, "revision", "2"]));
});

// ---- backend registry ---------------------------------------------------------

test("nssLocatorBackendFor returns the arm64 backend and null for unknown arches", () => {
    const backend = nssLocatorBackendFor("arm64");
    assert.equal(backend, arm64NssLocatorBackend);
    assert.equal(backend?.name, "arm64");
    assert.equal(backend?.deviceVerified, true);
    assert.equal(nssLocatorBackendFor("mips"), null);
});

test("LABEL_MISMATCH_LIMIT is a small positive integer", () => {
    assert.ok(Number.isInteger(LABEL_MISMATCH_LIMIT) && LABEL_MISMATCH_LIMIT > 1);
});

// ---- learnedWriterVerdict -----------------------------------------------------

test("learnedWriterVerdict: cached and decodable is a hit carrying the cached entry", () => {
    assert.deepEqual(learnedWriterVerdict("fn", () => ({ clientRandomOff: 1 })),
        { kind: "hit", cached: "fn", decoded: { clientRandomOff: 1 } });
});

test("learnedWriterVerdict: cached, read in full, but undecodable is stale", () => {
    assert.deepEqual(learnedWriterVerdict("fn", () => null), { kind: "stale" });
});

test("learnedWriterVerdict: a cached entry that could not be read is unreadable (kept, not stale)", () => {
    assert.deepEqual(learnedWriterVerdict("fn", () => DECODE_UNREADABLE), { kind: "unreadable" });
});

test("learnedWriterVerdict: no cache means none, without decoding", () => {
    assert.deepEqual(learnedWriterVerdict<string, number>(null, () => { throw new Error("decoded"); }), { kind: "none" });
});

test("a miss recorded under an old fingerprint is not the current fingerprint (revision bump)", () => {
    const oldFingerprint = missFingerprint([...NSS_KEYLOG_LABELS, "revision", "0"]);
    assert.notEqual(oldFingerprint, NSS_KEYLOG_WRITER_MISS_FINGERPRINT);
});

test("nssLocatorBackendFor is safe against Object.prototype names", () => {
    for (const name of ["toString", "constructor", "__proto__", "hasOwnProperty"]) {
        assert.equal(nssLocatorBackendFor(name), null);
    }
});


test("x64 backend is registered as untested-abi; arm is device-verified", () => {
    for (const [arch, name, verified] of [["x64", "x64", false], ["arm", "arm", true]] as const) {
        const backend = nssLocatorBackendFor(arch);
        assert.ok(backend, `${arch} backend registered`);
        assert.equal(backend!.name, name);
        assert.equal(backend!.deviceVerified, verified);
    }
    assert.equal(nssLocatorBackendFor("ia32"), null); // no x86 Fenix build exists: no backend
});
