// Unit tests for the shared LibreSSL KDF locator's shipped data.
//
// Run: npm run test:agent
//
// No Frida runtime is needed to validate the bundled signatures and the raw-
// label -> NSS-label mapping, which are the parts most prone to silent
// regressions (a mistyped byte or a dropped label yields no keys at runtime
// with no error). The address-resolution logic (findLibreSslKdfAddresses) needs
// a live module and is exercised end-to-end, not here.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

import { BUNDLED_LIBRESSL_KDF } from "./libressl_kdf.js";
import { TLS13_LABEL_MAP } from "../tls/definitions/shared_constants.js";

const HEX_PATTERN = /^([0-9A-Fa-f]{2}|\?\?|\?)( ([0-9A-Fa-f]{2}|\?\?|\?))*$/;

test("BUNDLED_LIBRESSL_KDF ships x64 signatures for the KDF functions", () => {
    const x64 = BUNDLED_LIBRESSL_KDF["x64"];
    assert.ok(x64, "x64 bundle present");
    for (const kind of ["hkdfWithLen", "prf"] as const) {
        const pat = x64[kind];
        assert.ok(typeof pat === "string" && pat.length > 0, `${kind} pattern present`);
        assert.match(pat as string, HEX_PATTERN, `${kind} is space-separated hex`);
        // All three LibreSSL prologues begin with endbr64 (F3 0F 1E FA).
        assert.ok((pat as string).startsWith("F3 0F 1E FA"), `${kind} starts with endbr64`);
    }
    // The signatures must be distinct functions.
    const vals = [x64.hkdfWithLen, x64.prf];
    assert.equal(new Set(vals).size, 2, "distinct signatures");
});

test("TLS13_LABEL_MAP maps every raw LibreSSL label to an NSS keylog label", () => {
    // LibreSSL passes these raw labels to tls13_hkdf_expand_label; Wireshark
    // expects the mapped NSS names.
    assert.equal(TLS13_LABEL_MAP["c hs traffic"], "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(TLS13_LABEL_MAP["s hs traffic"], "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(TLS13_LABEL_MAP["c ap traffic"], "CLIENT_TRAFFIC_SECRET_0");
    assert.equal(TLS13_LABEL_MAP["s ap traffic"], "SERVER_TRAFFIC_SECRET_0");
    assert.equal(TLS13_LABEL_MAP["exp master"], "EXPORTER_SECRET");
});
