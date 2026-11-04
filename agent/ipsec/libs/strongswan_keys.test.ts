// Unit tests for the pure helpers in strongswan_keys.ts (IKEv2 + ESP key
// extraction). No Frida runtime, no device — only the pure message builders,
// the anchor sets and the constants are pinned here. The Frida installers
// (locator wiring, dbg hook, add_sa struct reads) are covered by the Docker
// two-container tshark-decryption e2e.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines the Frida globals the module graph touches at load.
import "../../shared/frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

import {
    IKE_FUNC_ANCHORS, ESP_FUNC_ANCHORS, IKE_KEY_LITERALS,
    TRANSFORM_TYPE, PROTO_ESP, IKE_SA_ID_SLOT, PROPOSAL_GET_ALGORITHM_SLOT,
    buildIkeMessage, buildEspMessage, type IkeDerivation,
} from "./strongswan_keys.js";

// ---- anchors ---------------------------------------------------------------

test("IKE anchors are the five IKEv2-only literals that co-locate in derive_ike_keys", () => {
    const texts = IKE_FUNC_ANCHORS.map((a) => a.text);
    assert.deepEqual(texts, [
        "SKEYSEED %B",
        "Sk_ei secret %B",
        "Sk_er secret %B",
        "Sk_ai secret %B",
        "Sk_ar secret %B",
    ]);
});

test("IKE anchors exclude literals shared with derive_ike_keys_ppk or keymat_v1", () => {
    // "Sk_d/Sk_pi/Sk_pr secret %B" also occur in derive_ike_keys_ppk(), and
    // "shared Diffie Hellman secret %B" also occurs in keymat_v1 (IKEv1); any of
    // them would make agreedFunction() see two functions and fail closed
    // (confirmed on stock libcharon 5.9.13 — the DH literal resolved to two).
    const texts = new Set(IKE_FUNC_ANCHORS.map((a) => a.text));
    for (const shared of ["Sk_d secret %B", "Sk_pi secret %B", "Sk_pr secret %B",
                          "shared Diffie Hellman secret %B"]) {
        assert.ok(!texts.has(shared), `${shared} must not be a function anchor`);
    }
});

test("ESP anchors include a DBG1 anchor so add_sa is found on DEBUG_LEVEL>=1 builds", () => {
    const texts = ESP_FUNC_ANCHORS.map((a) => a.text);
    assert.ok(texts.includes("adding SAD entry with SPI %.8x and reqid {%u}%s")); // DBG2
    assert.ok(texts.includes("unable to add SAD entry with SPI %.8x%s (%N)"));    // DBG1
});

test("key-dump literals map to the four decryption-relevant IKE labels", () => {
    const byText = new Map(IKE_KEY_LITERALS.map(([t, l]) => [t, l]));
    assert.equal(byText.get("Sk_ei secret %B"), "sk_ei");
    assert.equal(byText.get("Sk_er secret %B"), "sk_er");
    assert.equal(byText.get("Sk_ai secret %B"), "sk_ai");
    assert.equal(byText.get("Sk_ar secret %B"), "sk_ar");
});

test("constants match strongSwan transform/vtable layout", () => {
    assert.equal(TRANSFORM_TYPE.ENCRYPTION, 1);
    assert.equal(TRANSFORM_TYPE.INTEGRITY, 3);
    assert.equal(PROTO_ESP, 50);
    assert.equal(IKE_SA_ID_SLOT.GET_INITIATOR_SPI, 3);
    assert.equal(IKE_SA_ID_SLOT.GET_RESPONDER_SPI, 4);
    assert.equal(PROPOSAL_GET_ALGORITHM_SLOT, 2);
});

// ---- buildIkeMessage -------------------------------------------------------

function ikeCtx(overrides: Partial<IkeDerivation> = {}): IkeDerivation {
    return {
        spi_i: "1111111111111111",
        spi_r: "2222222222222222",
        enc_alg: 12,            // ENCR_AES_CBC
        enc_key_len_bits: 256,
        int_alg: 12,            // AUTH_HMAC_SHA2_256_128
        keys: { sk_ei: "aa", sk_er: "bb", sk_ai: "cc", sk_ar: "dd" },
        ...overrides,
    };
}

test("buildIkeMessage emits a complete ipsec_ike_keys record", () => {
    const msg = buildIkeMessage(ikeCtx());
    assert.ok(msg);
    assert.equal(msg!.contentType, "ipsec_ike_keys");
    assert.equal(msg!.ike_version, 2);
    assert.equal(msg!.spi_i, "1111111111111111");
    assert.equal(msg!.spi_r, "2222222222222222");
    assert.equal(msg!.enc_alg, 12);
    assert.equal(msg!.enc_key_len_bits, 256);
    assert.equal(msg!.int_alg, 12);
    assert.deepEqual(msg!.keys, { sk_ei: "aa", sk_er: "bb", sk_ai: "cc", sk_ar: "dd" });
});

test("buildIkeMessage returns null without the minimum SPIs + SK_ei/SK_er", () => {
    assert.equal(buildIkeMessage(ikeCtx({ spi_i: "" })), null);
    assert.equal(buildIkeMessage(ikeCtx({ keys: { sk_ei: "aa" } })), null); // no sk_er
    assert.equal(buildIkeMessage(ikeCtx({ keys: {} })), null);
});

// ---- buildEspMessage -------------------------------------------------------

test("buildEspMessage emits an ipsec_esp_keys record with wildcard addresses", () => {
    const msg = buildEspMessage({
        spi: "c0ffee01", proto: PROTO_ESP, family: "IPv4",
        enc_alg: 12, int_alg: 12, enc_key: "00112233", int_key: "44556677",
    });
    assert.ok(msg);
    assert.equal(msg!.contentType, "ipsec_esp_keys");
    assert.equal(msg!.spi, "c0ffee01");
    assert.equal(msg!.src, "*");
    assert.equal(msg!.dst, "*");
    assert.equal(msg!.family, "IPv4");
    assert.equal(msg!.enc_key, "00112233");
    assert.equal(msg!.int_key, "44556677");
});

test("buildEspMessage returns null for non-ESP protocol or missing enc_key", () => {
    const base = { spi: "c0ffee01", family: "IPv4", enc_alg: 12, int_alg: 12, enc_key: "00", int_key: "" };
    assert.equal(buildEspMessage({ ...base, proto: 51 /* AH */ }), null);
    assert.equal(buildEspMessage({ ...base, proto: PROTO_ESP, enc_key: "" }), null);
    assert.ok(buildEspMessage({ ...base, proto: PROTO_ESP })); // AEAD: empty int_key is allowed
});
