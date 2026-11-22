// Unit tests for the NSS keylog-writer locator's arm64 backend decoders and the
// pure selection helpers of nss_keylog_locator.ts, on real Fenix 160.0.1 bytes.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { decodeKeylogWriter } from "./nss_keylog_backend_arm64.js";
import { directCallTargets } from "./arm64_xref.js";
import { isPlausibleWriterClientRandomOffset, NSS_HEX_TABLE } from "./nss_layout_constants.js";
import type { ModuleByteReader } from "./module_mapping.js";
import {
    isKnownLabel, isSecItemShape, parseNssVersion, pickKeylogWriter, secretSourceFor, NSS_KEYLOG_LABELS,
    LEARNED_NSS_KEYLOG_WRITER_MISS,
} from "./nss_keylog_locator.js";
import {
    CLIENT_RANDOM_OFF, CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, ECH_CONFIG_TAIL_SITE,
    ECH_CONFIG_TAIL_SITE_VADDR, HEX_TABLE_OFFSETS, TLS13_WRAP, TLS13_WRAP_VADDR, WRITER, WRITER_VADDR,
} from "./__fixtures__/nss_fenix160_arm64.js";

/** Test readers written as text: each returned string becomes its byte codes. */
type TextReader = (addr: number, length: number) => string | null;
const textReader = (read: TextReader): ModuleByteReader => (addr, length) => {
    const text = read(addr, length);
    return text === null ? null : Uint8Array.from(text, (c) => c.charCodeAt(0));
};

/** The real module's hex-table copies; every other address reads as non-matching text. */
const fenixLiterals = textReader((addr, length) =>
    HEX_TABLE_OFFSETS.includes(addr) ? NSS_HEX_TABLE.slice(0, length) : "x".repeat(length));

const wordIndex = (vaddr: number) => (vaddr - WRITER_VADDR) / 4;
const add64 = (rd: number, rn: number, imm12: number) => (0x91000000 | (imm12 << 10) | (rn << 5) | rd) >>> 0;
const mov64 = (rd: number, rm: number) => (0xaa0003e0 | (rm << 16) | rd) >>> 0;
const RET = 0xd65f03c0;

// ---- decodeKeylogWriter --------------------------------------------------------

test("real 3.132 writer decodes client_random +0x650", () => {
    assert.deepEqual(decodeKeylogWriter(WRITER, WRITER_VADDR, fenixLiterals), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("writer without a hex-table literal does not decode", () => {
    assert.equal(decodeKeylogWriter(WRITER, WRITER_VADDR, textReader((_a, n) => "x".repeat(n))), null);
});

test("a second distinct ss+imm ADD makes the writer ambiguous", () => {
    const words = [...WRITER];
    words[wordIndex(0x279e64)] = add64(9, 22, 0x700); // was `mov x9, xzr`
    assert.equal(decodeKeylogWriter(words, WRITER_VADDR, fenixLiterals), null);
});

test("an ADD off x22 after x22 is overwritten does not count", () => {
    // 0x279f08 reloads x22 (adrp/ldr); an add off it there is not ss+imm.
    const words = [...WRITER];
    words[wordIndex(0x279f10)] = add64(9, 22, 0x700); // was `mov w9, #0xa`
    assert.deepEqual(decodeKeylogWriter(words, WRITER_VADDR, fenixLiterals), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("tls13_DeriveSecretWrap does not decode (TLS 1.3 votes can never win)", () => {
    assert.equal(decodeKeylogWriter(TLS13_WRAP, TLS13_WRAP_VADDR, fenixLiterals), null);
});

test("an error block laid out before `mov Xn, x0` that clobbers x0 is rolled back", () => {
    // 0x1000: cbnz x1, +12 ; mov x0, #0x13 ; ret ; mov x22, x0 ; add x10, x22, #0x650 ; adr x8, 0x2000 ; ret
    const cbnzX1 = (0xb5000000 | (3 << 5) | 1) >>> 0;
    const movzX0 = (0xd2800000 | (0x13 << 5)) >>> 0;
    const adrX8To2000 = (0x10000000 | (((0x2000 - 0x1014) >> 2) << 5) | 8) >>> 0;
    const words = [cbnzX1, movzX0, RET, mov64(22, 0), add64(10, 22, 0x650), adrX8To2000, RET];
    const literals = textReader((a, n) => (a === 0x2000 ? NSS_HEX_TABLE.slice(0, n) : null));
    assert.deepEqual(decodeKeylogWriter(words, 0x1000, literals), { clientRandomOff: 0x650 });
});

test("a copy of x0 taken after a call is not ss", () => {
    const bl = 0x94000100;
    const adrX8 = (0x10000000 | (((0x2000 - 0x100c) >> 2) << 5) | 8) >>> 0;
    const words = [bl, mov64(22, 0), add64(10, 22, 0x650), adrX8, RET];
    const literals = textReader((a, n) => (a === 0x2000 ? NSS_HEX_TABLE.slice(0, n) : null));
    assert.equal(decodeKeylogWriter(words, 0x1000, literals), null);
});

test("plausible client_random offsets: 0x100..0x2000, 8-aligned", () => {
    assert.ok(isPlausibleWriterClientRandomOffset(0x650, 8));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x30, 8));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x654, 8));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x3000, 8));
});

// ---- directCallTargets ----------------------------------------------------------

test("CLIENT_RANDOM label site: the first call after the site is the writer", () => {
    const targets = directCallTargets(CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR);
    assert.equal(targets[0], 0x2a8920);   // bl @0x280408, before the site
    assert.equal(targets[1], WRITER_VADDR); // bl @0x280420
});

test("ECH_CONFIG tail `b` resolves to the writer", () => {
    const targets = directCallTargets(ECH_CONFIG_TAIL_SITE, ECH_CONFIG_TAIL_SITE_VADDR);
    assert.deepEqual(targets, [WRITER_VADDR]); // bl @0x2a1054 and tail b @0x2a1070, deduplicated
});

test("the TLS 1.3 wrap calls the writer directly (diagnostic)", () => {
    assert.ok(directCallTargets(TLS13_WRAP, TLS13_WRAP_VADDR).includes(WRITER_VADDR));
});

test("a B inside the window is an intra-function jump, not a call", () => {
    assert.deepEqual(directCallTargets([0x14000002, RET, RET], 0x1000), []);
});

// ---- locator core pure helpers ------------------------------------------------------

test("pickKeylogWriter: exactly one decoding candidate wins", () => {
    const decode = (c: number) => (c === 2 || c === 4 ? { clientRandomOff: c } : null);
    assert.deepEqual(pickKeylogWriter([1, 2, 3], decode), { candidate: 2, decoded: { clientRandomOff: 2 } });
    assert.deepEqual(pickKeylogWriter([2, 1, 2], decode), { candidate: 2, decoded: { clientRandomOff: 2 } });
    assert.equal(pickKeylogWriter([1, 3], decode), null);
    assert.equal(pickKeylogWriter([2, 4], decode), null);
    assert.equal(pickKeylogWriter([], decode), null);
});

test("isKnownLabel accepts exactly the ten NSS keylog labels", () => {
    assert.equal(NSS_KEYLOG_LABELS.length, 10);
    for (const label of NSS_KEYLOG_LABELS) assert.ok(isKnownLabel(label));
    assert.ok(!isKnownLabel("CLIENT_RANDOMX"));
    assert.ok(!isKnownLabel(""));
    assert.ok(!isKnownLabel(null));
});

test("isSecItemShape: readable data and len 1..512", () => {
    assert.ok(isSecItemShape(true, 48));
    assert.ok(!isSecItemShape(false, 48));
    assert.ok(!isSecItemShape(true, 0));
    assert.ok(!isSecItemShape(true, 513));
    assert.ok(!isSecItemShape(true, null));
});

test("secretSourceFor: the shape probe must agree with the version", () => {
    const v3132 = parseNssVersion("3.132");
    const v390 = parseNssVersion("3.90.1 Basic ECC");
    assert.deepEqual(v390, { major: 3, minor: 90 });
    assert.equal(secretSourceFor(v3132, true), "secitem");
    assert.equal(secretSourceFor(v3132, false), null);
    assert.equal(secretSourceFor(v390, false), "symkey");
    assert.equal(secretSourceFor(v390, true), null);
    assert.equal(secretSourceFor(null, true), "secitem");
    assert.equal(secretSourceFor(null, false), null);
    assert.equal(parseNssVersion("garbage"), null);
});

test("miss marker name follows the learned-cache convention", () => {
    assert.equal(LEARNED_NSS_KEYLOG_WRITER_MISS, "nss.miss.keylog_writer");
});

test("decodeWriter: a function near the module end read in full is a definite miss, not unreadable", async () => {
    const { withFakeCodeModule } = await import("./frida-test-stubs.js");
    const { resetReadableCache } = await import("../util/safe_memory.js");
    const { DECODE_UNREADABLE } = await import("./keylog_guards.js");
    const { arm64NssLocatorBackend } = await import("./nss_keylog_backend_arm64.js");
    resetReadableCache();
    withFakeCodeModule(0x41000000n, new Uint8Array(200), (mod) => {
        const verdict = arm64NssLocatorBackend.decodeWriter(mod.base.add(100), mod); // 25 words to the module end
        assert.notEqual(verdict, DECODE_UNREADABLE);
        assert.equal(verdict, null);
    });
    resetReadableCache();
});
