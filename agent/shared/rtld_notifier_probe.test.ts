// Unit tests for the arm32 linker-notifier probe (shared/rtld_notifier_probe.ts).
//
// Run: npm run test:agent
//
// The fixture bytes are the real ones read on a Pixel 5 (Android 14, 32-bit
// Firefox) right after a frida 17.24.3 attach: rtld_db_dlactivity at 0xf0b99b40
// held `00 f0 00 90` (B.W -> 0xf1799b44), and 0xf1799b44 was not mapped.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    decodeThumbBranchWTarget, isAddressInMaps, isNotifierBranchBroken,
    isJavaBlockedByBrokenLinkerNotifier, resetJavaGateForTests, LINKER_NOTIFIER_JAVA_SKIP_WARNING,
} from "./rtld_notifier_probe.js";

const STUB = 0xf0b99b40;
const MAPS = [
    "f0b65000-f0c3c000 r-xp 00000000 07:80 15     /apex/com.android.runtime/bin/linker",
    "f0c3c000-f0c41000 rw-p 000d6000 07:80 15     /apex/com.android.runtime/bin/linker",
    "7b0d6000-7c681000 r-xp 00000000 00:05 4833395  /memfd:frida-agent-32.so (deleted)",
].join("\n");

test("decodes the observed broken B.W to 0xf1799b44", () => {
    assert.equal(decodeThumbBranchWTarget(STUB, 0xf000, 0x9000), 0xf1799b44);
});

test("decodes a small forward and a backward B.W", () => {
    // B.W +0x100: S=0, J1=J2=1 (I1=I2=0), imm11=0x80
    assert.equal(decodeThumbBranchWTarget(0x1000, 0xf000, 0xb880), 0x1104);
    // B.W -4: S=1, imm10=0x3ff, J1=J2=1, imm11=0x7fe
    assert.equal(decodeThumbBranchWTarget(0x1000, 0xf7ff, 0xbffe), 0x1000);
});

test("non-B.W instructions are not decoded", () => {
    assert.equal(decodeThumbBranchWTarget(STUB, 0x4770, 0xd4d4), null); // original `bx lr` + padding
    assert.equal(decodeThumbBranchWTarget(STUB, 0xf000, 0xd000), null); // BL, not B.W
});

test("isAddressInMaps honours range bounds", () => {
    assert.equal(isAddressInMaps(0xf0b65000, MAPS), true);
    assert.equal(isAddressInMaps(0xf0c40fff, MAPS), true);
    assert.equal(isAddressInMaps(0xf0c41000, MAPS), false);
    assert.equal(isAddressInMaps(0xf1799b44, MAPS), false);
});

test("broken: B.W into unmapped memory", () => {
    assert.equal(isNotifierBranchBroken(STUB, 0xf000, 0x9000, MAPS), true);
});

test("healthy: B.W into a mapped trampoline page", () => {
    const withTrampoline = MAPS + "\nf1799000-f179a000 r-xp 00000000 00:00 0";
    assert.equal(isNotifierBranchBroken(STUB, 0xf000, 0x9000, withTrampoline), false);
});

test("healthy: unhooked stub", () => {
    assert.equal(isNotifierBranchBroken(STUB, 0x4770, 0xd4d4, MAPS), false);
});

// ---- isJavaBlockedByBrokenLinkerNotifier: the shared once-gate for Android TLS Java hooks ----

test("Java gate: broken probe blocks Java, warns once, probes once", () => {
    resetJavaGateForTests();
    let probes = 0;
    const warnings: string[] = [];
    const probe = () => { probes++; return true; };
    const warn = (m: string) => warnings.push(m);
    assert.equal(isJavaBlockedByBrokenLinkerNotifier(probe, warn), true);   // legacy "java" phase
    assert.equal(isJavaBlockedByBrokenLinkerNotifier(probe, warn), true);   // modern conscrypt
    assert.equal(probes, 1);
    assert.deepEqual(warnings, [LINKER_NOTIFIER_JAVA_SKIP_WARNING]);
    resetJavaGateForTests();
});

test("Java gate: healthy probe allows Java and logs nothing", () => {
    resetJavaGateForTests();
    const warnings: string[] = [];
    assert.equal(isJavaBlockedByBrokenLinkerNotifier(() => false, (m) => warnings.push(m)), false);
    assert.equal(isJavaBlockedByBrokenLinkerNotifier(() => true, (m) => warnings.push(m)), false); // cached
    assert.deepEqual(warnings, []);
    resetJavaGateForTests();
});

test("Java gate: the default probe is a no-op off 32-bit ARM", () => {
    resetJavaGateForTests();
    // frida-test-stubs report a non-arm Process.arch: the device probe says healthy.
    assert.equal(isJavaBlockedByBrokenLinkerNotifier(undefined, () => assert.fail("no warning expected")), false);
    resetJavaGateForTests();
});
