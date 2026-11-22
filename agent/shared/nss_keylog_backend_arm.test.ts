// Unit tests for the NSS keylog-writer locator's arm32 (Thumb-2) backend, on real
// Fenix 160.0.1 armeabi-v7a libnss3.so bytes. Static validation only: this
// backend has not run on a device.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { armDirectCallTargets, armNssLocatorBackend, decodeArmKeylogWriter } from "./nss_keylog_backend_arm.js";
import { firstThumbCallTarget } from "./arm_xref.js";
import { isPlausibleWriterClientRandomOffset, NSS_HEX_TABLE } from "./nss_layout_constants.js";
import type { ModuleByteReader } from "./module_mapping.js";
import {
    CLIENT_RANDOM_ADD_PC, CLIENT_RANDOM_OFF, CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, ECH_CONFIG_ADD_PC,
    ECH_TAIL_FN, ECH_TAIL_FN_VADDR, HEX_TABLE_OFFSETS, WRITER, WRITER_VADDR,
} from "./__fixtures__/nss_fenix160_arm.js";

const ASCII_X = 0x78;

/** The writer's bytes (literal pools included) plus every real hex-table copy; anything else reads as "x". */
function fenixReader(code: Uint8Array = WRITER, hexTables: number[] = HEX_TABLE_OFFSETS): ModuleByteReader {
    return (addr, length) => {
        if (addr >= WRITER_VADDR && addr + length <= WRITER_VADDR + code.length) {
            return code.slice(addr - WRITER_VADDR, addr - WRITER_VADDR + length);
        }
        if (hexTables.includes(addr)) return Uint8Array.from(NSS_HEX_TABLE.slice(0, length), (c) => c.charCodeAt(0));
        return new Uint8Array(length).fill(ASCII_X);
    };
}

/** The writer with the instruction bytes at `vaddr` replaced. */
function patchedWriter(vaddr: number, bytes: number[]): Uint8Array {
    const code = WRITER.slice();
    code.set(bytes, vaddr - WRITER_VADDR);
    return code;
}

// ---- decodeArmKeylogWriter --------------------------------------------------------------

test("real 3.132 writer decodes client_random +0x428 despite the early error block", () => {
    assert.deepEqual(decodeArmKeylogWriter(WRITER, WRITER_VADDR, fenixReader()), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("a Thumb-bit address (the cached hook address) decodes the same", () => {
    assert.deepEqual(decodeArmKeylogWriter(WRITER, WRITER_VADDR + 1, fenixReader()), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("writer without a hex-table reference does not decode", () => {
    assert.equal(decodeArmKeylogWriter(WRITER, WRITER_VADDR, fenixReader(WRITER, [])), null);
});

test("a second distinct ss+imm add makes the writer ambiguous", () => {
    // 0x1bb3c6 `add.w r0, r2, #0x20` -> `addw r0, r4, #0x500` (r4 still holds ss)
    const code = patchedWriter(0x1bb3c6, [0x04, 0xf2, 0x00, 0x50]);
    assert.equal(decodeArmKeylogWriter(code, WRITER_VADDR, fenixReader(code)), null);
});

test("a duplicate of the same ss+imm add counts once", () => {
    // 0x1bb3c6 -> `add.w r0, r4, #0x428`
    const code = patchedWriter(0x1bb3c6, [0x04, 0xf5, 0x85, 0x60]);
    assert.deepEqual(decodeArmKeylogWriter(code, WRITER_VADDR, fenixReader(code)), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("an add off r4 after r4 is overwritten (0x1bb3d4 ldrb r4) does not count", () => {
    // 0x1bb3d6 `add.w r5, r2, r7, lsl #1` -> `addw r5, r4, #0x500`
    const code = patchedWriter(0x1bb3d6, [0x04, 0xf2, 0x00, 0x55]);
    assert.deepEqual(decodeArmKeylogWriter(code, WRITER_VADDR, fenixReader(code)), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("an add off r0 after a call is not ss + imm", () => {
    // 0x1bb392 `adds.w r8, r0, #0x43` (after blx) -> `addw r8, r0, #0x500`
    const code = patchedWriter(0x1bb392, [0x00, 0xf2, 0x00, 0x58]);
    assert.deepEqual(decodeArmKeylogWriter(code, WRITER_VADDR, fenixReader(code)), { clientRandomOff: CLIENT_RANDOM_OFF });
});

test("a body with neither copy nor add (the ECH caller) does not decode", () => {
    assert.equal(decodeArmKeylogWriter(ECH_TAIL_FN, ECH_TAIL_FN_VADDR, fenixReader()), null);
});

test("plausible client_random offsets: 0x100..0x2000, 4-aligned", () => {
    assert.ok(isPlausibleWriterClientRandomOffset(0x428, 4));
    assert.ok(isPlausibleWriterClientRandomOffset(0x424, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x43, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x42a, 4));
    assert.ok(!isPlausibleWriterClientRandomOffset(0x3000, 4));
});

// ---- call resolution ---------------------------------------------------------------------

test("real CLIENT_RANDOM label site resolves to the writer", () => {
    assert.equal(firstThumbCallTarget(CLIENT_RANDOM_SITE, CLIENT_RANDOM_SITE_VADDR, CLIENT_RANDOM_ADD_PC), WRITER_VADDR);
});

test("ECH_CONFIG site with a tail `b.w` resolves to the writer", () => {
    assert.equal(firstThumbCallTarget(ECH_TAIL_FN, ECH_TAIL_FN_VADDR, ECH_CONFIG_ADD_PC), WRITER_VADDR);
});

test("direct callees: the ECH caller reaches the writer; the writer's own are tail veneers only", () => {
    assert.deepEqual(armDirectCallTargets(ECH_TAIL_FN, ECH_TAIL_FN_VADDR), [WRITER_VADDR]);
    assert.deepEqual(armDirectCallTargets(WRITER, WRITER_VADDR), [0x1dd18c, 0x1dd0f0]);
});

// ---- backend surface -----------------------------------------------------------------------

test("backend identity: arm, device-verified (Pixel 5, 32-bit Firefox)", () => {
    assert.equal(armNssLocatorBackend.name, "arm");
    assert.equal(armNssLocatorBackend.deviceVerified, true);
});

test("hookAddress sets the Thumb bit", () => {
    let orArg: unknown = null;
    const fn = { or: (v: unknown) => { orArg = v; return "thumb"; } } as unknown as NativePointer;
    assert.equal(armNssLocatorBackend.hookAddress(fn) as unknown, "thumb");
    assert.equal(orArg, 1);
});

test("decodeWriter: a function near the module end read in full is a definite miss, not unreadable", async () => {
    const { withFakeCodeModule } = await import("./frida-test-stubs.js");
    const { resetReadableCache } = await import("../util/safe_memory.js");
    const { DECODE_UNREADABLE } = await import("./keylog_guards.js");
    resetReadableCache();
    withFakeCodeModule(0x40000000n, new Uint8Array(200), (mod) => {
        // 100 bytes left to the module end (< WRITER_DECODE_CAP_BYTES): a stale cache entry must be rejectable.
        const verdict = armNssLocatorBackend.decodeWriter(mod.base.add(100).or(1), mod);
        assert.notEqual(verdict, DECODE_UNREADABLE);
        assert.equal(verdict, null);
    });
    resetReadableCache();
});
