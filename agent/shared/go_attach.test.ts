// Unit tests for agent/shared/go_attach.ts (onEnter hooks on Go functions).
//
// Run: npm run test:agent
//
// WHY: on arm64 every Go function opens with a stack-guard check that uses both scratch
// registers x16/x17; when Frida cannot place its trampoline in B range it needs one of them
// and attaching at the entry throws "unable to intercept function". Seen live (Go 1.21,
// Linux/arm64 + macOS/arm64) for writeKeyLog and writeRecordLocked: no Go keys, no Go
// write plaintext. Such functions are now always hooked at the instruction after the check
// (one deterministic site), where the argument registers are still the entry values.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    GO_HOOK_STACK_HEADROOM, attachGoFunctionEntry, decodeSubX17SpImm, goArm64StackCheckEnd, widenGoArm64StackCheck,
} from "./go_attach.js";

const G = globalThis as any;
/** Encoded words of the fake program (only the stack-guard load is read as a word). */
const LDR_X16_STACKGUARD = 0xf9400b90;
let words = new Map<number, number>();
function P(n: number): any {
    return {
        value: n, isNull: () => n === 0, toString: () => `0x${n.toString(16)}`, equals: (o: any) => o?.value === n,
        add: (k: number) => P(n + k),
        readU32: () => { const w = words.get(n); if (w === undefined) throw new Error(`access violation at ${n}`); return w; },
    };
}
function program(insns: Array<[number, string, string]>): void {
    const byAddress = new Map(insns.map(([at, mnemonic, opStr]) => [at, { mnemonic, opStr }]));
    words = new Map(insns.map(([at, mnemonic, opStr]) =>
        [at, mnemonic === "ldr" && opStr === "x16, [x28, #0x10]" ? LDR_X16_STACKGUARD : 0xd503201f])); // else: nop
    G.Instruction = {
        parse: (p: any) => {
            const i = byAddress.get(p.value);
            if (!i) throw new Error(`invalid instruction at ${p}`);
            return { mnemonic: i.mnemonic, opStr: i.opStr, next: P(p.value + 4) };
        },
    };
}

// crypto/tls.(*Config).writeKeyLog, Go 1.21 linux/arm64 (go tool objdump).
const SMALL_FRAME: Array<[number, string, string]> = [
    [0x1000, "ldr", "x16, [x28, #0x10]"],
    [0x1004, "sub", "x17, sp, #0x30"],
    [0x1008, "cmp", "x17, x16"],
    [0x100c, "b.ls", "#0x1208"],
    [0x1010, "str", "x30, [sp, #-0xb0]!"],
];

test("goArm64StackCheckEnd: the instruction after the stack-guard branch", () => {
    program(SMALL_FRAME);
    assert.equal(goArm64StackCheckEnd(P(0x1000))?.value, 0x1010);
    program([[0x1000, "ldr", "x16, [x28, #0x10]"], [0x1004, "cmp", "sp, x16"], [0x1008, "b.ls", "#0x1100"], [0x100c, "str", "x30, [sp, #-0x20]!"]]);
    assert.equal(goArm64StackCheckEnd(P(0x1000))?.value, 0x100c);
});

test("goArm64StackCheckEnd: not a Go prologue, or an argument register written -> null", () => {
    program([[0x1000, "stp", "x29, x30, [sp, #-0x10]!"]]);
    assert.equal(goArm64StackCheckEnd(P(0x1000)), null, "C function");
    program([[0x1000, "ldr", "x16, [x28, #0x10]"], [0x1004, "mov", "x1, x16"], [0x1008, "b.ls", "#0x1100"]]);
    assert.equal(goArm64StackCheckEnd(P(0x1000)), null, "x1 would no longer be the entry value");
    program([[0x1000, "ldr", "x16, [x28, #0x10]"]]);
    assert.equal(goArm64StackCheckEnd(P(0x1000)), null, "undecodable");
});

/** Records every Interceptor.attach target. */
function recordAttaches(): number[] {
    const attachedAt: number[] = [];
    G.Interceptor.attach = (target: any, _cb: any) => {
        attachedAt.push(target.value);
        return { detach: () => { } };
    };
    return attachedAt;
}

test("attachGoFunctionEntry: a Go arm64 function is always hooked after its stack check (deterministic)", () => {
    program(SMALL_FRAME);
    const attachedAt = recordAttaches();
    attachGoFunctionEntry(P(0x1000), { onEnter: () => { } }, "arm64");
    assert.deepEqual(attachedAt, [0x1010], "never at the entry, whether or not Frida could patch it");
});

test("attachGoFunctionEntry: non-Go code, unreadable code and other architectures are hooked at the address", () => {
    const attachedAt = recordAttaches();
    const onEnter = () => { };
    program(SMALL_FRAME);
    attachGoFunctionEntry(P(0x1000), { onEnter }, "x64");
    program([[0x2000, "stp", "x29, x30, [sp, #-0x10]!"]]);
    attachGoFunctionEntry(P(0x2000), { onEnter }, "arm64");
    attachGoFunctionEntry(P(0x3000), { onEnter }, "arm64"); // unreadable
    assert.deepEqual(attachedAt, [0x1000, 0x2000, 0x3000]);
});

test("attachGoFunctionEntry: an attach failure propagates", () => {
    program(SMALL_FRAME);
    G.Interceptor.attach = () => { throw new Error("unable to intercept function"); };
    assert.throws(() => attachGoFunctionEntry(P(0x1000), { onEnter: () => { } }, "arm64"), /unable to intercept/);
});

// ---- goroutine stack headroom ----------------------------------------------------------------
// WHY: a Frida JS onEnter needs ~6 KiB of the goroutine's stack; Go guarantees 928 B + frame.
// darwin/arm64 Go 1.24 crashed in 9/10 -p runs at writeRecordLocked until its check was widened.

test("decodeSubX17SpImm: sub x17, sp, #imm (plain and lsl #12); anything else is null", () => {
    assert.equal(decodeSubX17SpImm(0xd102c3f1), 176, "writeRecordLocked, Go 1.24 darwin/arm64");
    assert.equal(decodeSubX17SpImm(0xd100c3f1), 48, "writeKeyLog");
    assert.equal(decodeSubX17SpImm(0xd14017f1), 5 * 4096);
    assert.equal(decodeSubX17SpImm(0xeb3063ff), null, "cmp sp, x16 (small-frame check)");
    assert.equal(decodeSubX17SpImm(0xd102c3f4), null, "sub x20, sp, #176 (frame allocation, not the check)");
    assert.equal(decodeSubX17SpImm(0xf1000231), null, "subs (flag-setting) is not the check");
});

test("widenGoArm64StackCheck: frame + headroom, rounded up to 4 KiB, never less than asked", () => {
    assert.equal(widenGoArm64StackCheck(0xd102c3f1), 0xd14017f1, "176 + 16 KiB -> 5 pages (the word validated live)");
    for (const insn of [0xd100c3f1, 0xd102c3f1, 0xd13ffff1]) {
        const widened = widenGoArm64StackCheck(insn)!;
        assert.ok(decodeSubX17SpImm(widened)! >= decodeSubX17SpImm(insn)! + GO_HOOK_STACK_HEADROOM);
        assert.equal(widened & 0x3ff, 0x3f1, "still sub x17, sp");
    }
    assert.equal(widenGoArm64StackCheck(0xeb3063ff), null);
    assert.equal(widenGoArm64StackCheck(0xd17ffff1, 64 * 1024 * 1024), null, "beyond imm12 << 12");
});

test("attachGoFunctionEntry: widens a sub-x17 stack check once, before hooking after it", () => {
    program(SMALL_FRAME);
    words.set(0x1004, 0xd100c3f1); // sub x17, sp, #0x30
    const patches: Array<[number, number]> = [];
    G.Memory.patchCode = (at: any, size: number, apply: (code: any) => void) => {
        assert.equal(size, 4);
        apply({ writeU32: (w: number) => { patches.push([at.value, w >>> 0]); words.set(at.value, w >>> 0); } });
    };
    const attachedAt = recordAttaches();
    attachGoFunctionEntry(P(0x1000), { onEnter: () => { } }, "arm64");
    attachGoFunctionEntry(P(0x1000), { onEnter: () => { } }, "arm64");
    assert.deepEqual(patches, [[0x1004, widenGoArm64StackCheck(0xd100c3f1)!]], "patched exactly once");
    assert.deepEqual(attachedAt, [0x1010, 0x1010]);
});

test("attachGoFunctionEntry: a small-frame check or a failing patch still hooks (no headroom)", () => {
    program([[0x5000, "ldr", "x16, [x28, #0x10]"], [0x5004, "cmp", "sp, x16"], [0x5008, "b.ls", "#0x5100"], [0x500c, "str", "x30, [sp, #-0x20]!"]]);
    words.set(0x5004, 0xeb3063ff);
    let patched = 0;
    G.Memory.patchCode = () => { patched++; };
    const attachedAt = recordAttaches();
    attachGoFunctionEntry(P(0x5000), { onEnter: () => { } }, "arm64");
    assert.equal(patched, 0);
    program(SMALL_FRAME.map(([at, m, o]) => [at + 0x6000, m, o] as [number, string, string]));
    words.set(0x7004, 0xd100c3f1);
    G.Memory.patchCode = () => { patched++; throw new Error("patch denied"); };
    attachGoFunctionEntry(P(0x7000), { onEnter: () => { } }, "arm64");
    assert.equal(patched, 1, "the widening was attempted");
    assert.deepEqual(attachedAt, [0x500c, 0x7010], "and the hook still installed");
});
