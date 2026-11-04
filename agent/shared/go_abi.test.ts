// Unit tests for shared/go_abi.ts (Go ABIInternal register arguments).
//
// Run: npm run test:agent
//
// WHY: the Go TLS plaintext hooks read Frida's C args[] — args[2..4] for
// writeRecordLocked(typ, data) and args[0] as Read's buffer. Under Go's register ABI those
// are the wrong registers on both arches (arm64: args[2] is data.ptr, so the
// recordType == 23 gate never matched; args[0] is the *Conn receiver, not the buffer).

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { goArg, goIntArg, goKeyLogArgs, goMemmoveArgs, goStackArg, goWriteRecordArgs, isGoStackAbi,
         GO_TLS_RECORD_TYPE_APPLICATION_DATA } from "./go_abi.js";

function reg(n: number): any { return { value: n, toInt32: () => n | 0, toUInt32: () => n >>> 0 }; }

/** writeRecordLocked(c, typ, data.ptr, data.len, data.cap) placed in `names` registers. */
function context(names: string[], values: number[]): any {
    const ctx: any = {};
    names.forEach((name, i) => { ctx[name] = reg(values[i]); });
    return ctx;
}
const ARGS = [0xc0, 0x1700 | GO_TLS_RECORD_TYPE_APPLICATION_DATA, 0xbeef, 42, 64]; // typ's upper bits undefined

test("goWriteRecordArgs: x64 ABIInternal is RAX, RBX, RCX, RDI, RSI", () => {
    const rec = goWriteRecordArgs(context(["rax", "rbx", "rcx", "rdi", "rsi"], ARGS), "x64")!;
    assert.equal(rec.recordType, 23, "only the uint8's low byte counts");
    assert.equal((rec.data as any).value, 0xbeef);
    assert.equal(rec.length, 42);
});

test("goWriteRecordArgs: arm64 ABIInternal is X0..X4", () => {
    const rec = goWriteRecordArgs(context(["x0", "x1", "x2", "x3", "x4"], ARGS), "arm64")!;
    assert.equal(rec.recordType, 23);
    assert.equal((rec.data as any).value, 0xbeef);
    assert.equal(rec.length, 42);
});

test("goIntArg: argument 1 is the first parameter after the receiver; it reads registers only (386/arm: none)", () => {
    assert.equal((goIntArg(context(["rax", "rbx"], [1, 2]), 1, "x64") as any).value, 2);
    assert.equal((goIntArg(context(["x0", "x1"], [1, 2]), 1, "arm64") as any).value, 2);
    assert.equal(goIntArg(context(["eax"], [1]), 0, "ia32"), null);
    assert.equal(goIntArg(context(["r0"], [1]), 0, "arm"), null);
    assert.equal(goIntArg(context(["rax"], [1]), 9, "x64"), null, "beyond the 9 x64 int registers");
    assert.equal(goWriteRecordArgs(context(["r0"], [1]), "arm"), null, "arm without an sp to read the stack from");
});

/** A fake sp: `words[i]` sits at sp + 4*i (no word is readable outside the array). */
function stack(words: number[]): any {
    return {
        add: (offset: number) => ({
            readPointer: () => {
                if (offset % 4 !== 0 || offset / 4 >= words.length) throw new Error(`unread stack offset ${offset}`);
                return reg(words[offset / 4]);
            },
        }),
    };
}
const RET = 0x8badf00d; // 386 return address / arm caller's saved-LR slot at 0(SP) on entry

test("isGoStackAbi: 386 and arm pass Go arguments on the stack, amd64/arm64 in registers", () => {
    assert.equal(isGoStackAbi("ia32"), true);
    assert.equal(isGoStackAbi("arm"), true);
    assert.equal(isGoStackAbi("x64"), false);
    assert.equal(isGoStackAbi("arm64"), false);
});

for (const arch of ["ia32", "arm"]) {
    test(`goArg (${arch}): at entry argument word i is at sp+4+4i; the registers are ignored`, () => {
        const ctx = { sp: stack([RET, 0xc0, 0x11, 0x22]), eax: reg(0xdead), r0: reg(0xdead) };
        assert.equal((goArg(ctx as any, 0, arch) as any).value, 0xc0, "receiver");
        assert.equal((goArg(ctx as any, 2, arch) as any).value, 0x22);
        assert.equal((goStackArg(ctx as any, 1, arch) as any).value, 0x11);
        assert.equal(goIntArg(ctx as any, 0, arch), null, "no register ABI");
        assert.equal(goStackArg(ctx as any, 0, "x64"), null);
        assert.equal(goArg({} as any, 0, arch), null, "no sp in the context");
    });

    test(`goWriteRecordArgs (${arch}): writeRecordLocked(c, typ, data) from the entry stack`, () => {
        const ctx = { sp: stack([RET, ...ARGS]) };
        const rec = goWriteRecordArgs(ctx as any, arch)!;
        assert.equal(rec.recordType, 23, "the uint8 typ occupies a whole word; only its low byte counts");
        assert.equal((rec.data as any).value, 0xbeef);
        assert.equal(rec.length, 42);
    });

    test(`goKeyLogArgs (${arch}): writeKeyLog(c, label, clientRandom, secret) from the entry stack`, () => {
        // c, label(ptr,len), cr(ptr,len,cap), secret(ptr,len,cap)
        const ctx = { sp: stack([RET, 0xc0, 0x1000, 23, 0x2000, 32, 32, 0x3000, 48, 64]) };
        const k = goKeyLogArgs(ctx as any, arch)!;
        assert.deepEqual([(k.label as any).value, k.labelLength, (k.clientRandom as any).value, k.clientRandomLength,
                          (k.secret as any).value, k.secretLength], [0x1000, 23, 0x2000, 32, 0x3000, 48]);
    });
}

test("goMemmoveArgs: register ABI only (x64 RAX/RBX/RCX, arm64 X0..X2); null on 386/arm (no 32-bit Go plaintext)", () => {
    const x64 = goMemmoveArgs(context(["rax", "rbx", "rcx"], [0xd0, 0x50, 99]), "x64")!;
    assert.deepEqual([(x64.to as any).value, (x64.from as any).value, x64.length], [0xd0, 0x50, 99]);
    const arm64 = goMemmoveArgs(context(["x0", "x1", "x2"], [0xd0, 0x50, 99]), "arm64")!;
    assert.deepEqual([(arm64.to as any).value, (arm64.from as any).value, arm64.length], [0xd0, 0x50, 99]);
    assert.equal(goMemmoveArgs({ sp: stack([0xd0, 0x50, 99]) } as any, "ia32"), null);
    assert.equal(goMemmoveArgs({ sp: stack([RET, 0xd0, 0x50, 99]) } as any, "arm"), null);
});
