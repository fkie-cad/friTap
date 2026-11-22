// Unit tests for the range lookups of safe_memory.ts (findRange, isWritable, moduleImageBounds).
//
// Run: npm run test:agent
//
// WHY: Process.findRangeByAddress costs 42 ms per call on Chrome/macOS;
// findRange is the one Darwin-aware lookup.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../shared/frida-test-stubs.js";
import { findRange, isWritable, moduleImageBounds, untag } from "./safe_memory.js";

const G = globalThis as any;
const TBI = 0x00ff_ffff_ffff_ffffn;

/** Just enough NativePointer for the lookup (the stub's ptr() mask is not a BigPtr: treat it as the TBI mask). */
class BigPtr {
    constructor(readonly v: bigint) {}
    isNull() { return this.v === 0n; }
    and(m: unknown) { return new BigPtr(this.v & (m instanceof BigPtr ? m.v : TBI)); }
    add(n: number | bigint) { return new BigPtr(this.v + BigInt(n)); }
    compare(o: BigPtr) { return this.v < o.v ? -1 : this.v > o.v ? 1 : 0; }
    toString() { return "0x" + this.v.toString(16); }
}

function withRange(base: bigint, size: number, protection: string, body: () => void): void {
    const previous = G.Process.findRangeByAddress;
    G.Process.findRangeByAddress = (a: BigPtr) =>
        a.v >= base && a.v < base + BigInt(size) ? { base: new BigPtr(base), size, protection } : null;
    try { body(); } finally { G.Process.findRangeByAddress = previous; }
}

test("findRange answers base, end and protection of the mapping, null when unmapped", () => {
    withRange(0x10000n, 0x2000, "rw-", () => {
        const range = findRange(new BigPtr(0x10800n) as any)!;
        assert.equal(range.base.toString(), "0x10000");
        assert.equal(range.end.toString(), "0x12000");
        assert.equal(range.protection, "rw-");
        assert.equal(findRange(new BigPtr(0x20000n) as any), null);
    });
});

test("findRange clears an Android pointer tag before the lookup", () => {
    withRange(0x7000_0000n, 0x1000, "r--", () => {
        assert.ok(findRange(new BigPtr(0xb400_0000_7000_0010n) as any));
    });
});

test("findRange never throws", () => {
    const previous = G.Process.findRangeByAddress;
    G.Process.findRangeByAddress = () => { throw new Error("boom"); };
    try { assert.equal(findRange(new BigPtr(0x1000n) as any), null); } finally { G.Process.findRangeByAddress = previous; }
});

test("isWritable needs rw- and the whole span inside the mapping", () => {
    withRange(0x10000n, 0x1000, "rw-", () => {
        assert.equal(isWritable(new BigPtr(0x10ff8n) as any, 8), true);
        assert.equal(isWritable(new BigPtr(0x10ffcn) as any, 8), false);   // straddles the end
    });
    withRange(0x10000n, 0x1000, "r-x", () => {
        assert.equal(isWritable(new BigPtr(0x10000n) as any, 8), false);
    });
});

test("untag clears only the top byte", () => {
    assert.equal(untag(new BigPtr(0xb400_0070_0000_0010n) as any).toString(), "0x7000000010");
    assert.equal(untag(new BigPtr(0x7fff_0000_1000n) as any).toString(), "0x7fff00001000");
});

/** A module of `size` bytes at `base` whose readable ranges are `ranges` ([base, size]). */
function fakeModule(base: bigint, size: number, ranges: [bigint, number][] | null) {
    return {
        base: new BigPtr(base), size,
        enumerateRanges: () => {
            if (ranges === null) throw new Error("gone");
            return ranges.map(([b, n]) => ({ base: new BigPtr(b), size: n }));
        },
    } as any;
}

const bounds = (mod: any) => moduleImageBounds(mod).map((p: any) => p.v);

test("module image bounds reach past Module.size into later segments (macOS __DATA_CONST vtables)", () => {
    // Chrome 157 macOS arm64: Module.size = __TEXT only; vtables at +0xe620ee8.
    const base = 0x100000000n;
    const [lo, hi] = bounds(fakeModule(base, 0xe354000, [
        [base, 0xe354000], [base + 0xe354000n, 0xc04000], [base + 0xf308000n, 0x21c000],
    ]));
    assert.equal(lo, base);
    assert.equal(hi, base + 0xf524000n);
    assert.ok(base + 0xe620ee8n < hi);
});

test("module image bounds fall back to Module.size and ignore ranges below the base", () => {
    const base = 0x100000000n;
    assert.deepEqual(bounds(fakeModule(base, 0x1000, [])), [base, base + 0x1000n]);
    assert.deepEqual(bounds(fakeModule(base, 0x1000, [[base - 0x10000n, 0x20000]])), [base, base + 0x1000n]);
    assert.deepEqual(bounds(fakeModule(base, 0x1000, null)), [base, base + 0x1000n]);
});

test("codeBytesAvailable: capped by the cap, the module end and the readable range end; 0 outside", async () => {
    const { withFakeCodeModule } = await import("../shared/frida-test-stubs.js");
    const { codeBytesAvailable, resetReadableCache } = await import("./safe_memory.js");
    resetReadableCache();
    withFakeCodeModule(0x43000000n, new Uint8Array(0x1000), (mod) => {
        assert.equal(codeBytesAvailable(mod.base.add(0x10), mod, 0x80), 0x80);      // the cap
        assert.equal(codeBytesAvailable(mod.base.add(0xf00), mod, 0x1000), 0x100); // the module end
        assert.equal(codeBytesAvailable(mod.base.add(0x1000), mod, 0x80), 0);      // outside
    });
    withFakeCodeModule(0x44000000n, new Uint8Array(0x1000), (mod) => {
        assert.equal(codeBytesAvailable(mod.base.add(0x100), mod, 0x1000), 0x100); // the range end
        assert.equal(codeBytesAvailable(mod.base.add(0x300), mod, 0x1000), 0);     // unreadable
    }, 0x200);
    resetReadableCache();
});
