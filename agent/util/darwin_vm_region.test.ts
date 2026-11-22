// Run: npm run test:agent
import { test } from "node:test";
import assert from "node:assert/strict";
import { RegionAnswer, regionContains, resolveLeafRegion } from "./darwin_vm_region.js";

/** Minimal NativePointer stand-in: only compare() is used. */
function p(n: bigint): NativePointer {
    return { n, compare: (o: { n: bigint }) => (n < o.n ? -1 : n > o.n ? 1 : 0) } as unknown as NativePointer;
}

test("regionContains: [base, end) holds the query", () => {
    assert.equal(regionContains(p(0x1000n), p(0x1000n), p(0x1100n)), true);
    assert.equal(regionContains(p(0x10ffn), p(0x1000n), p(0x1100n)), true);
});

test("regionContains: mach_vm_region's next region after an unmapped query does not", () => {
    assert.equal(regionContains(p(0x10n), p(0x104984000n), p(0x104988000n)), false);
    assert.equal(regionContains(p(0x1100n), p(0x1000n), p(0x1100n)), false);
});

function answer(base: bigint, end: bigint, protection: number, isSubmap: boolean): RegionAnswer {
    return { base: p(base), end: p(end), protection, isSubmap };
}

// Shared region: one r-- submap entry over the whole cache, leaves underneath.
const SUBMAP = answer(0x180000000n, 0x280000000n, 1, true);

test("resolveLeafRegion descends a submap to the leaf's own range and protection", () => {
    const depths: number[] = [];
    const leaf = resolveLeafRegion(p(0x1a0001000n), (d) => {
        depths.push(d);
        return d === 0 ? SUBMAP : answer(0x1a0000000n, 0x1a0004000n, 3, false);
    })!;
    assert.deepEqual(depths, [0, 1]);
    assert.equal((leaf.base as any).n, 0x1a0000000n);
    assert.equal((leaf.end as any).n, 0x1a0004000n);
    assert.equal(leaf.protection, 3);
});

test("resolveLeafRegion: a hole inside the submap is unmapped, not the submap entry", () => {
    const leaf = resolveLeafRegion(p(0x1a0001000n), (d) =>
        d === 0 ? SUBMAP : answer(0x1b0000000n, 0x1b0004000n, 5, false));
    assert.equal(leaf, null);
});

test("resolveLeafRegion: a plain region answers at depth 0", () => {
    const leaf = resolveLeafRegion(p(0x1000n), () => answer(0x1000n, 0x2000n, 3, false))!;
    assert.equal(leaf.protection, 3);
});

test("resolveLeafRegion: nothing-after is unmapped, a kernel failure or endless nesting falls back", () => {
    assert.equal(resolveLeafRegion(p(0x1000n), () => null), null);
    assert.equal(resolveLeafRegion(p(0x1000n), () => undefined), undefined);
    assert.equal(resolveLeafRegion(p(0x1a0001000n), () => SUBMAP), undefined);
});
