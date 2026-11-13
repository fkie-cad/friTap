// Unit tests for the bounded caches in shared/lru.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";

import { LruMap, FifoSet } from "./lru.js";

test("LruMap evicts the least recently used entry and stays bounded", () => {
    const lru = new LruMap<number, string>(3);
    lru.set(1, "a"); lru.set(2, "b"); lru.set(3, "c");
    assert.equal(lru.get(1), "a");      // 1 becomes most recent
    lru.set(4, "d");                    // evicts 2
    assert.equal(lru.get(2), undefined);
    assert.equal(lru.size, 3);
    for (let i = 0; i < 100; i++) lru.set(100 + i, "x");
    assert.equal(lru.size, 3);
    assert.equal(lru.delete(199), true);
    assert.equal(lru.size, 2);
});

test("LruMap reports capacity evictions but not delete/overwrite", () => {
    const evicted: number[] = [];
    const lru = new LruMap<number, string>(2, (k) => evicted.push(k));
    lru.set(1, "a"); lru.set(2, "b");
    lru.set(1, "a2");                   // overwrite: no eviction, 1 now most recent
    lru.delete(2);
    lru.set(3, "c"); lru.set(4, "d");   // evicts 1
    assert.deepEqual(evicted, [1]);
});

test("LruMap.clear empties the map without reporting evictions", () => {
    const evicted: number[] = [];
    const lru = new LruMap<number, string>(3, (k) => evicted.push(k));
    lru.set(1, "a"); lru.set(2, "b");
    lru.clear();
    assert.equal(lru.size, 0);
    assert.equal(lru.get(1), undefined);
    assert.deepEqual(evicted, []);
    lru.set(5, "e");
    assert.equal(lru.get(5), "e");
});

test("FifoSet evicts the oldest value without hit promotion", () => {
    const set = new FifoSet<number>(2);
    set.add(1); set.add(2);
    assert.equal(set.has(1), true);     // no promotion
    set.add(3);                         // evicts 1
    assert.equal(set.has(1), false);
    assert.equal(set.size, 2);
});
