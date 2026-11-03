// Unit tests for shared/ssl_fd_cache.ts (SSL -> fd cache with an fd -> SSL reverse index).
//
// Run: npm run test:agent
//
// WHY: close(fd) used to scan the whole SSL->fd map on every close() in the process.
// The reverse index makes it O(entries for that fd); it must stay in sync on set,
// SSL_free, close and LRU eviction.

import { test } from "node:test";
import assert from "node:assert/strict";

import { SslFdCache } from "./ssl_fd_cache.js";

test("set/get and close(fd) drops every SSL cached with that fd only", () => {
    const cache = new SslFdCache(8);
    cache.set("a", 3);
    cache.set("b", 3);
    cache.set("c", 4);
    cache.deleteFd(3);
    assert.equal(cache.get("a"), undefined);
    assert.equal(cache.get("b"), undefined);
    assert.equal(cache.get("c"), 4);
    assert.equal(cache.indexedFdCount, 1);
});

test("re-caching an SSL under a new fd moves it in the reverse index", () => {
    const cache = new SslFdCache(8);
    cache.set("a", 3);
    cache.set("a", 9);
    cache.deleteFd(3);
    assert.equal(cache.get("a"), 9, "closing the OLD fd must not forget the SSL");
    cache.deleteFd(9);
    assert.equal(cache.get("a"), undefined);
    assert.equal(cache.indexedFdCount, 0);
});

test("SSL_free (deleteSsl) prunes the reverse index", () => {
    const cache = new SslFdCache(8);
    cache.set("a", 3);
    cache.deleteSsl("a");
    assert.equal(cache.size, 0);
    assert.equal(cache.indexedFdCount, 0);
    cache.deleteSsl("missing");                        // no-op
    cache.deleteFd(42);                                // no-op
});

test("LRU eviction keeps the reverse index in sync", () => {
    const cache = new SslFdCache(2);
    cache.set("a", 1);
    cache.set("b", 2);
    cache.set("a", 1);                                  // refresh: b is now the oldest
    cache.set("c", 3);                                  // evicts b
    assert.equal(cache.get("b"), undefined);
    assert.equal(cache.get("a"), 1);
    assert.equal(cache.size, 2);
    assert.equal(cache.indexedFdCount, 2, "fd 2 left the index with b");
});
