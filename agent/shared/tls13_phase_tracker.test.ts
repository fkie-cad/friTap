// Unit tests for the TLS 1.3 handshake/application phase tracker used by the
// legacy Windows ncrypt.dll keylog hooks (lsass.ts / sspi.ts).
//
// Run: npm run test:agent
//
// The tracker is the fix for the HANDSHAKE_TRAFFIC_SECRET <-> TRAFFIC_SECRET_0
// label swap: ncrypt's SslExpandTrafficKeys is called twice per handshake and
// the phase is inferred from call order. Keying that order per (thread,
// client_random) instead of per thread stops pooled lsass worker threads from
// carrying a stale flag between concurrent handshakes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { Tls13PhaseTracker, makeHandshakeKey } from "./tls13_phase_tracker.js";

test("first call is handshake phase, second is application phase", () => {
    const tracker = new Tls13PhaseTracker();
    const key = makeHandshakeKey(10, "aabb");
    assert.equal(tracker.nextPhase(key), "HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(tracker.nextPhase(key), "TRAFFIC_SECRET_0");
});

test("a third call restarts the cycle at handshake phase", () => {
    const tracker = new Tls13PhaseTracker();
    const key = makeHandshakeKey(10, "aabb");
    tracker.nextPhase(key);
    tracker.nextPhase(key);
    assert.equal(tracker.nextPhase(key), "HANDSHAKE_TRAFFIC_SECRET");
});

test("interleaved handshakes on the SAME thread keep independent phase", () => {
    // The bug: a per-thread flag would make handshake B's first call read as the
    // application phase because handshake A left the flag set on that thread.
    const tracker = new Tls13PhaseTracker();
    const a = makeHandshakeKey(7, "aaaa");
    const b = makeHandshakeKey(7, "bbbb");
    assert.equal(tracker.nextPhase(a), "HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(tracker.nextPhase(b), "HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(tracker.nextPhase(a), "TRAFFIC_SECRET_0");
    assert.equal(tracker.nextPhase(b), "TRAFFIC_SECRET_0");
});

test("same client_random on different threads are distinct handshakes", () => {
    const tracker = new Tls13PhaseTracker();
    const t1 = makeHandshakeKey(1, "cccc");
    const t2 = makeHandshakeKey(2, "cccc");
    assert.equal(tracker.nextPhase(t1), "HANDSHAKE_TRAFFIC_SECRET");
    assert.equal(tracker.nextPhase(t2), "HANDSHAKE_TRAFFIC_SECRET");
});

test("completed handshakes do not accumulate", () => {
    const tracker = new Tls13PhaseTracker();
    for (let i = 0; i < 100; i++) {
        const key = makeHandshakeKey(i, "rr");
        tracker.nextPhase(key);
        tracker.nextPhase(key);
    }
    assert.equal(tracker.size, 0);
});

test("aborted handshakes are evicted oldest-first once maxTracked is exceeded", () => {
    const tracker = new Tls13PhaseTracker(3);
    // Each of these only ever gets its first (handshake) call -> aborted.
    tracker.nextPhase(makeHandshakeKey(1, "a")); // oldest
    tracker.nextPhase(makeHandshakeKey(2, "b"));
    tracker.nextPhase(makeHandshakeKey(3, "c"));
    assert.equal(tracker.size, 3);
    tracker.nextPhase(makeHandshakeKey(4, "d")); // evicts (1,a)
    assert.equal(tracker.size, 3);
    // (1,a) was evicted, so its "second" call is treated as a fresh first call.
    assert.equal(
        tracker.nextPhase(makeHandshakeKey(1, "a")),
        "HANDSHAKE_TRAFFIC_SECRET",
    );
});

test("maxTracked below 1 is rejected", () => {
    assert.throws(() => new Tls13PhaseTracker(0), RangeError);
});
