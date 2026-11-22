// Unit tests for the tier-2 NSS ECH random recorder (agent/shared/nss_ech_random_recorder.ts):
// attribution, inner/outer decision at the secret callback, HRR, address reuse, bounds.
//
// Run: npm run test:agent

import "./frida-test-stubs.js";
import { test } from "node:test";
import assert from "node:assert/strict";

import { MAX_ECH_OFFSETS_PER_SOCKET, NssEchRandomRecorder } from "./nss_ech_random_recorder.js";
import { NssClientRandomLearner } from "./nss_client_random_learner.js";
import { MAX_TRACKED_SOCKETS, NssTrackedSockets } from "./nss_tracked_sockets.js";

const r = (n: number) => n.toString(16).padStart(2, "0").repeat(32);
const SS = 0x6f983c8000n;
const OFF = 0x650;

/** A socket with the Fenix 160 layout: outer at +0x650, inner at +0x670. */
function echSocket(recorder: NssEchRandomRecorder, ss: bigint = SS): void {
    recorder.trackSocket(ss);
    recorder.record(ss + BigInt(OFF), r(1));      // outer client_random
    recorder.record(ss + BigInt(OFF + 32), r(2)); // client_inner_random
}

test("ECH accepted (inner copied over client_random): keyed with inner, then outer", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2), r(1)]);
});

test("ECH offered but rejected / not yet swapped (live is the outer random): single line", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(1)), [r(1)]);
});

test("non-ECH socket (only a client_random generated): single line", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(SS);
    recorder.record(SS + BigInt(OFF), r(1));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(1)), [r(1)]);
});

test("untracked (pre-attach) socket and unrecorded live bytes: the live random only", () => {
    const recorder = new NssEchRandomRecorder();
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(9)), [r(9)]);
    echSocket(recorder);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(9)), [r(9)]);
});

test("live bytes are compared case-insensitively and returned lower-case", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(0xab).toUpperCase()), [r(0xab)]);
    recorder.trackSocket(SS);
    recorder.record(SS + BigInt(OFF), r(0x11));
    recorder.record(SS + BigInt(OFF + 32), r(0xcd));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(0xcd).toUpperCase()), [r(0xcd), r(0x11)]);
});

test("HRR / later generation at the same field: the first random per offset wins", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    recorder.record(SS + BigInt(OFF), r(7));
    recorder.record(SS + BigInt(OFF + 32), r(8));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2), r(1)]);
});

test("no second random (no inner generated): never dual, even if outer equals live", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(SS);
    recorder.record(SS + BigInt(OFF), r(1));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2)]);
});

test("identical outer and inner randoms collapse to one line (dedupe)", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(SS);
    recorder.record(SS + BigInt(OFF), r(3));
    recorder.record(SS + BigInt(OFF + 32), r(3));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(3)), [r(3)]);
});

test("attribution: nearest socket at/below, 4-aligned, inside the window", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(0x6f983c6000n);
    recorder.trackSocket(SS);
    assert.deepEqual(recorder.record(SS + 0x650n, r(1)), { ss: SS, offset: 0x650 });
    assert.equal(recorder.record(SS + 0x652n, r(1)), null);   // misaligned
    assert.equal(recorder.record(SS + 0x4000n, r(1)), null);  // outside the window
    assert.equal(recorder.record(0x1000n, r(1)), null);       // no socket below
    assert.equal(recorder.record(SS + 0x700n, "zz"), null);   // not a 32-byte hex random
});

test("address reuse on SSL_ImportFD resets the socket's randoms", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    recorder.trackSocket(SS); // a new sslSocket at the same address
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2)]);
    recorder.record(SS + BigInt(OFF), r(4));
    recorder.record(SS + BigInt(OFF + 32), r(5));
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(5)), [r(5), r(4)]);
});

test("forgetSocket (PR_Close) drops the record and stops attribution to it", () => {
    const recorder = new NssEchRandomRecorder();
    echSocket(recorder);
    recorder.forgetSocket(SS);
    assert.equal(recorder.trackedSockets, 0);
    assert.equal(recorder.record(SS + BigInt(OFF), r(1)), null);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2)]);
});

test("cap: at most MAX_TRACKED_SOCKETS sockets, the oldest dropped", () => {
    const recorder = new NssEchRandomRecorder();
    for (let i = 0; i <= MAX_TRACKED_SOCKETS; i++) recorder.trackSocket(BigInt(i + 1) * 0x10000n);
    assert.equal(recorder.trackedSockets, MAX_TRACKED_SOCKETS);
    assert.equal(recorder.record(0x10000n + 0x650n, r(1)), null); // the first one is gone
    assert.notEqual(recorder.record(0x20000n + 0x650n, r(1)), null);
});

test("cap: at most MAX_ECH_OFFSETS_PER_SOCKET offsets recorded per socket", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(SS);
    for (let i = 0; i < MAX_ECH_OFFSETS_PER_SOCKET; i++) assert.notEqual(recorder.record(SS + BigInt(0x100 + i * 0x40), r(i + 1)), null);
    assert.equal(recorder.record(SS + 0x3000n, r(0x77)), null);
    assert.notEqual(recorder.record(SS + 0x100n, r(0x78)), null); // an already recorded offset still answers
});

test("recording continues after the learner accepted (learning + recording coexist)", () => {
    const learner = new NssClientRandomLearner({}, 1);
    const recorder = new NssEchRandomRecorder();
    for (const ss of [0x1000000n, SS]) { learner.trackSocket(ss); recorder.trackSocket(ss); }
    learner.attribute(0x1000000n + 0x650n, r(1), true);
    recorder.record(0x1000000n + 0x650n, r(1));
    assert.equal(learner.validateSocket(0x1000000n, () => r(1)), 0x650);
    assert.equal(learner.acceptedOffset, 0x650);
    // The learner stops attributing once settled, the recorder keeps going.
    assert.equal(learner.attribute(SS + 0x650n, r(5), true), null);
    assert.deepEqual(recorder.record(SS + 0x650n, r(5)), { ss: SS, offset: 0x650 });
    assert.deepEqual(recorder.record(SS + 0x670n, r(6)), { ss: SS, offset: 0x670 });
    assert.deepEqual(recorder.keylogRandoms(SS, learner.acceptedOffset!, r(6)), [r(6), r(5)]);
});

// ---- shared store: one attribution for both consumers ----------------------------------

test("shared store: one trackSocket serves the learner and the recorder", () => {
    const sockets = new NssTrackedSockets();
    const learner = new NssClientRandomLearner({}, 1, sockets);
    const recorder = new NssEchRandomRecorder(sockets);
    sockets.track(SS);
    const hit = sockets.locate(SS + 0x650n)!;
    assert.deepEqual(hit, { ss: SS, offset: 0x650 });
    assert.deepEqual(learner.attributeAt(hit, r(1), true), hit);
    assert.deepEqual(recorder.recordAt(hit, r(1)), hit);
    assert.equal(learner.validateSocket(SS, () => r(1)), 0x650);
    sockets.forget(SS);
    assert.equal(learner.trackedSockets, 0);
    assert.equal(recorder.trackedSockets, 0);
});

test("known offset: O(1) attribution to data-off (outer) or data-off-32 (inner), nothing else", () => {
    const sockets = new NssTrackedSockets();
    sockets.track(0x6f983c6000n);
    sockets.track(SS);
    assert.deepEqual(sockets.locate(SS + 0x650n, OFF), { ss: SS, offset: 0x650 });
    assert.deepEqual(sockets.locate(SS + 0x670n, OFF), { ss: SS, offset: 0x670 });
    assert.equal(sockets.locate(SS + 0x700n, OFF), null);              // not a client_random field
    assert.deepEqual(sockets.locate(SS + 0x700n), { ss: SS, offset: 0x700 }); // the scan would take it
    assert.equal(sockets.locate(0x6f983c6000n + 0x2650n, 0x2650 + 4), null);
});

test("recordAt ignores all-zero bytes (not a generated random)", () => {
    const recorder = new NssEchRandomRecorder();
    recorder.trackSocket(SS);
    assert.equal(recorder.record(SS + 0x650n, "0".repeat(64)), null);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2)]);
});

test("clear() drops recorded randoms but keeps the shared tracked sockets", () => {
    const sockets = new NssTrackedSockets();
    const recorder = new NssEchRandomRecorder(sockets);
    echSocket(recorder);
    recorder.clear();
    assert.equal(sockets.size, 1);
    assert.deepEqual(recorder.keylogRandoms(SS, OFF, r(2)), [r(2)]);
});
