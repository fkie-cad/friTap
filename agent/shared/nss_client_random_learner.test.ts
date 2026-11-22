// Unit tests for the tier-2 NSS client_random learner (agent/shared/nss_client_random_learner.ts):
// attribution, per-socket validation and global acceptance, replayed over two real Fenix 160.0.1
// arm64 probe runs (fixture: __fixtures__/nss_client_random_fenix160.ts) plus synthetic edge cases.
//
// Run: npm run test:agent

import "./frida-test-stubs.js";
import { test } from "node:test";
import assert from "node:assert/strict";

import {
    ACCEPTANCE_QUORUM, NssClientRandomLearner, isPlausibleClientRandomOffset,
} from "./nss_client_random_learner.js";
import { RUN1, RUN2, type ReplayEvent } from "./__fixtures__/nss_client_random_fenix160.js";

const ZERO = "0".repeat(64);
const r = (n: number) => n.toString(16).padStart(2, "0").repeat(32);
const A = (hex: string) => BigInt(hex);

interface ReplayResult {
    emitted: number;
    matched: number;
    /** key events of sockets the learner never tracked (pre-attach) or could not validate */
    silent: number;
    accepted: number | null;
    acceptedAfter: number | null;
    disagreed: boolean;
}

/** Replay a fixture run: every "k" event is a secret callback reading live r650 / r670. */
function replay(events: ReplayEvent[]): ReplayResult {
    let acceptedAfter: number | null = null;
    const learner = new NssClientRandomLearner({ onAccepted: (_o, n) => { acceptedAfter = n; } });
    const res: ReplayResult = { emitted: 0, matched: 0, silent: 0, accepted: null, acceptedAfter: null, disagreed: false };
    for (const ev of events) {
        if (ev[0] === "i") learner.trackSocket(A(ev[1]));
        else if (ev[0] === "g") learner.attribute(A(ev[1]), ev[2], true);
        else {
            const [, ss, , r650, r670] = ev;
            const live = (off: number) => (off === 0x650 ? r650 : off === 0x670 ? r670 : null);
            // NSS source order: the accepted offset first, else this socket's validated one.
            const off = learner.acceptedOffset ?? learner.validateSocket(A(ss), live);
            if (off === null) { res.silent++; continue; }
            res.emitted++;
            if (live(off) === r650) res.matched++; // NSS's own keylog logged ss+0x650
        }
    }
    res.accepted = learner.acceptedOffset;
    res.acceptedAfter = acceptedAfter;
    res.disagreed = learner.disagreed;
    return res;
}

test("replay of both Fenix runs: every emitted client_random equals NSS's own keylog, +0x650 accepted", () => {
    for (const run of [RUN1, RUN2]) {
        const res = replay(run);
        assert.ok(res.emitted > 30, `emitted ${res.emitted}`);
        assert.equal(res.matched, res.emitted);
        assert.equal(res.silent, 0); // every socket in these runs was created after attach
        assert.equal(res.accepted, 0x650);
        assert.equal(res.acceptedAfter, ACCEPTANCE_QUORUM);
        assert.equal(res.disagreed, false);
    }
});

test("0x2000-spaced neighbours: the random goes to the nearest socket, not the lower one in the window", () => {
    // RUN2: sslSockets 0x6f983c6000 and 0x6f983c8000; the random at 0x6f983c8650 is +0x2650 from the lower one.
    const learner = new NssClientRandomLearner();
    learner.trackSocket(A("0x6f983c6000"));
    learner.trackSocket(A("0x6f983c8000"));
    const hit = learner.attribute(A("0x6f983c8650"), r(1), true);
    assert.deepEqual(hit, { ss: A("0x6f983c8000"), offset: 0x650 });
    assert.equal(learner.validateSocket(A("0x6f983c6000"), () => r(1)), null); // nothing attributed
    assert.equal(learner.validateSocket(A("0x6f983c8000"), (o) => (o === 0x650 ? r(1) : null)), 0x650);
});

test("ECH: outer at +0x650 and inner at +0x670; valid before (outer) and after (inner) the swap", () => {
    for (const live650 of [r(1) /* outer, no swap yet */, r(2) /* inner copied over */]) {
        const learner = new NssClientRandomLearner();
        learner.trackSocket(A("0x1000000"));
        learner.attribute(A("0x1000650"), r(1), true);
        learner.attribute(A("0x1000670"), r(2), true);
        assert.equal(learner.validateSocket(A("0x1000000"), (o) => (o === 0x650 ? live650 : r(2))), 0x650);
    }
});

test("server_random next to a written client_random is rejected (the 32 bytes after it are not zero)", () => {
    const learner = new NssClientRandomLearner();
    learner.trackSocket(A("0x1000000"));
    assert.equal(learner.attribute(A("0x1000630"), r(9), false), null);
    learner.attribute(A("0x1000650"), r(1), true);
    assert.equal(learner.validateSocket(A("0x1000000"), (o) => (o === 0x650 ? r(1) : r(9))), 0x650);
});

test("heap sid buffers and misaligned or far destinations are ignored", () => {
    const learner = new NssClientRandomLearner();
    learner.trackSocket(A("0x71d6fdc000"));
    assert.equal(learner.attribute(A("0x704b2fab81"), r(3), true), null); // RUN1 heap buffer below every socket
    assert.equal(learner.attribute(A("0x71d6fdc652"), r(3), true), null); // not 4-aligned
    assert.equal(learner.attribute(A("0x71d6fe0000"), r(3), true), null); // +0x4000: outside the window
    assert.equal(learner.validateSocket(A("0x71d6fdc000"), () => r(3)), null);
});

test("address reuse at SSL_ImportFD resets the old socket's randoms", () => {
    const learner = new NssClientRandomLearner();
    learner.trackSocket(A("0x1000000"));
    learner.attribute(A("0x1000650"), r(1), true);
    learner.trackSocket(A("0x1000000"));
    assert.equal(learner.validateSocket(A("0x1000000"), () => r(1)), null);
    learner.attribute(A("0x1000650"), r(2), true);
    assert.equal(learner.validateSocket(A("0x1000000"), () => r(2)), 0x650);
});

test("global acceptance needs 3 agreeing sockets at distinct addresses", () => {
    const accepted: number[] = [];
    const learner = new NssClientRandomLearner({ onAccepted: (o) => accepted.push(o) });
    const validate = (base: number, n: number) => {
        learner.trackSocket(BigInt(base));
        learner.attribute(BigInt(base + 0x650), r(n), true);
        return learner.validateSocket(BigInt(base), () => r(n));
    };
    validate(0x1000000, 1);
    validate(0x1000000, 2); // same address again (reuse): still one vote
    validate(0x2000000, 3);
    assert.equal(learner.acceptedOffset, null);
    validate(0x3000000, 4);
    assert.equal(learner.acceptedOffset, 0x650);
    assert.deepEqual(accepted, [0x650]);
    assert.equal(learner.settled, true);
    assert.equal(learner.attribute(A("0x4000650"), r(5), true), null); // settled: no more learning
});

test("disagreement is never accepted and fails closed for every socket", () => {
    const disagreements: number[][] = [];
    const learner = new NssClientRandomLearner({ onDisagreement: (o) => disagreements.push(o) });
    for (const [base, off] of [[0x1000000, 0x650], [0x2000000, 0x650], [0x3000000, 0x670], [0x4000000, 0x650]]) {
        learner.trackSocket(BigInt(base));
        learner.attribute(BigInt(base + off), r(base >> 24), true);
        learner.validateSocket(BigInt(base), () => r(base >> 24));
    }
    assert.equal(learner.acceptedOffset, null);
    assert.equal(learner.disagreed, true);
    assert.deepEqual(disagreements, [[0x650, 0x670]]);
    assert.equal(learner.validatedOffset(A("0x1000000")), null);
});

test("an unvalidated socket emits nothing: mismatch is sticky, untracked / unwritten are not decided", () => {
    const learner = new NssClientRandomLearner();
    assert.equal(learner.validateSocket(A("0x9000000"), () => r(1)), null); // pre-attach socket
    learner.trackSocket(A("0x1000000"));
    learner.attribute(A("0x1000650"), r(1), true);
    assert.equal(learner.validateSocket(A("0x1000000"), () => ZERO), null);     // not written yet
    assert.equal(learner.validateSocket(A("0x1000000"), () => r(7)), null);     // mismatch
    assert.equal(learner.validateSocket(A("0x1000000"), () => r(1)), null);     // sticky
    assert.equal(learner.validatedOffset(A("0x1000000")), null);
    assert.equal(learner.mismatches, 1);
});

test("cached offsets must be inside the window and 4-aligned", () => {
    assert.equal(isPlausibleClientRandomOffset(0x650), true);
    for (const bad of [0, -4, 0x652, 0x4000, 1.5, "0x650", null]) assert.equal(isPlausibleClientRandomOffset(bad), false);
});
