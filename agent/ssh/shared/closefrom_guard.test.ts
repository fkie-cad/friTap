// Unit tests for ssh/shared/closefrom_guard.ts.
//
// WHY: OpenSSH's ssh calls closefrom(3) at the top of main(); in spawn mode that closed the
// Frida agent's channel, so every key/packet message was lost. The guard must keep exactly
// the agent's descriptors and still close everything else the target asked to close.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import { closefromTargetsToGuard, planClosefrom } from "./closefrom_guard.js";

test("planClosefrom: nothing preserved at/above lowfd -> plain closefrom(lowfd)", () => {
    assert.deepEqual(planClosefrom(3, new Set()), { closeEach: [], originalFrom: 3 });
    assert.deepEqual(planClosefrom(10, new Set([4, 7])), { closeEach: [], originalFrom: 10 });
});

test("planClosefrom: skips preserved fds, closes the gaps, original takes the rest", () => {
    assert.deepEqual(planClosefrom(3, new Set([5, 7])), { closeEach: [3, 4, 6], originalFrom: 8 });
    assert.deepEqual(planClosefrom(3, new Set([3, 4, 5])), { closeEach: [], originalFrom: 6 });
});

test("planClosefrom: preserved fds below lowfd are irrelevant", () => {
    assert.deepEqual(planClosefrom(6, new Set([4, 8])), { closeEach: [6, 7], originalFrom: 9 });
});

const fakePtr = (a: string): any => ({ toString: () => a });

test("closefromTargetsToGuard: the module copy and the global lookup are often one function", () => {
    const own = fakePtr("0x5555aaa0");
    const sameViaGlobal = fakePtr("0x5555aaa0");
    assert.deepEqual(closefromTargetsToGuard([own, sameViaGlobal], new Set()).map(String), ["0x5555aaa0"]);
});

test("closefromTargetsToGuard: skips nulls and already guarded addresses, keeps distinct ones", () => {
    const own = fakePtr("0x5555aaa0");
    const libc = fakePtr("0x7fff1230");
    assert.deepEqual(closefromTargetsToGuard([own, libc], new Set()).map(String), ["0x5555aaa0", "0x7fff1230"]);
    assert.deepEqual(closefromTargetsToGuard([null, libc], new Set(["0x7fff1230"])), []);
});
