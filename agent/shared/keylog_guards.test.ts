// Unit tests for keylog_guards.ts: the three-state decode verdict helpers and
// the parameterised label self-check shared by the keylog-writer hooks.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { DECODE_UNREADABLE, isDecoded, LabelSelfCheck, unreadableIfShort } from "./keylog_guards.js";

const LIMIT = 4;
const isKnown = (label: string | null) => label === "CLIENT_RANDOM";

test("unknown labels below the limit skip, and a known label resets the run", () => {
    const check = new LabelSelfCheck(isKnown, LIMIT);
    for (let i = 0; i < LIMIT - 1; i++) assert.equal(check.observe("BOGUS"), "skip");
    assert.equal(check.observe("CLIENT_RANDOM"), "emit");
    for (let i = 0; i < LIMIT - 1; i++) assert.equal(check.observe("BOGUS"), "skip");
});

test("detach happens exactly on the limit-th unknown label in a row", () => {
    const check = new LabelSelfCheck(isKnown, LIMIT);
    const verdicts = Array.from({ length: LIMIT }, () => check.observe("BOGUS"));
    assert.deepEqual(verdicts.slice(0, -1), Array(LIMIT - 1).fill("skip"));
    assert.equal(verdicts[LIMIT - 1], "detach");
});

test("a null label (unreadable) counts as unknown", () => {
    const check = new LabelSelfCheck(isKnown, LIMIT);
    for (let i = 0; i < LIMIT - 1; i++) assert.equal(check.observe(null), "skip");
    assert.equal(check.observe(null), "detach");
});

test("isDecoded is false for a miss and for an unreadable decode", () => {
    assert.equal(isDecoded({ off: 1 }), true);
    assert.equal(isDecoded(null), false);
    assert.equal(isDecoded(DECODE_UNREADABLE), false);
});

test("unreadableIfShort: a miss on a short read proves nothing; a hit or a full-read miss stands", () => {
    assert.equal(unreadableIfShort(null, false), DECODE_UNREADABLE);
    assert.equal(unreadableIfShort(null, true), null);
    assert.deepEqual(unreadableIfShort({ off: 1 }, false), { off: 1 });
});
