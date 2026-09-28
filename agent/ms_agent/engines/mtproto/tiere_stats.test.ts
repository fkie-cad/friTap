// Unit test for markTierERevalidated (agent/ms_agent/engines/mtproto/scanner.ts):
// an incremental pass that re-reads remembered Connections runs Tier E's per-object
// read, so its stats must not stay at the pass-start 'off'/enabled=false (N2). The
// host's stats dump (friTap/memory_scanning/engine.py) reads tierE.state/enabled
// verbatim, so a Tier-E-touching pass must self-report enabled with a distinct state.
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/engines/mtproto/tiere_stats.test.ts)

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../../shared/frida-test-stubs.js";
import { markTierERevalidated } from "./scanner.js";

test("markTierERevalidated flips a pass-start 'off' tierE to enabled/revalidated", () => {
    const tierE = { state: "off", enabled: false, skipReason: null, vtableHits: 0, candidates: 0 };
    markTierERevalidated(tierE);
    assert.equal(tierE.enabled, true);
    assert.equal(tierE.state, "revalidated");
    // A distinct state (not 'ran'/'off') so a full-pass scan and an incremental
    // re-read are still tellable apart in the host's stats dump.
    assert.notEqual(tierE.state, "off");
    assert.notEqual(tierE.state, "ran");
});
