// Unit tests for the numeric-interval range labelling in ranges.ts.
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/core/ranges.test.ts)
//
// Regression for the on-device bug (Pixel 7 / Android 17): /proc/self/maps
// zero-pads start addresses ("02000000") while NativePointer.toString(16) does
// not ("2000000"). The OLD hex-STRING-keyed label lookup missed every zero-padded
// range — the scudo ranges libsignal's TLS structs live in — so the allowlist
// matched nothing and the scan fell back to a 20 MB anonymous subset that never
// contained the live handshake. A NUMERIC interval search is immune to the
// formatting mismatch. These tests pin that.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { findInterval, addressToNumber } from "./ranges.js";

// A fake NativePointer whose toString(16) returns UNPADDED hex, exactly like Frida.
function fakePtr(unpaddedHex: string) {
    return { toString: (_radix?: number) => unpaddedHex };
}

test("addressToNumber parses an unpadded hex pointer", () => {
    assert.equal(addressToNumber(fakePtr("2000000")), 0x02000000);
    assert.equal(addressToNumber(fakePtr("7abc1234")), 0x7abc1234);
});

test("findInterval returns the containing interval", () => {
    // Intervals as loadAnonNames builds them: [loNum, hiNum, name], sorted by lo.
    const index = [
        [0x02000000, 0x02001000, "[anon:scudo:primary]"],
        [0x10000000, 0x10008000, "[anon:dalvik-main space]"],
        [0x7abc0000, 0x7abc1000, "[anon:scudo:secondary]"],
    ];
    assert.equal(findInterval(index, 0x02000500)[2], "[anon:scudo:primary]");
    assert.equal(findInterval(index, 0x10007fff)[2], "[anon:dalvik-main space]");
    assert.equal(findInterval(index, 0x7abc0000)[2], "[anon:scudo:secondary]"); // inclusive lo
});

test("findInterval excludes the end address and gaps/out-of-range", () => {
    const index = [
        [0x02000000, 0x02001000, "a"],
        [0x10000000, 0x10008000, "b"],
    ];
    assert.equal(findInterval(index, 0x02001000), null); // end is exclusive
    assert.equal(findInterval(index, 0x0fffffff), null); // in the gap
    assert.equal(findInterval(index, 0x00000000), null); // below all
    assert.equal(findInterval(index, 0xffffffff), null); // above all
    assert.equal(findInterval([], 0x1000), null);        // empty index
});

test("the zero-pad bug is fixed: a padded maps interval is found for an unpadded pointer", () => {
    // The maps line was "02000000-02001000 ... [anon:scudo:primary]" -> lo=0x02000000.
    // Frida reports the same range with base.toString(16) === "2000000" (no pad).
    // Numeric lookup matches; the old string-key lookup (anonNames["2000000"]) missed.
    const index = [[0x02000000, 0x02001000, "[anon:scudo:primary]"]];
    const value = addressToNumber(fakePtr("2000000"));
    assert.equal(findInterval(index, value)[2], "[anon:scudo:primary]");
});
