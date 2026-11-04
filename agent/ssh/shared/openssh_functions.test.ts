// Unit tests for ssh/shared/openssh_functions.ts: where the hooked OpenSSH functions are
// (export first, string anchors for the stripped Debian/Ubuntu builds).
//
// The anchor table itself is verified offline against the real stripped binaries and
// their debug symbols (Debian 12/13, Ubuntu 22.04/24.04, arm64 + amd64); these tests pin
// the selection logic on top of locateFunctionsByAnchors.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import {
    OPENSSH_FUNCTION_ANCHORS, needsAnchorResolution, openSshFunction, pickFunctions, planAnchors,
} from "./openssh_functions.js";
import type { AnchorFunctions } from "../../shared/string_anchor_functions.js";

const G = globalThis as any;

/** Minimal pointer: identity by address. */
const P = (a: number): any => ({
    a, toString: () => "0x" + a.toString(16), equals: (o: any) => o.a === a,
    compare: (o: any) => (a < o.a ? -1 : a > o.a ? 1 : 0), sub: (o: any) => P(a - o.a), isNull: () => a === 0,
});
const fnAt = (start: number): AnchorFunctions =>
    ({ functions: [{ start: P(start), end: P(start + 0x100), sites: [P(start + 8)] }], unboundedSites: [] });
const none: AnchorFunctions = { functions: [], unboundedSites: [] };

/** Results for a plan: `at(text)` gives the function that loads literal `text` (or none). */
function resultsFor(plan: ReturnType<typeof planAnchors>, at: Record<string, number | number[]>): AnchorFunctions[] {
    return plan.specs.map((s) => {
        const v = at[s.text];
        if (v === undefined) return none;
        const starts = Array.isArray(v) ? v : [v];
        return { functions: starts.map((x) => fnAt(x).functions[0]), unboundedSites: [] };
    });
}

test("planAnchors: one spec per distinct literal, slots index into it", () => {
    const plan = planAnchors(["ssh_packet_read_poll2", "ssh_packet_read_poll_seqnr"]);
    const texts = plan.specs.map((s) => s.text);
    assert.equal(new Set(texts).size, texts.length, "no duplicate literal");
    const [poll2, seqnr] = plan.slots;
    assert.deepEqual(poll2.anchors.map((i) => texts[i]), OPENSSH_FUNCTION_ANCHORS.ssh_packet_read_poll2.anchors);
    // read_poll2's exclusions are read_poll_seqnr's own anchors: shared, listed once.
    assert.ok(poll2.notIn.every((i) => seqnr.anchors.includes(i)));
});

test("every anchored function has a message anchor besides its __func__ (arm64 sees only messages)", () => {
    for (const [name, entry] of Object.entries(OPENSSH_FUNCTION_ANCHORS)) {
        assert.ok(entry.anchors.some((a) => a !== name), `${name} needs a message anchor`);
        for (const excluded of entry.notIn ?? []) assert.ok(!entry.anchors.includes(excluded));
    }
});

test("pickFunctions: Debian layout — every function in its own place", () => {
    const plan = planAnchors(["kex_derive_keys", "ssh_packet_read_poll2", "ssh_packet_read_poll_seqnr"]);
    const picked = pickFunctions(plan, resultsFor(plan, {
        "kex_derive_keys": 0x1000, "already have session ID at kex": 0x1000, "no session ID in rekex": 0x1000,
        "receive packet: type %u": 0x2000, "incoming seqnr wraps around": 0x2000,
        "Received SSH2_MSG_IGNORE": 0x3000, "ssh_packet_read_poll_seqnr": 0x3000,
    }));
    assert.equal(String(picked.get("kex_derive_keys")), "0x1000");
    assert.equal(String(picked.get("ssh_packet_read_poll2")), "0x2000");
    assert.equal(String(picked.get("ssh_packet_read_poll_seqnr")), "0x3000");
});

test("pickFunctions: Ubuntu LTO — read_poll2 inlined into read_poll_seqnr is not hooked as itself", () => {
    const plan = planAnchors(["ssh_packet_read_poll2", "ssh_packet_read_poll_seqnr"]);
    // arm64: no __func__ loads are visible, only messages; all of them sit in one function.
    const picked = pickFunctions(plan, resultsFor(plan, {
        "receive packet: type %u": 0x4000, "incoming seqnr wraps around": 0x4000, "resetting read seqnr %u": 0x4000,
        "Received SSH2_MSG_IGNORE": 0x4000,
    }));
    assert.equal(picked.has("ssh_packet_read_poll2"), false);
    assert.equal(String(picked.get("ssh_packet_read_poll_seqnr")), "0x4000");
});

test("pickFunctions: a literal loaded from two functions locates nothing", () => {
    const plan = planAnchors(["kex_send_kexinit"]);
    const picked = pickFunctions(plan, resultsFor(plan, { "SSH2_MSG_KEXINIT sent": [0x1000, 0x5000] }));
    assert.equal(picked.size, 0);
});

test("pickFunctions: two functions on one start are both dropped", () => {
    const plan = planAnchors(["kex_send_kexinit", "kex_input_kexinit"]);
    const picked = pickFunctions(plan, resultsFor(plan, {
        "SSH2_MSG_KEXINIT sent": 0x1000, "SSH2_MSG_KEXINIT received": 0x1000,
    }));
    assert.equal(picked.size, 0);
});

// ---- module-facing entry points (Frida globals stubbed) -----------------------------------

function withModule(exports: string[], ranges: boolean, body: () => void): void {
    const prev = { find: G.Process.findModuleByName, platform: G.Process.platform };
    G.Process.platform = "linux";
    G.Process.findModuleByName = (name: string) => ({
        name, path: "/usr/bin/" + name, base: P(0x10000),
        findExportByName: (s: string) => (exports.includes(s) ? P(0x20000) : null),
        enumerateExports: () => [],
        enumerateRanges: () => {
            if (!ranges) throw new Error("no ranges in this stub");
            return [];
        },
    });
    try { body(); } finally { G.Process.findModuleByName = prev.find; G.Process.platform = prev.platform; }
}

test("openSshFunction prefers the export", () => withModule(["kex_derive_keys"], true, () => {
    assert.equal(String(openSshFunction("ssh", "kex_derive_keys")), "0x20000");
    assert.equal(openSshFunction("ssh", "ssh_set_newkeys"), null, "not exported, not located");
}));

test("needsAnchorResolution: not when everything is exported, not off Linux, not without the marker", () => {
    const all = Object.keys(OPENSSH_FUNCTION_ANCHORS);
    withModule(all, true, () => assert.equal(needsAnchorResolution("ssh-exported"), false));
    withModule([], true, () => assert.equal(needsAnchorResolution("ssh-no-marker"), false, "no OpenSSH literal"));
    withModule([], false, () => assert.equal(needsAnchorResolution("ssh-no-ranges"), false, "never throws"));
    withModule([], true, () => {
        G.Process.platform = "darwin";
        assert.equal(needsAnchorResolution("ssh-darwin"), false);
    });
});
