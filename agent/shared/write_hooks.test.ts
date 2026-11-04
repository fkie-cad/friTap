// Unit tests for shared/write_hooks.ts (attachPlaintextWriteHook / attachPlaintextReadHook).
//
// Run: npm run test:agent
//
// WHY: the hooks emit only the bytes a call transferred, and build the record metadata
// (getpeername/getsockname, session id, client random) in onLeave only when there is
// something to emit — would-block / failed calls must not pay for it.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { installFakes, call, take, addr, mem, int } from "./write_hook_fakes.js";

import { attachPlaintextReadHook, attachPlaintextWriteHook, PlaintextCallArgs } from "./write_hooks.js";
import { BufferedSendTracker, GNUTLS_E_AGAIN } from "./write_length.js";

installFakes();

/** A builder that counts its calls and records the ctx it was given. */
function countingBuilder(): { build: (a: PlaintextCallArgs) => any; calls: string[] } {
    const calls: string[] = [];
    return { calls, build: (args) => { calls.push(String(args[0])); return { function: "test" }; } };
}

test("write hook: emits min(len, retval) and builds the message only for a successful call", () => {
    const b = countingBuilder();
    attachPlaintextWriteHook(addr("w1"), b.build);
    const body = mem("0123456789");
    call("w1", [addr("ssl"), body, int(10)], -1);
    call("w1", [addr("ssl"), body, int(10)], 0);
    assert.deepEqual(b.calls, [], "failed / would-block calls do not build metadata");
    call("w1", [addr("ssl"), body, int(10)], 4);
    call("w1", [addr("ssl"), body, int(10)], 4096);
    assert.deepEqual(take(), ["0123", "0123456789"]);
    assert.deepEqual(b.calls, ["0xssl", "0xssl"]);
});

test("write hook: a null message (unattributable record) emits nothing", () => {
    attachPlaintextWriteHook(addr("w2"), () => null);
    call("w2", [addr("ssl"), mem("data"), int(4)], 4);
    assert.deepEqual(take(), []);
});

test("write hook: a negative int length never turns a failure into a huge count", () => {
    const b = countingBuilder();
    attachPlaintextWriteHook(addr("w3"), b.build);
    call("w3", [addr("ssl"), mem("data"), int(-1)], -1);
    assert.deepEqual(take(), []);
    assert.deepEqual(b.calls, []);
});

test("write hook: buffered retries attribute the record to the flushing call once", () => {
    const b = countingBuilder();
    attachPlaintextWriteHook(addr("w4"), b.build, new BufferedSendTracker());
    call("w4", [addr("sess"), mem("queued"), int(6)], GNUTLS_E_AGAIN);
    call("w4", [addr("sess"), mem(""), int(0)], 6);
    assert.deepEqual(take(), ["queued"]);
    assert.equal(b.calls.length, 1);
});

test("read hook: emits the returned byte count; errors build and emit nothing", () => {
    const b = countingBuilder();
    attachPlaintextReadHook(addr("r1"), b.build);
    call("r1", [addr("ssl"), mem("HTTP/1.1 200 OK....garbage"), int(4096)], -1);
    assert.deepEqual(b.calls, []);
    call("r1", [addr("ssl"), mem("HTTP/1.1 200 OK....garbage"), int(4096)], 15);
    assert.deepEqual(take(), ["HTTP/1.1 200 OK"]);
    assert.deepEqual(b.calls, ["0xssl"]);
});
