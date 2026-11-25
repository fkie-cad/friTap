// Tests for the Java hook tracker (java_hook_tracker.ts).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { makeJavaHookTracker } from "./java_hook_tracker.js";

function fakeBridge() {
    return { available: true, perform: (fn: () => void) => fn() };
}

function fakeMethod(overloadCount: number) {
    const overloads = Array.from({ length: overloadCount }, () => ({ implementation: () => 1 as any }));
    return { overloads, implementation: overloads[0].implementation };
}

function collectingRegister() {
    const registered: Array<{ label: string; fn: () => void }> = [];
    return { registered, register: (label: string, fn: any) => { registered.push({ label, fn }); } };
}

test("reverts every overload of a tracked method on teardown", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("java-ssl-providers", fakeBridge, register);
    const method = fakeMethod(2);

    tracker.track(method);
    assert.equal(registered.length, 1);
    assert.equal(registered[0].label, "java-ssl-providers");
    assert.equal(tracker.pending(), 2);

    registered[0].fn();
    assert.deepEqual(method.overloads.map(o => o.implementation), [null, null]);
    assert.equal(tracker.pending(), 0);
});

test("registers one teardown for many methods and ignores duplicates", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("conscrypt", fakeBridge, register);
    const a = fakeMethod(1), b = fakeMethod(1);

    tracker.track(a);
    tracker.track(b);
    tracker.track(a);
    assert.equal(registered.length, 1);
    assert.equal(tracker.pending(), 2);
});

test("a single overload without an overloads list is reverted itself", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("single", fakeBridge, register);
    const overload = { implementation: () => 1 as any };

    tracker.track(overload);
    registered[0].fn();
    assert.equal(overload.implementation, null);
});

test("a hook installed after a teardown registers a new one", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("again", fakeBridge, register);

    tracker.track(fakeMethod(1));
    registered[0].fn();
    tracker.track(fakeMethod(1));
    assert.equal(registered.length, 2);
});

test("revert is a no-op without a Java bridge", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("no-vm", () => ({ available: false }), register);
    const method = fakeMethod(1);

    tracker.track(method);
    registered[0].fn();
    assert.notEqual(method.overloads[0].implementation, null);
    assert.equal(tracker.pending(), 0);
});

test("tracking nothing registers nothing", () => {
    const { registered, register } = collectingRegister();
    const tracker = makeJavaHookTracker("empty", fakeBridge, register);
    tracker.track(undefined);
    assert.equal(registered.length, 0);
});
