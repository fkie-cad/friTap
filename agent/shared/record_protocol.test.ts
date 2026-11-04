// Unit tests for agent/shared/record_protocol.ts — binding a registry row's
// record protocol to everything its executor's hooks send.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import {
    activeRecordProtocol,
    bindListenerCallbacks,
    bindRecordProtocol,
    executeHookRow,
    recordProtocolOf,
    runHookExecutor,
    runWithRecordProtocol,
} from "./record_protocol.js";

/** A fake Interceptor whose attach stores the listener so the test can fire it. */
function fakeInterceptor() {
    const attached: any[] = [];
    const interceptor: any = {
        attach(_target: unknown, callbacks: any) { attached.push(callbacks); return { detach() {} }; },
        flush() { return this === interceptor; },
        defaults: { mode: "x" },
    };
    Object.defineProperty(interceptor, "attach", { writable: false, configurable: false, value: interceptor.attach });
    return { interceptor, attached };
}

test("recordProtocolOf defaults to the install protocol", () => {
    assert.equal(recordProtocolOf({ protocol: "ssh" }), "ssh");
    assert.equal(recordProtocolOf({ protocol: "tls", recordProtocol: "quic" }), "quic");
});

test("runWithRecordProtocol restores the previous value, also on throw", () => {
    assert.equal(activeRecordProtocol(), undefined);
    runWithRecordProtocol("ssh", () => {
        assert.equal(activeRecordProtocol(), "ssh");
        assert.throws(() => runWithRecordProtocol("ipsec", () => { throw new Error("x"); }));
        assert.equal(activeRecordProtocol(), "ssh");
    });
    assert.equal(activeRecordProtocol(), undefined);
});

test("bindRecordProtocol captures the protocol active at bind time and keeps `this`", () => {
    const bound = runWithRecordProtocol("signal", () =>
        bindRecordProtocol(function (this: any, a: number) { return [this.tag, a, activeRecordProtocol()]; }));
    assert.deepEqual(bound.call({ tag: "self" }, 7), ["self", 7, "signal"]);
    const plain = () => 1;
    assert.equal(bindRecordProtocol(plain), plain, "no active protocol: unchanged");
});

test("bindListenerCallbacks binds onEnter/onLeave, keeps other members, passes native callbacks through", () => {
    const seen: (string | undefined)[] = [];
    const callbacks = { extra: 42, onEnter() { seen.push(activeRecordProtocol()); }, onLeave() { seen.push(activeRecordProtocol()); } };
    const bound = bindListenerCallbacks(callbacks, "ssh");
    bound.onEnter([]); bound.onLeave(null);
    assert.equal(bound.extra, 42);
    assert.deepEqual(seen, ["ssh", "ssh"]);
    const native = { onEnter: { isNull: () => false } };
    assert.equal(bindListenerCallbacks(native, "ssh"), native);
    const fn = bindListenerCallbacks(() => activeRecordProtocol(), "ipsec");
    assert.equal(fn(), "ipsec");
});

test("runHookExecutor binds listeners attached synchronously, then restores Interceptor", () => {
    const { interceptor, attached } = fakeInterceptor();
    const scope: any = { Interceptor: interceptor };
    runHookExecutor("ssh", () => {
        scope.Interceptor.attach(null, { onEnter() { return activeRecordProtocol(); } });
        assert.equal(scope.Interceptor.flush(), true, "other members forwarded with the real `this`");
        assert.equal(scope.Interceptor.defaults.mode, "x");
    }, scope);
    assert.equal(scope.Interceptor, interceptor);
    assert.equal(attached[0].onEnter(), "ssh", "listener fires later under its row's protocol");
    assert.equal(activeRecordProtocol(), undefined);
});

test("runHookExecutor leaves TLS-family listeners unwrapped", () => {
    const { interceptor, attached } = fakeInterceptor();
    const scope: any = { Interceptor: interceptor };
    const callbacks = { onEnter() {} };
    runHookExecutor("tls", () => scope.Interceptor.attach(null, callbacks), scope);
    assert.equal(attached[0], callbacks);
});

test("executeHookRow runs the row's executor under its record protocol and returns its outcome", () => {
    const row: any = { protocol: "rc4", hookFn: (name: string) => (name === "libcrypto" ? activeRecordProtocol() === "rc4" : false) };
    assert.equal(executeHookRow(row, "libcrypto", true), true);
});
