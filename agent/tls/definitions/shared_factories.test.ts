// Unit tests for createLifecycleHook's optional onFreed callback (P1: SSL_free ->
// ssl_identity.forgetSslIdentity in the modern tree).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import { createLifecycleHook } from "./shared_factories.js";

const G = globalThis as any;

function fakePtr(name: string, isNull = false): any {
    return { name, isNull: () => isNull, toString: () => `0x${name}` };
}

/** Install `hook` against a fake SSL_free and return its onEnter. */
function installAndCaptureOnEnter(hook: ReturnType<typeof createLifecycleHook>): (args: any[]) => void {
    let captured: any = null;
    const previous = G.Interceptor.attach;
    G.Interceptor.attach = (_target: any, callbacks: any) => { captured = callbacks; return { detach: () => { } }; };
    try {
        hook.install({ libssl: { SSL_free: fakePtr("SSL_free") } } as any, "libssl", {} as any, false);
    } finally {
        G.Interceptor.attach = previous;
    }
    assert.ok(captured, "SSL_free was hooked");
    return (args: any[]) => captured.onEnter.call({}, args);
}

const throwingFdDecoder = () => { throw new Error("torn down"); };

test("onFreed runs with the freed context even when the lifecycle event fails", () => {
    const freed: any[] = [];
    const onEnter = installAndCaptureOnEnter(
        createLifecycleHook("SSL_free", throwingFdDecoder, () => "", undefined, (ctx) => freed.push(ctx)),
    );
    const ssl = fakePtr("ssl1");
    onEnter([ssl]);
    assert.deepEqual(freed, [ssl]);
});

test("onFreed is skipped for a NULL context and is optional", () => {
    const freed: any[] = [];
    const onEnter = installAndCaptureOnEnter(
        createLifecycleHook("SSL_free", throwingFdDecoder, () => "", undefined, (ctx) => freed.push(ctx)),
    );
    onEnter([fakePtr("null", true)]);
    assert.deepEqual(freed, []);
    const withoutCallback = installAndCaptureOnEnter(createLifecycleHook("SSL_free", throwingFdDecoder, () => ""));
    assert.doesNotThrow(() => withoutCallback([fakePtr("ssl2")]));
});

test("a throwing onFreed never escapes the SSL_free hook", () => {
    const onEnter = installAndCaptureOnEnter(
        createLifecycleHook("SSL_free", throwingFdDecoder, () => "", undefined, () => { throw new Error("boom"); }),
    );
    assert.doesNotThrow(() => onEnter([fakePtr("ssl3")]));
});
