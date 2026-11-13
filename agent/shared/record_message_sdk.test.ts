// SDK attribution for endpointless records (I2.1 option 5): an fd-less record that is
// kept without address fields must still offer its client_random to a held
// caller_stack (offerCallerStackJoin), exactly like an addressed record does.
//
// Run: npm run test:agent
//
// --attribute-sdk is read from the agent's config_batch handshake when fritap_agent.ts
// is first evaluated, so this file answers that handshake with attribute_sdk: true and
// imports the modules under test only afterwards (dynamic imports inside the tests: the
// test runner compiles to CommonJS, which has no top-level await).

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.recv = (channel: string, callback: (value: any) => void) => {
    if (channel === "config_batch") callback({ payload: { attribute_sdk: true } });
    return { wait: () => undefined };
};
const sentMessages: any[] = [];
G.send = (message: any) => { sentMessages.push(message); };
G.Thread = { backtrace: () => [] };
G.Backtracer = { ACCURATE: 0, FUZZY: 1 };

/** The modules under test, imported only after the config handshake above is answered. */
async function modulesUnderTest() {
    const { buildEndpointlessRecord, finishSslRecord } = await import("./record_message.js");
    const { maybeCaptureCallerStack } = await import("./sdk_backtrace.js");
    const { attribute_sdk } = await import("../fritap_agent.js");
    return { buildEndpointlessRecord, finishSslRecord, maybeCaptureCallerStack, attribute_sdk };
}

const CR = "ef".repeat(32);
const MODULE = "libwebviewchromium.so";

function fakeSsl(address: number): any {
    return { isNull: () => address === 0, toString: () => "0x" + address.toString(16) };
}

function callerStacksSent(): any[] {
    return sentMessages.filter((m) => m && (m.contentType === "caller_stack" || m.payload?.contentType === "caller_stack"));
}

test("the config handshake turned --attribute-sdk on for this file", async () => {
    const { attribute_sdk } = await modulesUnderTest();
    assert.equal(attribute_sdk, true);
});

test("buildEndpointlessRecord offers its client_random to a held caller_stack (sent once)", async () => {
    const { buildEndpointlessRecord, maybeCaptureCallerStack } = await modulesUnderTest();
    const ssl = fakeSsl(0x9100);
    maybeCaptureCallerStack(ssl, {} as any, () => ({}), { transportModule: MODULE });
    assert.equal(callerStacksSent().length, 0, "a cr-less capture is held");

    const message = buildEndpointlessRecord(
        { fd: -1, isRead: false, functionName: "SSL_write", methodAddresses: {}, enableDefaultFd: false,
          library: MODULE, ssl, clientRandom: () => CR },
        () => ({ ssl_session_id: "" }),
    );
    assert.equal(message.client_random, CR);
    const sent = callerStacksSent();
    assert.equal(sent.length, 1, "the held caller_stack was sent by the endpointless record's offer");
    assert.equal(JSON.stringify(sent[0]).includes(CR), true, "sent with the record's client_random");
});

test("finishSslRecord (class-based hooks, e.g. Cronet) offers an addressed record to a held caller_stack", async () => {
    const { finishSslRecord, maybeCaptureCallerStack } = await modulesUnderTest();
    const ssl = fakeSsl(0x9200);
    const cr = "a7".repeat(32);
    const before = callerStacksSent().length;
    maybeCaptureCallerStack(ssl, {} as any, () => ({}), { transportModule: MODULE });
    assert.equal(callerStacksSent().length, before, "a cr-less capture is held");

    const message: { [key: string]: any } = { src_addr: "10.0.0.2", dst_addr: "93.184.215.14", src_port: 50001, dst_port: 443 };
    finishSslRecord(message, {
        library: MODULE, methodAddresses: {}, enableDefaultFd: false,
        probeClientRandom: () => cr, sessionFields: () => ({}),
    }, ssl, "SSL_write", false);
    assert.equal(message.client_random, cr);
    const sent = callerStacksSent();
    assert.equal(sent.length, before + 1, "the held caller_stack was sent by the record's offer");
    assert.equal(JSON.stringify(sent[sent.length - 1]).includes(cr), true, "sent with the record's client_random");
});

// ---------------------------------------------------------------------------
// SSL_free in either hook order: --modern attaches the lifecycle hook (whose
// onFreed calls forgetSslIdentity) BEFORE the fd-scope hook (forgetSsl), the
// legacy tree may run only forgetSsl. The held caller_stack must be found and
// sent (it has a 5-tuple) regardless of which runs first.
// ---------------------------------------------------------------------------

/** Its own module, with a layout locator still pending: a client_random may still arrive. */
const FREE_MODULE = "libsslfree_order_test.so";
const HELD_TUPLE = { src_addr: "10.0.0.2", dst_addr: "93.184.215.14", src_port: 50002, dst_port: 443 };

async function captureHeldThenFree(address: number, identityForgottenFirst: boolean): Promise<number> {
    const { maybeCaptureCallerStack } = await modulesUnderTest();
    const { forgetSsl } = await import("./sdk_backtrace.js");
    const { forgetSslIdentity, markLayoutLocatorStarted } = await import("./ssl_identity.js");
    markLayoutLocatorStarted(FREE_MODULE);
    const ssl = fakeSsl(address);
    const before = callerStacksSent().length;
    maybeCaptureCallerStack(ssl, {} as any, () => ({ ...HELD_TUPLE }), { transportModule: FREE_MODULE });
    assert.equal(callerStacksSent().length, before, "held: a client_random may still arrive");
    const prevPtr = G.ptr;
    G.ptr = (value: any) => fakeSsl(Number(value));
    try {
        if (identityForgottenFirst) forgetSslIdentity(ssl);
        forgetSsl(ssl.toString());
        if (!identityForgottenFirst) forgetSslIdentity(ssl);
    } finally {
        G.ptr = prevPtr;
    }
    return callerStacksSent().length - before;
}

test("SSL_free (fd-scope hook first): the held caller_stack is sent once", async () => {
    assert.equal(await captureHeldThenFree(0x9300, false), 1);
});

test("SSL_free (--modern: lifecycle forgetSslIdentity first): the held caller_stack is still sent once", async () => {
    assert.equal(await captureHeldThenFree(0x9400, true), 1);
});
