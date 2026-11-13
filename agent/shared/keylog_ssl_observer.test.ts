// Unit tests for sendKeylog(line, ssl?, module?) feeding the per-SSL* identity
// cache through keylog_ssl_observer.ts (P1, design B3).
//
// Run: npm run test:agent

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { extractKeylogClientRandom, observeKeylogSsl, setKeylogSslObserver } from "./keylog_ssl_observer.js";
import { sendKeylog, setKeylogEnabled } from "./shared_structures.js";
import { noteSslClientRandom, resetSslIdentityState, setSslMemoryReader, sslIdentity } from "./ssl_identity.js";

const G = globalThis as any;
const CR = "AB".repeat(32);
const SECRET = "cd".repeat(48);

function fakePtr(address: number): any {
    return { address, isNull: () => address === 0, toString: () => "0x" + address.toString(16) };
}

/** Every native read faults: noting must not depend on memory. */
const faultingReader = { readPointer: () => null, readBytes: () => null, readU64: () => null };

let sent: any[] = [];
let previousSend: any;

beforeEach(() => {
    resetSslIdentityState();
    setSslMemoryReader(faultingReader);
    // No setKeylogSslObserver here: importing ssl_identity must have registered
    // noteSslClientRandom already (the tests below rely on that).
    sent = [];
    previousSend = G.send;
    G.send = (msg: any) => { sent.push(msg); };
});

afterEach(() => {
    G.send = previousSend;
    setKeylogEnabled(true);
    setSslMemoryReader(null);
    setKeylogSslObserver(noteSslClientRandom); // undo tests that swap the observer
});

test("extractKeylogClientRandom: 2nd token, 64 hex chars, lower-cased", () => {
    assert.equal(extractKeylogClientRandom(`CLIENT_RANDOM ${CR} ${SECRET}`), CR.toLowerCase());
    assert.equal(extractKeylogClientRandom(`  CLIENT_TRAFFIC_SECRET_0\t${CR}  ${SECRET}\n`), CR.toLowerCase());
});

test("extractKeylogClientRandom: non-NSS and malformed lines give ''", () => {
    for (const line of [
        "", "CLIENT_RANDOM", `RSA ${"ab".repeat(8)} ${SECRET}`,
        `CLIENT_RANDOM ${"ab".repeat(31)} ${SECRET}`, `CLIENT_RANDOM ${"zz".repeat(32)} ${SECRET}`,
        `CLIENT_RANDOM ${CR}00 ${SECRET}`, `CLIENT_RANDOM Error_reading_client_random ${SECRET}`,
    ]) {
        assert.equal(extractKeylogClientRandom(line), "", line);
    }
    assert.equal(extractKeylogClientRandom(null), "");
    assert.equal(extractKeylogClientRandom(42), "");
});

test("sendKeylog(line, ssl) notes the client_random even when keylogging is disabled", () => {
    setKeylogEnabled(false);
    const ssl = fakePtr(0x7000_1000);
    sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR} ${SECRET}`, ssl, "libfoo.so");
    assert.equal(sslIdentity(ssl)?.cr, CR.toLowerCase());
    assert.equal(sent.length, 0, "keylog_enabled=false must still suppress the KeylogEvent");
});

test("sendKeylog(line, ssl) notes and still emits when keylogging is enabled", () => {
    const ssl = fakePtr(0x7000_2000);
    const line = `CLIENT_RANDOM ${CR} ${SECRET}`;
    sendKeylog(line, ssl);
    assert.equal(sslIdentity(ssl)?.cr, CR.toLowerCase());
    assert.deepEqual(sent, [{ contentType: "keylog", keylog: line, protocol: "tls" }]);
});

test("sendKeylog without an SSL* behaves as before", () => {
    const line = `CLIENT_RANDOM ${CR} ${SECRET}`;
    sendKeylog(line);
    assert.deepEqual(sent, [{ contentType: "keylog", keylog: line, protocol: "tls" }]);
});

test("sendKeylog: malformed lines and NULL/odd SSL* are harmless", () => {
    const ssl = fakePtr(0x7000_3000);
    assert.doesNotThrow(() => {
        sendKeylog("garbage", ssl, "libfoo.so");
        sendKeylog(null as any, ssl);
        sendKeylog(`CLIENT_RANDOM ${CR} ${SECRET}`, fakePtr(0));
        sendKeylog(`CLIENT_RANDOM ${CR} ${SECRET}`, null);
        sendKeylog(`CLIENT_RANDOM ${CR} ${SECRET}`, {} as any);
    });
    assert.equal(sslIdentity(ssl), null);
    assert.equal(sent.length, 5, "every line is still forwarded unchanged");
});

test("observeKeylogSsl: a throwing observer never breaks keylog emission", () => {
    setKeylogSslObserver(() => { throw new Error("boom"); });
    const line = `CLIENT_RANDOM ${CR} ${SECRET}`;
    assert.doesNotThrow(() => observeKeylogSsl(line, fakePtr(0x7000_4000)));
    sendKeylog(line, fakePtr(0x7000_4000));
    assert.equal(sent.length, 1);
});

test("observeKeylogSsl: no observer registered is a no-op", () => {
    setKeylogSslObserver(null);
    const ssl = fakePtr(0x7000_5000);
    observeKeylogSsl(`CLIENT_RANDOM ${CR} ${SECRET}`, ssl);
    assert.equal(sslIdentity(ssl), null);
});
