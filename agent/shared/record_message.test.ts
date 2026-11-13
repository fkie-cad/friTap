// Unit tests for the shared datalog record builder (shared/record_message.ts):
// the `library` field that names the module which produced a plaintext record.
//
// Run: npm run test:agent
//
// WHY: without `library` on TCP-TLS datalog records, the host attributed every new flow
// to the TLS library announced LAST (e.g. WebView flows labelled libcronet.*.so).

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    buildRecordMessage, buildEndpointlessRecord, stampRecordClientRandom, stampRecordLibrary, RecordContext,
    SslRecordSource, sslRecordClientRandom, buildEndpointlessSslRecord, finishSslRecord,
} from "./record_message.js";
import { noteSslClientRandom, resetSslIdentityState, sslIdentity } from "./ssl_identity.js";
import { unwantedFDs } from "./shared_structures.js";

const PEER = { src_addr: "10.0.0.2", dst_addr: "93.184.215.14", src_port: 50000, dst_port: 443, ss_family: "AF_INET" };

function context(library?: string): RecordContext {
    return {
        fd: 5, isRead: false, functionName: "SSL_write", methodAddresses: {}, enableDefaultFd: false,
        resolvePeer: () => ({ ...PEER }), library,
    };
}

test("buildRecordMessage: stamps library when the context names a module", () => {
    const message = buildRecordMessage(context("libwebviewchromium.so"), () => ({ ssl_session_id: "ab" }));
    assert.equal(message.library, "libwebviewchromium.so");
    assert.equal(message.function, "SSL_write");
    assert.equal(message.ssl_session_id, "ab");
    assert.equal(message.dst_port, 443);
});

test("buildRecordMessage: no library key without a module name (undefined or empty)", () => {
    for (const library of [undefined, ""]) {
        const message = buildRecordMessage(context(library), () => ({}));
        assert.equal("library" in message, false, `library=${JSON.stringify(library)}`);
    }
});

test("buildRecordMessage: an unattributable record stays null", () => {
    const ctx = { ...context("libssl.so"), resolvePeer: () => null };
    assert.equal(buildRecordMessage(ctx, () => ({})), null);
});

test("stampRecordLibrary: sets a non-empty name, ignores empty/undefined", () => {
    const message: { [key: string]: any } = {};
    stampRecordLibrary(message, "");
    stampRecordLibrary(message, undefined);
    assert.deepEqual(message, {});
    stampRecordLibrary(message, "libgnutls.so.30");
    assert.deepEqual(message, { library: "libgnutls.so.30" });
});

// ── client_random (P1 design B4): the cross-source join key on plaintext records ──

const CR = "ab".repeat(32);

function fakeSsl(address: number): any {
    return { isNull: () => address === 0, toString: () => "0x" + address.toString(16) };
}

test("stampRecordClientRandom: stamps a value, skips empty/undefined, never overwrites", () => {
    const message: { [key: string]: any } = {};
    stampRecordClientRandom(message, "");
    stampRecordClientRandom(message, undefined);
    assert.deepEqual(message, {});
    stampRecordClientRandom(message, CR);
    assert.equal(message.client_random, CR);
    stampRecordClientRandom(message, "cd".repeat(32));
    assert.equal(message.client_random, CR, "an existing client_random is kept");
});

test("buildRecordMessage: stamps the context's clientRandom lookup", () => {
    const message = buildRecordMessage({ ...context("libmonochrome.so"), clientRandom: () => CR }, () => ({}));
    assert.equal(message.client_random, CR);
});

test("buildRecordMessage: a session decoder's client_random wins; the lookup is not even called", () => {
    let called = 0;
    const ctx = { ...context("libssl.so"), clientRandom: () => { called++; return "cd".repeat(32); } };
    const message = buildRecordMessage(ctx, () => ({ client_random: CR }));
    assert.equal(message.client_random, CR);
    assert.equal(called, 0);
});

test("buildRecordMessage: an empty decoder result falls back to the ssl identity cache", () => {
    resetSslIdentityState();
    const ssl = fakeSsl(0x7000);
    noteSslClientRandom(ssl, CR.toUpperCase());
    const message = buildRecordMessage({ ...context("libssl.so"), ssl }, () => ({ client_random: "" }));
    assert.equal(message.client_random, CR);
});

test("buildRecordMessage: no client_random key when nothing is known, and a throwing lookup is harmless", () => {
    resetSslIdentityState();
    const unknown = buildRecordMessage({ ...context("libssl.so"), ssl: fakeSsl(0x7100) }, () => ({}));
    assert.equal("client_random" in unknown, false);
    const throwing = buildRecordMessage({ ...context("libssl.so"), clientRandom: () => { throw new Error("fault"); } }, () => ({}));
    assert.equal("client_random" in throwing, false);
    assert.equal(throwing.function, "SSL_write");
});

// ── I2.1 option 5: fd-less records with a client_random are kept WITHOUT address fields ──

const ADDRESS_FIELDS = ["src_addr", "dst_addr", "src_port", "dst_port", "ss_family"];

function assertNoAddressFields(message: { [key: string]: any }): void {
    for (const field of ADDRESS_FIELDS) assert.equal(field in message, false, `${field} on an endpointless record`);
}

/** A context with no socket fd and no library-specific peer resolver (getPortsAndAddresses path). */
function fdlessContext(overrides: Partial<RecordContext> = {}): RecordContext {
    return { fd: -1, isRead: true, functionName: "SSL_read", methodAddresses: {}, enableDefaultFd: false,
             library: "libmonochrome.so", ...overrides };
}

test("buildEndpointlessRecord: fd<0 + client_random -> no address fields, library/cr/function/session kept", () => {
    const message = buildEndpointlessRecord(fdlessContext({ clientRandom: () => CR }), () => ({ ssl_session_id: "S1" }));
    assertNoAddressFields(message);
    assert.equal(message.client_random, CR);
    assert.equal(message.library, "libmonochrome.so");
    assert.equal(message.function, "SSL_read");
    assert.equal(message.ssl_session_id, "S1");
});

test("buildEndpointlessRecord: the client_random comes through the P1 ssl identity cache", () => {
    resetSslIdentityState();
    const ssl = fakeSsl(0x7200);
    noteSslClientRandom(ssl, CR.toUpperCase());
    const message = buildEndpointlessRecord(fdlessContext({ ssl }), () => ({}));
    assert.equal(message.client_random, CR);
    assertNoAddressFields(message);
});

test("buildEndpointlessRecord: fd<0 without a client_random -> null (dropped as before)", () => {
    resetSslIdentityState();
    assert.equal(buildEndpointlessRecord(fdlessContext({ clientRandom: () => "" }), () => ({})), null);
    assert.equal(buildEndpointlessRecord(fdlessContext({ ssl: fakeSsl(0x7300) }), () => ({ client_random: "" })), null);
});

test("buildEndpointlessRecord: never applies to a record that has a socket fd", () => {
    assert.equal(buildEndpointlessRecord(fdlessContext({ fd: 4, clientRandom: () => CR }), () => ({})), null);
});

test("buildRecordMessage: fd<0 + client_random -> endpointless record", () => {
    const message = buildRecordMessage(fdlessContext({ clientRandom: () => CR }), () => ({ ssl_session_id: "S2" }));
    assertNoAddressFields(message);
    assert.equal(message.client_random, CR);
    assert.equal(message.ssl_session_id, "S2");
});

test("buildRecordMessage: fd<0 without client_random and without -ed stays null", () => {
    assert.equal(buildRecordMessage(fdlessContext({ clientRandom: () => "" }), () => ({})), null);
});

test("buildRecordMessage: -ed + client_random -> endpointless beats the shared placeholder tuple", () => {
    const message = buildRecordMessage(fdlessContext({ enableDefaultFd: true, clientRandom: () => CR }), () => ({}));
    assertNoAddressFields(message);
    assert.equal(message.client_random, CR);
});

test("buildRecordMessage: -ed without client_random keeps the oriented placeholder tuple", () => {
    const read = buildRecordMessage(fdlessContext({ enableDefaultFd: true, clientRandom: () => "" }), () => ({}));
    assert.deepEqual([read.src_port, read.dst_port, read.ss_family], [2345, 1234, "AF_INET"]);
    const write = buildRecordMessage(fdlessContext({ enableDefaultFd: true, isRead: false, clientRandom: () => "" }), () => ({}));
    assert.deepEqual([write.src_port, write.dst_port], [1234, 2345]);
});

test("buildRecordMessage: an unwanted (non-IP) fd stays dropped even with a client_random", () => {
    unwantedFDs.add(77);
    try {
        const ctx = fdlessContext({ fd: 77, clientRandom: () => CR });
        assert.equal(buildRecordMessage(ctx, () => ({})), null);
    } finally {
        unwantedFDs.delete(77);
    }
});

test("buildRecordMessage: an fd-less record falling through to the -ed placeholder reads the session fields once", () => {
    let calls = 0;
    const ctx = fdlessContext({ enableDefaultFd: true, clientRandom: () => "" });
    const message = buildRecordMessage(ctx, () => { calls++; return { ssl_session_id: "S3" }; });
    assert.equal(message.ssl_session_id, "S3");
    assert.equal(message.dst_port, 1234, "the oriented -ed placeholder tuple (read)");
    assert.equal(calls, 1);
});

// ── SslRecordSource: the shared record path of class-based hooks (Cronet legacy + modern) ──

function source(probedCr: string, probes: NativePointer[] = []): SslRecordSource {
    return {
        library: "libcronet.so", methodAddresses: {}, enableDefaultFd: false,
        probeClientRandom: (ssl) => { probes.push(ssl); return probedCr; },
        sessionFields: () => ({ ssl_session_id: "SID" }),
    };
}

test("sslRecordClientRandom: a probe hit is lower-cased and noted; without a layout anchor the probe is asked again", () => {
    resetSslIdentityState();
    const probes: NativePointer[] = [];
    const ssl = fakeSsl(0x7400);
    assert.equal(sslRecordClientRandom(source(CR.toUpperCase(), probes), ssl), CR);
    assert.equal(sslIdentity(ssl)?.cr, CR, "noted in the shared per-SSL* identity");
    assert.equal(sslRecordClientRandom(source(CR.toUpperCase(), probes), ssl), CR);
    assert.equal(probes.length, 2, "an anchorless note is not served ahead of the probe (reused SSL* safety)");
});

test("sslRecordClientRandom: a probe miss is not noted", () => {
    resetSslIdentityState();
    const ssl = fakeSsl(0x7500);
    assert.equal(sslRecordClientRandom(source(""), ssl), "");
    assert.equal(sslIdentity(ssl), null);
});

test("buildEndpointlessSslRecord: a known client_random -> no address fields, source fields stamped", () => {
    resetSslIdentityState();
    const message = buildEndpointlessSslRecord(source(CR), fakeSsl(0x7600), "SSL_read", true);
    assertNoAddressFields(message);
    assert.deepEqual(
        [message.client_random, message.library, message.function, message.ssl_session_id],
        [CR, "libcronet.so", "SSL_read", "SID"],
    );
});

test("buildEndpointlessSslRecord: without a client_random -> null", () => {
    resetSslIdentityState();
    assert.equal(buildEndpointlessSslRecord(source(""), fakeSsl(0x7700), "SSL_write", false), null);
});

test("finishSslRecord: stamps function/library/client_random onto an addressed record, keeping its peer", () => {
    resetSslIdentityState();
    const message: { [key: string]: any } = { ...PEER, ssl_session_id: "SID" };
    finishSslRecord(message, source(CR), fakeSsl(0x7800), "SSL_write", false);
    assert.deepEqual(
        [message.function, message.library, message.client_random, message.dst_port, message.ssl_session_id],
        ["SSL_write", "libcronet.so", CR, 443, "SID"],
    );
});

test("finishSslRecord: an existing client_random is kept, and none is stamped when unknown", () => {
    resetSslIdentityState();
    const decoded: { [key: string]: any } = { client_random: "cd".repeat(32) };
    finishSslRecord(decoded, source(CR), fakeSsl(0x7900), "SSL_read", true);
    assert.equal(decoded.client_random, "cd".repeat(32));
    const unknown: { [key: string]: any } = {};
    finishSslRecord(unknown, source(""), fakeSsl(0x7a00), "SSL_read", true);
    assert.equal("client_random" in unknown, false);
});

// ── fd >= 0 whose peer lookup FAILED (not an unwanted fd): keep it endpointless when the cr is known ──

test("buildRecordMessage: a resolver returning null + client_random -> endpointless record", () => {
    const ctx = { ...context("libssl.so"), resolvePeer: () => null, clientRandom: () => CR };
    const message = buildRecordMessage(ctx, () => ({ ssl_session_id: "S4" }));
    assert.notEqual(message, null, "a failed peer lookup must not lose a record whose client_random is known");
    assertNoAddressFields(message);
    assert.equal(message.client_random, CR);
    assert.equal(message.ssl_session_id, "S4");
    assert.equal(message.function, "SSL_write");
});

test("buildRecordMessage: a resolver returning null without a client_random stays null", () => {
    const ctx = { ...context("libssl.so"), resolvePeer: () => null, clientRandom: () => "" };
    assert.equal(buildRecordMessage(ctx, () => ({})), null);
});
