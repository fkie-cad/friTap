// Unit tests for agent/shared/optional_ssl_fd_session.ts.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
    bindOptionalSslFdAndSession,
    describeSslFdSessionFallback,
    fdLessSslGetFd,
    sessionlessSslSessionGetId,
    type NativeFunctionFactory,
} from "./optional_ssl_fd_session.js";
import { SslPlaintextHooks, type SslPlaintextHost } from "./ssl_plaintext_hooks.js";
import { isSocketFdTrackerInstalled } from "./socket_fd_tracker.js";

const resolved = (name: string) => ({ name, isNull: () => false }) as unknown as NativePointer;
const nullPointer = { isNull: () => true } as unknown as NativePointer;

interface Bound { address: NativePointer; returnType: string; argTypes: string[] }

/** Records each binding; throws like Frida's NativeFunction on a missing address. */
function recordingFactory(): { factory: NativeFunctionFactory; calls: Bound[] } {
    const calls: Bound[] = [];
    const factory: NativeFunctionFactory = (address, returnType, argTypes) => {
        if (address === undefined) throw new Error("missing argument");
        const bound = { address, returnType, argTypes };
        calls.push(bound);
        return bound;
    };
    return { factory, calls };
}

const FULL_SURFACE = {
    SSL_get_fd: resolved("SSL_get_fd"),
    BIO_get_fd: resolved("BIO_get_fd"),
    SSL_get_session: resolved("SSL_get_session"),
    SSL_SESSION_get_id: resolved("SSL_SESSION_get_id"),
};

test("present symbols: bound directly (order, signatures, no fallback)", () => {
    const { factory, calls } = recordingFactory();
    const bound = bindOptionalSslFdAndSession(FULL_SURFACE, "SSL_get_fd", factory);
    assert.deepEqual(calls, [
        { address: FULL_SURFACE.SSL_SESSION_get_id, returnType: "pointer", argTypes: ["pointer", "pointer"] },
        { address: FULL_SURFACE.SSL_get_fd, returnType: "int", argTypes: ["pointer"] },
        { address: FULL_SURFACE.SSL_get_session, returnType: "pointer", argTypes: ["pointer"] },
    ]);
    assert.equal(bound.SSL_SESSION_get_id, calls[0]);
    assert.equal(bound.SSL_get_fd, calls[1]);
    assert.equal(bound.SSL_get_session, calls[2]);
    assert.notEqual(bound.SSL_get_fd, fdLessSslGetFd);
    assert.notEqual(bound.SSL_SESSION_get_id, sessionlessSslSessionGetId);
    assert.deepEqual(bound.fallbacks, []);
    assert.equal(bound.fdLess, false);
    assert.equal(describeSslFdSessionFallback("libssl.so", bound.fallbacks), "");
});

test("present symbols: the legacy BIO_get_fd selection is honoured", () => {
    const { factory } = recordingFactory();
    const bound = bindOptionalSslFdAndSession(FULL_SURFACE, "BIO_get_fd", factory);
    assert.equal(bound.SSL_get_fd.address, FULL_SURFACE.BIO_get_fd);
    assert.deepEqual(bound.fallbacks, []);
});

test("libhttpengine shape: missing SSL_get_fd + SSL_SESSION_get_id fall back, no throw", () => {
    const { factory, calls } = recordingFactory();
    const addresses = { SSL_read: resolved("SSL_read"), SSL_write: resolved("SSL_write"), SSL_get_session: resolved("SSL_get_session") };
    const bound = bindOptionalSslFdAndSession(addresses, "SSL_get_fd", factory);
    assert.equal(bound.SSL_get_fd, fdLessSslGetFd);
    assert.equal(bound.SSL_get_fd(resolved("ssl")), -1);
    assert.equal(bound.SSL_SESSION_get_id, sessionlessSslSessionGetId);
    assert.equal(bound.SSL_get_session.address, addresses.SSL_get_session);
    assert.equal(calls.length, 1, "only SSL_get_session is constructed");
    assert.deepEqual(bound.fallbacks, ["SSL_SESSION_get_id", "SSL_get_fd"]);
    assert.equal(bound.fdLess, true);
    assert.match(describeSslFdSessionFallback("libhttpengine.so", bound.fallbacks),
        /^libhttpengine\.so: SSL_SESSION_get_id, SSL_get_fd unresolved; .*fd -1.*empty session id$/);
});

test("only one optional symbol missing: the other stays bound", () => {
    const { factory } = recordingFactory();
    const noFd = bindOptionalSslFdAndSession({ ...FULL_SURFACE, SSL_get_fd: undefined }, "SSL_get_fd", factory);
    assert.equal(noFd.SSL_get_fd, fdLessSslGetFd);
    assert.equal(noFd.SSL_SESSION_get_id.address, FULL_SURFACE.SSL_SESSION_get_id);
    assert.deepEqual(noFd.fallbacks, ["SSL_get_fd"]);
    assert.equal(noFd.fdLess, true);

    const noId = bindOptionalSslFdAndSession({ ...FULL_SURFACE, SSL_SESSION_get_id: nullPointer }, "SSL_get_fd", factory);
    assert.equal(noId.SSL_SESSION_get_id, sessionlessSslSessionGetId);
    assert.equal(noId.SSL_get_fd.address, FULL_SURFACE.SSL_get_fd);
    assert.deepEqual(noId.fallbacks, ["SSL_SESSION_get_id"]);
    assert.equal(noId.fdLess, false, "only a missing fd getter makes the host fd-less");
});

test("missing SSL_get_session still throws (caller keeps its key-only fallback)", () => {
    const { factory } = recordingFactory();
    assert.throws(
        () => bindOptionalSslFdAndSession({ ...FULL_SURFACE, SSL_get_session: undefined }, "SSL_get_fd", factory),
        /missing argument/,
    );
});

test("sessionlessSslSessionGetId: a zero-length id (*outLength = 0, NULL), so getSslSessionId reports \"\"", () => {
    let written: number | undefined;
    const outLength = { writeU32: (value: number) => { written = value; } } as unknown as NativePointer;
    const id = sessionlessSslSessionGetId(resolved("session"), outLength);
    assert.equal(written, 0);
    assert.equal(id.isNull(), true);
});

// Both agent trees must route through the helper; the stand-ins make a
// "no SSL_SESSION_get_id" guard and a per-host early fd-tracker arm unnecessary
// (SslPlaintextHooks arms it). The hosts cannot be imported under Node.
const here = dirname(fileURLToPath(import.meta.url));
for (const host of ["../legacy/tls/libs/openssl_boringssl.ts", "../tls/libs/openssl_boringssl.ts"]) {
    test(`${host} binds via bindOptionalSslFdAndSession, without per-host stand-in special cases`, () => {
        const source = readFileSync(join(here, host), "utf8");
        assert.match(source, /bindOptionalSslFdAndSession\(this\.addresses\[this\.moduleName\]/);
        assert.match(source, /this\.fdLess = bound\.fdLess;/);
        assert.doesNotMatch(source, /if \(!this\.SSL_SESSION_get_id\)/);
        assert.doesNotMatch(source, /armFdTrackerIfFdLess|installSocketFdTracker/);
        assert.doesNotMatch(source, /new NativeFunction\(this\.addresses\[this\.moduleName\]\["SSL_get_fd"\]/);
    });
}

// SslPlaintextHooks is the one place that arms the socket fd tracker early for an fd-less
// host (both OpenSSL_BoringSSL trees and the Chromium host). The tracker is process-global
// and arms once: these run in order.
function plaintextHost(getFd: (ssl: NativePointer) => number, fdLess: boolean): SslPlaintextHost {
    return {
        moduleName: "libhttpengine.so", module_name: "libhttpengine.so", is_base_hook: true,
        addresses: { "libhttpengine.so": {} },
        SSL_get_fd: getFd, SSL_get_session: null, SSL_SESSION_get_id: sessionlessSslSessionGetId,
        getSslSessionId: () => "", fdLess,
    };
}
const NO_MODIFICATIONS = { readmod: null, writemod: null };

test("SslPlaintextHooks: a host with a real SSL_get_fd leaves the fd tracker to arm lazily", () => {
    const hooks = new SslPlaintextHooks(plaintextHost(() => 7, false), NO_MODIFICATIONS, false);
    hooks.attachRead(resolved("real_fd_SSL_read"));
    hooks.attachWrite(resolved("real_fd_SSL_write"));
    assert.equal(isSocketFdTrackerInstalled(), false);
});

test("SslPlaintextHooks: the flag, not the getter's identity, decides early arming", () => {
    const hooks = new SslPlaintextHooks(plaintextHost(fdLessSslGetFd, false), NO_MODIFICATIONS, false);
    hooks.attachRead(resolved("unflagged_SSL_read"));
    assert.equal(isSocketFdTrackerInstalled(), false);
});

test("SslPlaintextHooks: an fdLess host arms the fd tracker at install (idempotent)", () => {
    const hooks = new SslPlaintextHooks(plaintextHost(fdLessSslGetFd, true), NO_MODIFICATIONS, false);
    hooks.attachRead(resolved("fd_less_SSL_read"));
    assert.equal(isSocketFdTrackerInstalled(), true, "armed by attachRead, before any record");
    hooks.attachWrite(resolved("fd_less_SSL_write"));
    assert.equal(isSocketFdTrackerInstalled(), true);
});
