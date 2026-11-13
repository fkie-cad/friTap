// Unit tests for SSL-SCOPED fd-less peer attribution in socket_fd_tracker.ts.
//
// Run: npm run test:agent
//
// WHY: when one thread drives several fd-less SSL objects (curl -Z, event loops), the thread's
// last stream fd belongs to whichever connection it touched last. An SSL_read served from
// OpenSSL's buffer (no socket I/O inside the call) was then attributed to the wrong peer. The
// tracker now scopes each fd-less SSL call, notes the fd its own I/O used, and caches it per
// SSL object.
//
// The fake native world: Interceptor.attach records listeners per address and the tracker's
// libc hooks are driven by hand ("the BIO called recv(fd)").

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    fdOrDeferred, recoveredFd, forgetSsl, installSslScopeHooks, MAX_SSL_FD_ENTRIES,
} from "./socket_fd_tracker.js";
import { setPcapEnabled } from "./shared_structures.js";
import { installReadHook } from "../core/executors/read_write.js";
import { noteSslClientRandom, sslIdentity } from "./ssl_identity.js";

const G = globalThis as any;

function addr(name: string): any {
    return { name, isNull: () => false, toString: () => `0x${name}` };
}
function int(n: number): any { return { toInt32: () => n, toString: () => String(n), valueOf: () => n, isNull: () => n === 0 }; }

const listeners = new Map<string, any[]>();
const LIBC = ["socket", "connect", "close", "getsockopt", "recvfrom", "recv", "recvmsg",
              "sendto", "send", "sendmsg", "read", "write"];
const libcAddr = new Map(LIBC.map(n => [n, addr(n)]));

G.Module.findGlobalExportByName = (name: string) => libcAddr.get(name) ?? null;
G.Interceptor.attach = (target: any, callbacks: any) => {
    const key = String(target);
    listeners.set(key, [...(listeners.get(key) ?? []), callbacks]);
    return { detach: () => { } };
};
G.Memory.alloc = () => ({ writeU32: () => { }, readU32: () => 1 /* SOCK_STREAM */ });
G.NativeFunction = function (target: any) {
    return target?.name === "getsockopt" ? () => 0 : () => 0;
};

function libc(name: string, fd: number) {
    for (const cb of listeners.get(`0x${name}`) ?? []) cb.onEnter?.call({}, [int(fd)]);
}

/** One fd-less SSL call: onEnter, the BIO's socket I/O inside it, onLeave. Returns its fd. */
function sslCall(ssl: any, ioFd?: number, io = "recv"): number {
    assert.equal(fdOrDeferred(-1, ssl), null, "fd-less SSL calls are deferred");
    if (ioFd !== undefined) libc(io, ioFd);
    return recoveredFd(ssl);
}

const A = addr("sslA"), B = addr("sslB"), C = addr("sslC");

test("two SSL objects interleaved on one thread map to their own fds", () => {
    assert.equal(sslCall(A, 7, "send"), 7);
    assert.equal(sslCall(B, 9, "send"), 9);
    assert.equal(sslCall(A, 7), 7);
    // B's read is served from OpenSSL's buffer: no I/O inside; the thread's last fd is 7 (A's).
    assert.equal(sslCall(B), 9, "buffered read of B must not inherit A's fd");
    assert.equal(sslCall(B, 9), 9);
    assert.equal(sslCall(A), 7, "buffered read of A must not inherit B's fd");
});

test("a buffered read with no I/O uses the SSL's cached fd", () => {
    sslCall(C, 21, "recvfrom");
    libc("send", 22);                         // unrelated I/O on this thread afterwards
    assert.equal(sslCall(C), 21);
});

test("close(fd) invalidates the cached entry; the reused fd number maps to the new SSL", () => {
    const old = addr("sslOld"), fresh = addr("sslFresh");
    sslCall(old, 31);
    libc("send", 32);
    libc("close", 31);
    assert.equal(sslCall(old), 32, "stale entry dropped: falls back to the thread's last fd");
    sslCall(fresh, 31, "send");               // fd number 31 reused by a new connection
    assert.equal(sslCall(fresh), 31);
    libc("send", 40);
    assert.equal(sslCall(old), 40, "the old SSL must not regain the reused fd");
});

test("SSL_free forgets the SSL's cached fd (pointer reuse)", () => {
    const s = addr("sslFreed");
    sslCall(s, 41);
    libc("send", 42);
    forgetSsl(s);
    assert.equal(sslCall(s), 42);
});

test("thread-last-fd fallback still works for an SSL never seen doing I/O", () => {
    libc("recv", 51);
    assert.equal(sslCall(addr("sslNever")), 51);
});

test("nested scopes: inner I/O is attributed to the inner SSL only", () => {
    const outer = addr("sslOuter"), inner = addr("sslInner");
    assert.equal(fdOrDeferred(-1, outer), null);
    libc("send", 61);
    assert.equal(sslCall(inner, 62), 62);
    assert.equal(recoveredFd(outer), 61);
});

test("a scope whose onLeave never ran does not steal later scoped I/O", () => {
    const lost = addr("sslLost"), next = addr("sslNext");
    fdOrDeferred(-1, lost);                   // onLeave never delivered
    assert.equal(sslCall(next, 71), 71, "the newer scope is innermost");
    assert.equal(sslCall(next), 71);
    assert.equal(recoveredFd(lost), 71, "the stale frame is popped by its own leave");
});

test("an SSL object with a usable fd is not deferred", () => {
    assert.equal(fdOrDeferred(5, A), 5);
});

test("the SSL->fd cache is capped", () => {
    for (let i = 0; i < MAX_SSL_FD_ENTRIES + 10; i++) sslCall(addr(`cap${i}`), 1000 + (i % 50));
    libc("send", 99);
    assert.equal(sslCall(addr("cap0")), 99, "oldest entry evicted");
    const last = MAX_SSL_FD_ENTRIES + 9;
    assert.equal(sslCall(addr(`cap${last}`)), 1000 + (last % 50));
});

test("handshake scope caches the fd before the first SSL_read (data buffered in the handshake)", () => {
    const findModuleByName = G.Process.findModuleByName;
    G.Process.findModuleByName = () => ({ findExportByName: (s: string) => addr(`mod_${s}`) });
    try {
        installSslScopeHooks("libssl.3.dylib", () => -1);
        installSslScopeHooks("libssl.3.dylib", () => -1);   // idempotent
    } finally {
        G.Process.findModuleByName = findModuleByName;
    }
    assert.equal(listeners.get("0xmod_SSL_connect")?.length, 1);
    const hs = addr("sslHandshake");
    const ctx: any = {};
    listeners.get("0xmod_SSL_connect")![0].onEnter.call(ctx, [hs]);
    libc("recv", 81);
    listeners.get("0xmod_SSL_connect")![0].onLeave.call(ctx, int(1));
    libc("send", 82);                         // another connection's I/O on this thread
    assert.equal(sslCall(hs), 81);

    listeners.get("0xmod_SSL_free")![0].onEnter.call({}, [hs]);
    assert.equal(sslCall(hs), 82, "SSL_free hook dropped the entry");
});

test("SSL_free also forgets the SSL's client_random identity (ssl_identity)", () => {
    // Relies on the SSL_free listener installed by the previous test.
    const freed = addr("sslFreedIdentity");
    noteSslClientRandom(freed, "ab".repeat(32));
    assert.equal(sslIdentity(freed)?.cr, "ab".repeat(32));
    listeners.get("0xmod_SSL_free")![0].onEnter.call({}, [freed]);
    assert.equal(sslIdentity(freed), null, "SSL_free hook dropped the identity");
});

test("executor: a FAILED fd-less SSL_read still closes its scope and caches its fd", () => {
    setPcapEnabled(true);
    const def: any = {
        fdDecoder: () => -1,
        sessionIdDecoder: () => "",
        readHook: { symbol: "SSL_read", args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" } },
    };
    installReadHook(def, { m: { SSL_read: addr("exec_SSL_read") } }, "m", {}, false);
    const hook = listeners.get("0xexec_SSL_read")!.at(-1);
    const ssl = addr("sslWantRead");
    const ctx: any = {};
    hook.onEnter.call(ctx, [ssl, addr("buf"), int(4096)]);
    libc("recv", 91);                         // EAGAIN on its own socket
    hook.onLeave.call(ctx, int(-1));          // SSL_ERROR_WANT_READ
    libc("send", 92);
    assert.equal(sslCall(ssl), 91);
    assert.equal(sslCall(addr("sslOther")), 92, "no scope left open by the failed call");
});
