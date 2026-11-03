// Unit tests for DEFERRED fd-less peer attribution (fdOrDeferred / recoveredFd in
// socket_fd_tracker.ts) in every OpenSSL plaintext hook that uses it:
//   * the modern executors (core/executors/read_write.ts)
//   * the modern SSL_read_ex / SSL_write_ex hooks (tls/definitions/openssl.ts)
//   * the Android legacy class (legacy/tls/libs/openssl_boringssl.ts: libssl,
//     Conscrypt) — same shared hooks (shared/ssl_plaintext_hooks.ts)
//   * the legacy base class (tls/libs/openssl_boringssl.ts), including its
//     Apple gate: plaintext hooks for every genuine OpenSSL/LibreSSL module,
//     decided by module identity (usesBioGetFd), never for Apple's libboringssl.
//
// Run: npm run test:agent
//
// WHY: curl >= 7.87 wraps the socket in its own connection-filter BIO, so with
// genuine OpenSSL (Homebrew on macOS, distro OpenSSL on Linux) SSL_get_fd() is -1
// for every connection. The BIO send()s the record from INSIDE SSL_write and
// recv()s from inside SSL_read. Recovering the peer in onEnter (the old way)
// missed the first record of each connection — the HTTP request itself, since the
// tracker is armed lazily by that very record. Resolving it in onLeave sees the
// socket I/O the call just did.
//
// The fake native world: Interceptor.attach records listeners per address, the
// tracker's libc hooks are driven by hand ("the BIO called send(fd)"), and
// getpeername/getsockname write a Linux-layout sockaddr_in and record the fd.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { setPcapEnabled } from "./shared_structures.js";
import { installReadHook, installWriteHook } from "../core/executors/read_write.js";
import { createSslReadWriteExHooks } from "../tls/definitions/openssl.js";
import { OpenSSL_BoringSSL, usesBioGetFd } from "../tls/libs/openssl_boringssl.js";
import { OpenSSL_BoringSSL as AndroidOpenSSL_BoringSSL } from "../legacy/tls/libs/openssl_boringssl.js";

const G = globalThis as any;

// ── fake pointers / memory ─────────────────────────────────────────────────
function addr(name: string): any {
    return { name, isNull: () => false, toString: () => `0x${name}`, equals: (o: any) => o?.name === name };
}
function mem(size = 128, off = 0, buf: Buffer = Buffer.alloc(size)): any {
    const p: any = {
        buf, off,
        isNull: () => false,
        add: (n: number) => mem(size, off + Number(n), buf),
        readU8: () => buf.readUInt8(off),
        readU16: () => buf.readUInt16LE(off),
        readU32: () => buf.readUInt32LE(off),
        readULong: () => buf.readUInt32LE(off),
        writeU32: (v: number) => { buf.writeUInt32LE(v >>> 0, off); return p; },
        readByteArray: (n: number) => buf.subarray(off, off + Number(n)),
        toString: () => `mem+${off}`,
    };
    return p;
}
function plaintext(text: string): any { return mem(text.length, 0, Buffer.from(text)); }
/** A value usable both as Frida's int arg (toInt32) and with parseInt(). */
function int(n: number): any { return { toInt32: () => n, toString: () => String(n), valueOf: () => n, isNull: () => n === 0 }; }

// ── fake libc / Frida surface ──────────────────────────────────────────────
const listeners = new Map<string, any[]>();
const sockaddrCalls: Array<[string, number]> = [];
const LIBC = ["socket", "connect", "close", "getsockopt", "recvfrom", "recv", "recvmsg",
              "sendto", "send", "sendmsg", "read", "write"];
const libcAddr = new Map(LIBC.map(n => [n, addr(n)]));

G.Module.findGlobalExportByName = (name: string) => libcAddr.get(name) ?? null;
G.Interceptor.attach = (target: any, callbacks: any) => {
    const key = String(target);
    listeners.set(key, [...(listeners.get(key) ?? []), callbacks]);
    return { detach: () => { } };
};
G.Memory.alloc = (size: number) => mem(size);

function writeSockaddrIn(sa: any, ip: number[], port: number) {
    sa.buf.fill(0, sa.off, sa.off + 16);
    sa.buf.writeUInt16LE(2, sa.off);                 // AF_INET (Linux layout; Process.platform = "linux")
    sa.buf.writeUInt16BE(port, sa.off + 2);
    Buffer.from(ip).copy(sa.buf, sa.off + 4);
}
const nativeImpl: Record<string, (...a: any[]) => any> = {
    getsockopt: (_fd: number, _lvl: number, _name: number, optval: any) => { optval.writeU32(1); return 0; }, // SOCK_STREAM
    getpeername: (fd: number, sa: any) => { sockaddrCalls.push(["peer", fd]); writeSockaddrIn(sa, [93, 184, 215, 14], 443); return 0; },
    getsockname: (fd: number, sa: any) => { sockaddrCalls.push(["sock", fd]); writeSockaddrIn(sa, [192, 168, 0, 2], 50000 + fd); return 0; },
    ntohs: (v: number) => v,
    ntohl: (v: number) => v,
    SSL_get_fd: () => -1,                                 // curl's connection-filter BIO
    SSL_get_session: () => ({ isNull: () => true }),
    SSL_SESSION_get_id: () => mem(0),
};
G.NativeFunction = function (target: any) {
    const impl = target && nativeImpl[target.name];
    return impl ?? (() => 0);
};

const sent: any[] = [];
G.send = (message: any, data?: any) => { if (message?.contentType === "datalog") sent.push({ message, data }); };

setPcapEnabled(true);

const MOD = "libssl.3.dylib";
const SOCKET_FNS = { getpeername: addr("getpeername"), getsockname: addr("getsockname"), ntohs: addr("ntohs"), ntohl: addr("ntohl") };

function only(key: string): any {
    const l = listeners.get(key);
    assert.ok(l && l.length >= 1, `no listener attached at ${key}`);
    return l![l!.length - 1];
}
/** What curl's BIO does inside SSL_write/SSL_read: one libc call on `fd`. */
function libcIo(name: string, fd: number) {
    for (const cb of listeners.get(`0x${name}`) ?? []) cb.onEnter?.call({}, [int(fd)]);
}
function take(): any[] { return sent.splice(0, sent.length); }

// ── modern executors ───────────────────────────────────────────────────────
const def: any = {
    fdDecoder: () => -1,
    sessionIdDecoder: () => "",
    readHook: { symbol: "SSL_read", args: { sslCtxArgIndex: 0, bufferArgIndex: 1, bytesTransferred: "retval" } },
    writeHook: { symbol: "SSL_write", args: { sslCtxArgIndex: 0, bufferArgIndex: 1, lengthArgIndex: 2, bytesTransferred: "arg" } },
};
const modernAddresses = { [MOD]: { SSL_read: addr("SSL_read"), SSL_write: addr("SSL_write"), ...SOCKET_FNS } };
installReadHook(def, modernAddresses, MOD, {}, false);
installWriteHook(def, modernAddresses, MOD, {}, false);

test("modern SSL_write: the FIRST fd-less write is attributed to the fd its own send() used", () => {
    const req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const hook = only("0xSSL_write");
    const ctx: any = {};
    hook.onEnter.call(ctx, [addr("ssl"), plaintext(req), int(req.length)]);
    assert.equal(take().length, 0, "fd-less write must not be emitted from onEnter");

    libcIo("send", 7);                                   // curl's BIO sends the record
    hook.onLeave.call(ctx, int(req.length));

    const out = take();
    assert.equal(out.length, 1, "the request must be captured");
    assert.equal(Buffer.from(out[0].data).toString(), req);
    assert.equal(out[0].message.dst_port, 443);
    assert.equal(out[0].message.src_port, 50007);
    assert.equal(out[0].message.function, "SSL_write");
    assert.ok(sockaddrCalls.some(([kind, fd]) => kind === "peer" && fd === 7));
});

test("modern SSL_write: a failed fd-less write (retval <= 0) is not emitted", () => {
    const hook = only("0xSSL_write");
    const ctx: any = {};
    hook.onEnter.call(ctx, [addr("ssl"), plaintext("retry"), int(5)]);
    libcIo("send", 7);
    hook.onLeave.call(ctx, int(-1));
    assert.equal(take().length, 0);
});

test("modern SSL_read: fd-less read is attributed to the fd its recv() used", () => {
    const hook = only("0xSSL_read");
    const ctx: any = {};
    const buf = plaintext("HTTP/1.1 200 OK\r\n");
    hook.onEnter.call(ctx, [addr("ssl"), buf, int(16384)]);
    libcIo("recvfrom", 9);
    hook.onLeave.call(ctx, int(8));
    const out = take();
    assert.equal(out.length, 1);
    assert.equal(Buffer.from(out[0].data).toString(), "HTTP/1.1");
    assert.equal(out[0].message.src_port, 443, "read: src is the peer");
    assert.equal(out[0].message.dst_port, 50009);
});

test("modern SSL_write: an SSL object WITH an fd is attributed in onEnter, emitted in onLeave", () => {
    const withFd = { ...def, fdDecoder: () => 11 };
    const addrs = { [MOD]: { SSL_write: addr("SSL_write_fd"), ...SOCKET_FNS } };
    installWriteHook(withFd, addrs, MOD, {}, false);
    const ctx: any = {};
    only("0xSSL_write_fd").onEnter.call(ctx, [addr("ssl"), plaintext("hello"), int(5)]);
    assert.equal(take().length, 0, "emitted only once the written count is known");
    only("0xSSL_write_fd").onLeave.call(ctx, int(5));
    const out = take();
    assert.equal(out.length, 1, "no deferral when SSL_get_fd() works");
    assert.equal(out[0].message.src_port, 50011);
});

test("modern SSL_write: a partial write emits only the bytes written (no duplicate on retry)", () => {
    const withFd = { ...def, fdDecoder: () => 11 };
    const addrs = { [MOD]: { SSL_write: addr("SSL_write_partial"), ...SOCKET_FNS } };
    installWriteHook(withFd, addrs, MOD, {}, false);
    const body = "0123456789";
    const first: any = {};
    only("0xSSL_write_partial").onEnter.call(first, [addr("ssl"), plaintext(body), int(10)]);
    only("0xSSL_write_partial").onLeave.call(first, int(4));            // partial
    const retry: any = {};
    only("0xSSL_write_partial").onEnter.call(retry, [addr("ssl"), mem(10, 4, Buffer.from(body)), int(6)]);
    only("0xSSL_write_partial").onLeave.call(retry, int(6));
    const out = take();
    assert.deepEqual(out.map(o => Buffer.from(o.data).toString()), ["0123", "456789"]);
});

test("modern SSL_write: a failed write with an fd is not emitted", () => {
    const withFd = { ...def, fdDecoder: () => 11 };
    const addrs = { [MOD]: { SSL_write: addr("SSL_write_fail"), ...SOCKET_FNS } };
    installWriteHook(withFd, addrs, MOD, {}, false);
    const ctx: any = {};
    only("0xSSL_write_fail").onEnter.call(ctx, [addr("ssl"), plaintext("again"), int(5)]);
    only("0xSSL_write_fail").onLeave.call(ctx, int(-1));
    assert.equal(take().length, 0);
});

test("modern SSL_write (deferred): retval larger than the request is clamped", () => {
    const hook = only("0xSSL_write");
    const ctx: any = {};
    hook.onEnter.call(ctx, [addr("ssl"), plaintext("abc"), int(3)]);
    libcIo("send", 7);
    hook.onLeave.call(ctx, int(99));
    assert.equal(Buffer.from(take()[0].data).toString(), "abc");
});

// ── modern SSL_read_ex / SSL_write_ex (CPython's _ssl, curl on Linux) ─────
test("modern SSL_write_ex / SSL_read_ex: deferred attribution for fd-less SSL objects", () => {
    const addrs = { [MOD]: { SSL_read_ex: addr("SSL_read_ex"), SSL_write_ex: addr("SSL_write_ex"), ...SOCKET_FNS } };
    const fns: any = { SSL_get_fd: () => -1 };
    for (const extra of createSslReadWriteExHooks()) extra.install(addrs, MOD, fns, false);

    const w: any = {};
    const written = mem(8);
    only("0xSSL_write_ex").onEnter.call(w, [addr("ssl"), plaintext("GET /x"), int(6), written]);
    assert.equal(take().length, 0);
    libcIo("send", 12);
    written.writeU32(4);                                 // partial: *written < num
    only("0xSSL_write_ex").onLeave.call(w, int(1));      // SSL_write_ex returns 1 on success
    let out = take();
    assert.equal(out.length, 1);
    assert.equal(Buffer.from(out[0].data).toString(), "GET ", "*written bytes, not num");
    assert.equal(out[0].message.function, "SSL_write_ex");
    assert.equal(out[0].message.src_port, 50012);

    const r: any = {};
    const readbytes = mem(8);
    only("0xSSL_read_ex").onEnter.call(r, [addr("ssl"), plaintext("OK body"), int(4096), readbytes]);
    libcIo("recv", 12);
    readbytes.writeU32(2);
    only("0xSSL_read_ex").onLeave.call(r, int(1));
    out = take();
    assert.equal(out.length, 1);
    assert.equal(Buffer.from(out[0].data).toString(), "OK");

    const failed: any = {};
    only("0xSSL_read_ex").onEnter.call(failed, [addr("ssl"), plaintext("stale"), int(4096), readbytes]);
    only("0xSSL_read_ex").onLeave.call(failed, int(0));  // failure: *readbytes is not meaningful
    assert.equal(take().length, 0);
});

// ── legacy base class (the DEFAULT path on macOS) ──────────────────────────
class TestOpenSsl extends OpenSSL_BoringSSL {
    constructor(moduleName: string) {
        super(moduleName, "libSystem.B.dylib", true, { [`*${moduleName}*`]: ["SSL_write"] });
    }
    /** Point the instance at the fake native world (readAddresses saw only stubs). */
    useFakeAddresses(): boolean {
        this.addresses[this.moduleName] = {
            SSL_read: addr("legacy_SSL_read"), SSL_write: addr("legacy_SSL_write"),
            SSL_get_fd: addr("SSL_get_fd"), SSL_get_session: addr("SSL_get_session"),
            SSL_SESSION_get_id: addr("SSL_SESSION_get_id"), ...SOCKET_FNS,
        };
        return this.bindSslFdAndSessionFunctions();
    }
}

/** Construct in an ObjC-loaded (i.e. every macOS) process, with a resolvable SSL surface. */
function constructOnApple(moduleName: string): TestOpenSsl {
    const getModuleByName = G.Process.getModuleByName;
    G.ObjC.available = true;
    G.Process.getModuleByName = () => ({ enumerateExports: () => [{}, {}, {}] });
    try {
        return new TestOpenSsl(moduleName);
    } finally {
        G.ObjC.available = false;
        G.Process.getModuleByName = getModuleByName;
    }
}

test("usesBioGetFd: only Apple's libboringssl.dylib, by name or path", () => {
    assert.equal(usesBioGetFd("libboringssl.dylib"), true);
    assert.equal(usesBioGetFd("/usr/lib/libboringssl.dylib"), true);
    assert.equal(usesBioGetFd("libssl.3.dylib"), false);
    assert.equal(usesBioGetFd("/usr/lib/libssl.48.dylib"), false);
    assert.equal(usesBioGetFd("libboringssl.so"), false);
});

test("legacy base on Apple: genuine OpenSSL gets plaintext hooks; SSL_write is deferred", () => {
    const lib = constructOnApple(MOD);
    assert.equal(lib.do_read_write_hooks, true, "genuine OpenSSL is hooked even with ObjC loaded");
    assert.equal(lib.useFakeAddresses(), true);

    lib.install_plaintext_write_hook();
    lib.install_plaintext_read_hook();
    const write = only("0xlegacy_SSL_write");
    const ctx: any = {};
    const req = "GET / HTTP/1.1\r\n\r\n";
    write.onEnter.call(ctx, [addr("ssl"), plaintext(req), int(req.length)]);
    assert.equal(take().length, 0);
    libcIo("send", 21);
    write.onLeave.call(ctx, int(req.length));
    let out = take();
    assert.equal(out.length, 1, "legacy path must capture curl's first request");
    assert.equal(Buffer.from(out[0].data).toString(), req);
    assert.equal(out[0].message.function, "SSL_write");
    assert.equal(out[0].message.src_port, 50021);

    const read = only("0xlegacy_SSL_read");
    const rctx: any = {};
    read.onEnter.call(rctx, [addr("ssl"), plaintext("HTTP/1.1 200"), int(16384)]);
    libcIo("recv", 21);
    read.onLeave.call(rctx, int(12));
    out = take();
    assert.equal(out.length, 1);
    assert.equal(out[0].message.dst_port, 50021);
});

test("legacy base: Apple's libboringssl.dylib stays keys-only (no plaintext hooks)", () => {
    const lib = constructOnApple("/usr/lib/libboringssl.dylib");
    assert.equal(lib.do_read_write_hooks, false);
    assert.equal(lib.SSL_get_fd, undefined, "SSL_get_fd must not be bound for libboringssl");
    const before = listeners.get("0xlegacy_SSL_write")?.length ?? 0;
    lib.install_plaintext_write_hook();
    lib.install_plaintext_read_hook();
    assert.equal(listeners.get("0xlegacy_SSL_write")?.length ?? 0, before);
    assert.equal(take().length, 0);
});

// ── Android legacy class (legacy/tls/libs/openssl_boringssl.ts) ────────────
// The DEFAULT path on Android (openssl_boringssl_android.ts, conscrypt.ts). It used to
// recover the peer in onEnter from the thread's last fd: the first record of a
// connection was lost and, with several connections on one thread, records were
// attributed to whichever connection the thread touched last.
const ANDROID_MOD = "libssl.so";

class TestAndroidOpenSsl extends AndroidOpenSSL_BoringSSL {
    constructor() {
        super(ANDROID_MOD, "libc.so", true, { [`*${ANDROID_MOD}*`]: ["SSL_write"] });
        this.is_openssl = true;
        this.do_read_write_hooks = true;
        const fn = (name: string) => G.NativeFunction(addr(name));
        this.addresses[this.moduleName] = {
            SSL_read: addr("android_SSL_read"), SSL_write: addr("android_SSL_write"),
            SSL_read_ex: addr("android_SSL_read_ex"), SSL_write_ex: addr("android_SSL_write_ex"),
            ...SOCKET_FNS,
        };
        this.SSL_get_fd = fn("SSL_get_fd");                // -1: Conscrypt's memory BIO / custom BIO
        this.SSL_get_session = fn("SSL_get_session");
        this.SSL_SESSION_get_id = fn("SSL_SESSION_get_id");
    }
}

/** Fake libssl.so exporting the handshake functions and SSL_free (scope hooks). */
const androidExports: Record<string, any> = Object.fromEntries(
    ["SSL_do_handshake", "SSL_connect", "SSL_accept", "SSL_free"].map(n => [n, addr(`android_${n}`)]));
function constructAndroid(): TestAndroidOpenSsl {
    const getModuleByName = G.Process.getModuleByName;
    G.Process.getModuleByName = () => ({ enumerateExports: () => [{}, {}, {}] });
    try {
        return new TestAndroidOpenSsl();
    } finally {
        G.Process.getModuleByName = getModuleByName;
    }
}
function installAndroid(): TestAndroidOpenSsl {
    const lib = constructAndroid();
    const findModuleByName = G.Process.findModuleByName;
    G.Process.findModuleByName = (name: string) => name === ANDROID_MOD
        ? { findExportByName: (sym: string) => androidExports[sym] ?? null } : null;
    try {
        lib.install_plaintext_read_hook();
        lib.install_plaintext_write_hook();
        lib.install_extended_hooks();
    } finally {
        G.Process.findModuleByName = findModuleByName;
    }
    return lib;
}
installAndroid();

/** One hooked call: onEnter, the socket I/O done inside it (if any), onLeave. */
function call(hook: string, args: any[], retval: number, io?: [string, number]): any[] {
    const ctx: any = {};
    only(`0x${hook}`).onEnter.call(ctx, args);
    if (io) libcIo(io[0], io[1]);
    only(`0x${hook}`).onLeave.call(ctx, int(retval));
    return take();
}

test("android legacy: hooks attach once each, plus the handshake/SSL_free scope hooks", () => {
    for (const fn of ["SSL_read", "SSL_write", "SSL_read_ex", "SSL_write_ex",
                      "SSL_do_handshake", "SSL_connect", "SSL_accept", "SSL_free"]) {
        assert.equal(listeners.get(`0xandroid_${fn}`)?.length, 1, `${fn} hooked exactly once`);
    }
});

test("android legacy SSL_write: the FIRST fd-less write is captured with its own send() fd", () => {
    const req = "GET /generate_204 HTTP/1.1\r\n\r\n";
    const ctx: any = {};
    only("0xandroid_SSL_write").onEnter.call(ctx, [addr("ssl1"), plaintext(req), int(req.length)]);
    assert.equal(take().length, 0, "fd-less write must not be emitted from onEnter");
    libcIo("send", 51);
    only("0xandroid_SSL_write").onLeave.call(ctx, int(req.length));
    const out = take();
    assert.equal(out.length, 1, "the request must be captured");
    assert.equal(Buffer.from(out[0].data).toString(), req);
    assert.equal(out[0].message.function, "SSL_write");
    assert.equal(out[0].message.src_port, 50051);
    assert.equal(out[0].message.dst_port, 443);
});

test("android legacy: two SSL objects on one thread keep their own peers", () => {
    const A = addr("sslA"), B = addr("sslB");
    call("android_SSL_read", [A, plaintext("A-first"), int(4096)], 7, ["recv", 60]);
    call("android_SSL_read", [B, plaintext("B-first"), int(4096)], 7, ["recv", 61]);
    // A's next record was buffered by OpenSSL: no socket I/O inside this SSL_read. The
    // thread's last fd is B's (61) — the old heuristic would misattribute it.
    const out = call("android_SSL_read", [A, plaintext("A-buffered"), int(4096)], 10);
    assert.equal(out.length, 1);
    assert.equal(out[0].message.dst_port, 50060, "attributed to A's connection, not B's");
    const outB = call("android_SSL_write", [B, plaintext("B-write"), int(7)], 7);
    assert.equal(outB[0].message.src_port, 50061);
});

test("android legacy: a failed fd-less SSL_read still closes its scope and caches its fd", () => {
    const C = addr("sslC");
    assert.equal(call("android_SSL_read", [C, plaintext("x"), int(4096)], -1, ["recv", 70]).length, 0);
    libcIo("recv", 71);                                  // unrelated I/O on the same thread
    const out = call("android_SSL_read", [C, plaintext("payload"), int(4096)], 7);
    assert.equal(out.length, 1);
    assert.equal(out[0].message.dst_port, 50070, "scope was popped and C's fd cached");
});

test("android legacy: handshake scope caches the fd before the first SSL_read", () => {
    const D = addr("sslD");
    const hs: any = {};
    only("0xandroid_SSL_do_handshake").onEnter.call(hs, [D]);
    libcIo("send", 80);
    libcIo("recv", 80);
    only("0xandroid_SSL_do_handshake").onLeave.call(hs, int(1));
    libcIo("recv", 81);                                  // another connection on this thread
    const out = call("android_SSL_read", [D, plaintext("early data"), int(4096)], 10);
    assert.equal(out[0].message.dst_port, 50080);

    // SSL_free forgets D: a reused pointer falls back to the thread's last fd.
    only("0xandroid_SSL_free").onEnter.call({}, [D]);
    const reused = call("android_SSL_read", [D, plaintext("new conn"), int(4096)], 8);
    assert.equal(reused[0].message.dst_port, 50081);
});

test("android legacy SSL_read_ex / SSL_write_ex: deferred attribution", () => {
    const E = addr("sslE");
    const written = mem(8);
    written.writeU32(7);
    let out = call("android_SSL_write_ex", [E, plaintext("POST /x"), int(7), written], 1, ["sendto", 90]);
    assert.equal(out.length, 1);
    assert.equal(Buffer.from(out[0].data).toString(), "POST /x");
    assert.equal(out[0].message.function, "SSL_write_ex");
    assert.equal(out[0].message.src_port, 50090);

    const readbytes = mem(8);
    readbytes.writeU32(2);
    out = call("android_SSL_read_ex", [E, plaintext("OK body"), int(4096), readbytes], 1, ["recvfrom", 90]);
    assert.equal(out.length, 1);
    assert.equal(Buffer.from(out[0].data).toString(), "OK");
    assert.equal(out[0].message.dst_port, 50090);
    assert.equal(call("android_SSL_read_ex", [E, plaintext("z"), int(4096), readbytes], 0).length, 0);
});

test("android legacy: an SSL object WITH a socket fd is attributed in onEnter (no deferral)", () => {
    const lib = constructAndroid();
    lib.SSL_get_fd = () => 95;
    lib.addresses[lib.moduleName].SSL_write = addr("android_SSL_write_fd");
    lib.install_plaintext_write_hook();
    const ctx: any = {};
    only("0xandroid_SSL_write_fd").onEnter.call(ctx, [addr("sslF"), plaintext("hello"), int(5)]);
    assert.equal(take().length, 0, "emitted once the written count is known");
    only("0xandroid_SSL_write_fd").onLeave.call(ctx, int(3));           // partial write
    const out = take();
    assert.equal(out.length, 1);
    assert.equal(out[0].message.src_port, 50095);
    assert.equal(Buffer.from(out[0].data).toString(), "hel", "min(num, retval) bytes");
});
