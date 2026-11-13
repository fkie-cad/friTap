// Unit tests for the socket fd tracker's BACKEND selection and the JS-side closed-fd drain.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    installSocketFdTracker, isSocketFdTrackerInstalled, resetSocketFdTrackerForTests,
    fdOrDeferred, recoveredFd, recoverSocketFd, cachedSslFd, SocketFdBackend, ClosedFdDrain, MAX_SCOPE_DEPTH,
} from "./socket_fd_tracker.js";
import {
    nativeSocketObserver, resetNativeSocketObserverForTests, SOCKET_IO_FUNCTIONS, CLOSED_FD_CONSUMER,
} from "./native_socket_observer.js";

const G = globalThis as any;

const LIBC = ["socket", "connect", "close", "dup2", "dup3", "getsockopt", ...SOCKET_IO_FUNCTIONS];
const TRACKER_TARGETS = ["socket", "connect", "close", "dup2", "dup3", ...SOCKET_IO_FUNCTIONS];
function addr(name: string): any {
    return { name, isNull: () => false, toString: () => `0x${name}`, add: () => addr(name), readU32: () => 0 };
}
const libcAddr = new Map<string, any>(LIBC.map(n => [n, addr(n)]));
G.Module.findGlobalExportByName = (name: string) => libcAddr.get(name) ?? null;
G.Memory.alloc = () => addr("block");

let attached: Array<{ target: string; callbacks: any }> = [];
let failNativeAttachAt: string | null = null;
G.Interceptor.attach = (target: any, callbacks: any) => {
    if (String(target) === failNativeAttachAt && typeof callbacks.onEnter !== "function") {
        throw new Error("attach failed");
    }
    attached.push({ target: String(target), callbacks });
    return { detach: () => { attached = attached.filter(a => a.callbacks !== callbacks); } };
};

const consoleLines: string[] = [];
G.send = (message: any) => { if (message?.contentType === "console") consoleLines.push(message.console); };
const fallbackWarnings = () => consoleLines.filter(line => line.includes("falling back to JavaScript libc hooks"));

/** A CModule stub whose exported symbols are fake NativePointers named after the symbol. */
class FakeCModule {
    [symbol: string]: any;
    constructor(public source: string, public symbols: any) {
        for (const name of ["ft_state_size", "ft_init", "ft_scope_push", "ft_scope_pop", "ft_recover",
                            "ft_closed_skip", "ft_drain_closed", "ft_udp_skip", "ft_drain_udp_peers",
                            "ft_socket_on_enter", "ft_socket_on_leave", "ft_connect_on_enter",
                            "ft_connect_on_leave", "ft_close_on_enter", "ft_dup_on_enter",
                            "ft_dup_on_leave", "ft_io_on_enter"]) {
            this[name] = addr(name);
        }
    }
}

function freshTracker(factory?: () => SocketFdBackend | null): void {
    attached = [];
    consoleLines.length = 0;
    failNativeAttachAt = null;
    resetNativeSocketObserverForTests();
    resetSocketFdTrackerForTests(factory);
}

function assertJsListeners(): void {
    const targets = attached.map(a => a.target);
    for (const name of ["socket", "connect", "close", ...SOCKET_IO_FUNCTIONS]) {
        assert.ok(targets.includes(`0x${name}`), `JS backend hooks ${name}`);
    }
    assert.ok(attached.every(a => typeof a.callbacks.onEnter === "function"), "JS listeners are functions");
}

test("CModule constructor throws -> JS libc listeners and one user-visible warning", () => {
    G.CModule = function () { throw new Error("compilation failed: boom"); };
    freshTracker();
    installSocketFdTracker("test");
    assert.equal(isSocketFdTrackerInstalled(), true);
    assertJsListeners();
    assert.equal(nativeSocketObserver(), null, "the failure is remembered");
    assert.equal(fallbackWarnings().length, 1);
    assert.match(fallbackWarnings()[0], /--attribute-sdk/);
    delete G.CModule;
});

test("CModule unavailable -> JS backend", () => {
    delete G.CModule;
    freshTracker();
    installSocketFdTracker("test");
    assertJsListeners();
    assert.equal(fallbackWarnings().length, 1);
});

test("CModule compiles -> native backend; no JS callback is attached to libc", () => {
    let compiled: FakeCModule | null = null;
    G.CModule = function (source: string, symbols: any) {
        compiled = new FakeCModule(source, symbols);
        return compiled;
    };
    freshTracker();
    installSocketFdTracker("test");
    assert.ok(compiled !== null);
    assert.ok("ft_state" in compiled!.symbols, "state block is passed in as a symbol");
    assert.match(compiled!.source, new RegExp(`#define MAX_SCOPE_DEPTH ${MAX_SCOPE_DEPTH}\\b`));
    assert.match(compiled!.source, /#define FT_SOL_SOCKET 1\b/);
    assert.match(compiled!.source, /#define FT_SO_TYPE 3\b/);
    assert.match(compiled!.source, /#define FT_SOCK_STREAM 1\b/);
    assert.deepEqual(attached.map(a => a.target).sort(), TRACKER_TARGETS.map(n => `0x${n}`).sort());
    for (const { callbacks } of attached) {
        for (const cb of [callbacks.onEnter, callbacks.onLeave]) {
            assert.notEqual(typeof cb, "function", "native listeners must be CModule pointers, never JS");
        }
    }
    const socketHook = attached.find(a => a.target === "0xsocket")!.callbacks;
    assert.equal(socketHook.onEnter.name, "ft_socket_on_enter");
    assert.equal(socketHook.onLeave.name, "ft_socket_on_leave");
    assert.equal(attached.find(a => a.target === "0xdup2")!.callbacks.onLeave.name, "ft_dup_on_leave");
    assert.equal(attached.find(a => a.target === "0xread")!.callbacks.onEnter.name, "ft_io_on_enter");
    assert.equal(fallbackWarnings().length, 0);
    delete G.CModule;
});

test("a state block larger than reserved -> JS backend", () => {
    G.CModule = function (source: string, symbols: any) { return new FakeCModule(source, symbols); };
    const savedNativeFunction = G.NativeFunction;
    G.NativeFunction = function (target: any) {
        return target?.name === "ft_state_size" ? () => 1e9 : () => 0;
    };
    freshTracker();
    installSocketFdTracker("test");
    assertJsListeners();
    assert.equal(fallbackWarnings().length, 1);
    G.NativeFunction = savedNativeFunction;
    delete G.CModule;
});

test("a failed native attach detaches its group and falls back to JS", () => {
    G.CModule = function (source: string, symbols: any) { return new FakeCModule(source, symbols); };
    freshTracker();
    failNativeAttachAt = "0xread";
    installSocketFdTracker("test");
    assert.ok(!attached.some(a => a.callbacks.onEnter?.name === "ft_io_on_enter"), "native I/O group detached");
    assert.ok(attached.some(a => a.target === "0xread" && typeof a.callbacks.onEnter === "function"));
    assert.equal(fallbackWarnings().length, 1);
    delete G.CModule;
});

test("a partly failed arm detaches only the native groups it attached itself", () => {
    G.CModule = function (source: string, symbols: any) { return new FakeCModule(source, symbols); };
    freshTracker();
    assert.ok(nativeSocketObserver()!.armClosedFdConsumer(CLOSED_FD_CONSUMER.unwantedFds));
    failNativeAttachAt = "0xread";
    installSocketFdTracker("test");
    const native = attached.filter(a => typeof a.callbacks.onEnter !== "function");
    assert.deepEqual(native.map(a => a.target).sort(), ["0xclose", "0xdup2", "0xdup3"],
                     "the earlier consumer's close group stays; socket/connect are detached");
    assert.deepEqual(nativeSocketObserver()!.hookedFunctions, ["close", "dup2", "dup3"]);
    assert.ok(attached.some(a => a.target === "0xread" && typeof a.callbacks.onEnter === "function"),
              "the tracker fell back to JS listeners");
    delete G.CModule;
});

test("a failed arm with nothing armed before leaves no native listener behind", () => {
    G.CModule = function (source: string, symbols: any) { return new FakeCModule(source, symbols); };
    freshTracker();
    failNativeAttachAt = "0xread";
    installSocketFdTracker("test");
    assert.ok(attached.every(a => typeof a.callbacks.onEnter === "function"), "only JS listeners remain");
    assert.deepEqual(nativeSocketObserver()!.hookedFunctions, []);
    delete G.CModule;
});

test("android_fdsan_close_with_tag replaces close when exported (native and JS)", () => {
    libcAddr.set("android_fdsan_close_with_tag", addr("android_fdsan_close_with_tag"));
    try {
        G.CModule = function (source: string, symbols: any) { return new FakeCModule(source, symbols); };
        freshTracker();
        installSocketFdTracker("test");
        const fdsan = attached.find(a => a.target === "0xandroid_fdsan_close_with_tag");
        assert.equal(fdsan?.callbacks.onEnter.name, "ft_close_on_enter");
        assert.ok(!attached.some(a => a.target === "0xclose"), "close itself is not hooked twice");

        delete G.CModule;
        freshTracker();
        installSocketFdTracker("test");
        const targets = attached.map(a => a.target);
        assert.ok(targets.includes("0xandroid_fdsan_close_with_tag"));
        assert.ok(!targets.includes("0xclose"));
    } finally {
        libcAddr.delete("android_fdsan_close_with_tag");
        delete G.CModule;
    }
});

// ── JS-side drain of the native closed-fd ring, against a fake native backend ─────────────

/** A scriptable stand-in for the CModule backend. */
class FakeNativeBackend implements SocketFdBackend {
    readonly name = "native" as const;
    readonly hookedFunctions = ["fake"];
    scopeFd = -1;
    lastFd = -1;
    pending: ClosedFdDrain = [];
    drains = 0;
    enterScope(): void { this.scopeFd = -1; }
    leaveScope(): number { return this.scopeFd; }
    recover(): number { return this.lastFd; }
    drainClosedFds(): ClosedFdDrain {
        this.drains++;
        const out = this.pending;
        this.pending = [];
        return out;
    }
}

function sslPtr(name: string): any { return { isNull: () => false, toString: () => `0x${name}` }; }

/** One fd-less SSL call whose BIO did I/O on `ioFd` (as the C I/O hook would note it). */
function sslCall(fake: FakeNativeBackend, ssl: any, ioFd?: number): number {
    assert.equal(fdOrDeferred(-1, ssl), null);
    if (ioFd !== undefined) { fake.scopeFd = ioFd; fake.lastFd = ioFd; }
    return recoveredFd(ssl);
}

function armFake(): FakeNativeBackend {
    const fake = new FakeNativeBackend();
    freshTracker(() => fake);
    installSocketFdTracker("test");
    return fake;
}

test("native: a drained closed fd is forgotten by the SSL->fd cache", () => {
    const fake = armFake();
    const A = sslPtr("A"), B = sslPtr("B");
    assert.equal(sslCall(fake, A, 7), 7);
    assert.equal(sslCall(fake, B, 9), 9);
    assert.equal(cachedSslFd(A), 7);
    fake.pending = [7];
    fake.lastFd = -1;
    assert.equal(cachedSslFd(A), -1, "closed fd 7 is no longer attributed to A");
    assert.equal(cachedSslFd(B), 9, "other entries survive");
});

test("native: one drain per SSL call, before a reused fd is cached", () => {
    const fake = armFake();
    const old = sslPtr("old"), fresh = sslPtr("fresh");
    sslCall(fake, old, 31);
    fake.pending = [31];                      // old connection closed; fd 31 reused below
    const before = fake.drains;
    assert.equal(sslCall(fake, fresh, 31), 31);
    assert.equal(fake.drains - before, 1);
    assert.equal(cachedSslFd(fresh), 31, "the new SSL keeps the reused fd");
    assert.equal(cachedSslFd(old), -1, "the stale SSL lost it");
});

test("native: a buffered read (no I/O in the call) after close falls back to the thread's fd", () => {
    const fake = armFake();
    const C = sslPtr("C");
    sslCall(fake, C, 21);
    fake.pending = [21];
    fake.lastFd = 22;
    assert.equal(sslCall(fake, C), 22, "the closed fd is not recovered from the cache");
});

test("native: a lost ring (overflow) clears the whole SSL->fd cache", () => {
    const fake = armFake();
    const A = sslPtr("A2"), B = sslPtr("B2");
    sslCall(fake, A, 41);
    sslCall(fake, B, 42);
    fake.pending = "lost";
    assert.equal(cachedSslFd(A), -1);
    assert.equal(cachedSslFd(B), -1);
});

test("native: recoverSocketFd asks the backend for the current thread", () => {
    const fake = armFake();
    fake.lastFd = 55;
    assert.equal(recoverSocketFd(), 55);
});
