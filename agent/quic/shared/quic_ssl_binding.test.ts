// Unit tests for binding a Google QUICHE connection to its TLS client_random
// (quic_ssl_binding.ts, the tracker binding, and the observe-only
// ssl_log_secret hook of boringssl_anchor_locator.ts).
//
// Run: npm run test:agent
//
// WHY: the host keys QUIC flows by client_random. A wrong binding (another
// thread's handshake, or a freed QuicConnection reused by a new connection)
// would merge unrelated flows, and the observe-only hook must never leak keys.

import { test, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import { buildQuicMessage, QuicConnectionTracker } from "./quic_connection_tracker.js";
import type { QuicSocketAddress } from "./quiche_layout.js";
import {
    createQuicSslBinder, QuicSslBinderDeps, wantsCryptoFrameBinding, wantsObserveOnlySslHook,
} from "./quic_ssl_binding.js";
import { runAnchorLocatorObserveOnly } from "../../shared/boringssl_anchor_locator.js";
import { addKeylogSslListener } from "../../shared/keylog_ssl_observer.js";
import { sendKeylog, setKeylogEnabled } from "../../shared/shared_structures.js";
import {
    QuicheLayoutState, handshakerConnection, resolveConnectionIdentity, resolveConnectionRecord, seedQuicheLayout,
} from "./quiche_records.js";
import { installLearnedModuleCache } from "../../shared/learned_module_cache.js";
import { installQuicheCryptoBinding } from "./quiche_crypto_binding.js";

const G = globalThis as any;
const CR = "ab".repeat(32);
const CR2 = "cd".repeat(32);
const PEER: QuicSocketAddress = { family: "AF_INET", addr: 0x08080808, port: 443 };
const OTHER_PEER: QuicSocketAddress = { family: "AF_INET", addr: 0x01010101, port: 443 };
const SELF: QuicSocketAddress = { family: "AF_INET", addr: 0xC0A80002, port: 50000 };

function fakeSsl(address: number): any {
    return { isNull: () => address === 0, toString: () => "0x" + address.toString(16) };
}

/** Binder over a fake thread id and a recording bind. */
function fakeBinder(clientRandom: string = CR) {
    let thread = 1;
    const binds: { connPtr: string; connKey: string; clientRandom: string }[] = [];
    const reads: string[] = [];
    const deps: QuicSslBinderDeps = {
        currentThreadId: () => thread,
        readClientRandom: (ssl) => { reads.push(ssl.toString()); return clientRandom; },
        bind: (connPtr, connKey, cr) => { binds.push({ connPtr, connKey, clientRandom: cr }); return true; },
    };
    return { binder: createQuicSslBinder(deps), binds, reads, setThread: (t: number) => { thread = t; } };
}

let sent: any[] = [];
let previousSend: any;

beforeEach(() => {
    sent = [];
    previousSend = G.send;
    G.send = (msg: any) => { sent.push(msg); };
});

afterEach(() => {
    G.send = previousSend;
    setKeylogEnabled(true);
});

// ---- per-thread binding -------------------------------------------------------

test("a secret binds only on the thread that is inside OnCryptoFrame", () => {
    const { binder, binds, setThread } = fakeBinder();
    binder.enterCryptoFrame({ connPtr: "0xc0", connKey: "0xc0" });
    setThread(2);
    assert.equal(binder.onSslSecret(fakeSsl(0x55), "libcronet.so"), false);
    setThread(1);
    assert.equal(binder.onSslSecret(fakeSsl(0x55), "libcronet.so"), true);
    assert.deepEqual(binds, [{ connPtr: "0xc0", connKey: "0xc0", clientRandom: CR }]);
});

test("leaving OnCryptoFrame clears the thread's connection", () => {
    const { binder, binds } = fakeBinder();
    binder.leaveCryptoFrame(binder.enterCryptoFrame({ connPtr: "0xc0", connKey: "0xc0" }));
    assert.equal(binder.onKeylogClientRandom(CR), false);
    assert.equal(binds.length, 0);
});

test("a nested OnCryptoFrame restores the outer connection on leave", () => {
    const { binder, binds } = fakeBinder();
    const outer = binder.enterCryptoFrame({ connPtr: "0xa", connKey: "0xa" });
    const inner = binder.enterCryptoFrame({ connPtr: "0xb", connKey: "0xb" });
    binder.onKeylogClientRandom(CR2);
    binder.leaveCryptoFrame(inner);
    binder.onKeylogClientRandom(CR);
    binder.leaveCryptoFrame(outer);
    assert.equal(binder.onKeylogClientRandom(CR), false);
    assert.deepEqual(binds, [
        { connPtr: "0xb", connKey: "0xb", clientRandom: CR2 },
        { connPtr: "0xa", connKey: "0xa", clientRandom: CR },
    ]);
});

test("a non-hex or all-zero client_random binds nothing", () => {
    const { binder, binds } = fakeBinder();
    binder.enterCryptoFrame({ connPtr: "0xc0", connKey: "0xc0" });
    assert.equal(binder.onKeylogClientRandom("zz".repeat(32)), false);
    assert.equal(binder.onKeylogClientRandom("00".repeat(32)), false);
    assert.equal(binder.onKeylogClientRandom("ab"), false);
    assert.equal(binds.length, 0);
});

test("two threads keep their own connection", () => {
    const { binder, binds, setThread } = fakeBinder();
    binder.enterCryptoFrame({ connPtr: "0xa", connKey: "0xa" });
    setThread(2);
    binder.enterCryptoFrame({ connPtr: "0xb", connKey: "0xb#1" });
    binder.onKeylogClientRandom(CR2.toUpperCase());
    setThread(1);
    binder.onKeylogClientRandom(CR);
    assert.deepEqual(binds, [
        { connPtr: "0xb", connKey: "0xb#1", clientRandom: CR2 },
        { connPtr: "0xa", connKey: "0xa", clientRandom: CR },
    ]);
});

test("no client_random is read outside a CRYPTO frame (TCP TLS secrets)", () => {
    const { binder, reads } = fakeBinder();
    assert.equal(binder.onSslSecret(fakeSsl(0x55), "libmonochrome_64.so"), false);
    assert.deepEqual(reads, []);
});

test("an unreadable client_random binds nothing", () => {
    const { binder, binds } = fakeBinder("");
    binder.enterCryptoFrame({ connPtr: "0xc0", connKey: "0xc0" });
    assert.equal(binder.onSslSecret(fakeSsl(0x55), "libcronet.so"), false);
    assert.equal(binder.onSslSecret(fakeSsl(0), "libcronet.so"), false);
    assert.equal(binds.length, 0);
});

// ---- records carry the bound client_random -------------------------------------

test("buildQuicMessage adds client_random only when one is bound", () => {
    const info = new QuicConnectionTracker().synthesizeInfo("0x1");
    assert.equal(buildQuicMessage(info, "0x1", "f", "read", "lib").client_random, undefined);
    assert.equal("client_random" in buildQuicMessage(info, "0x1", "f", "read", "lib", ""), false);
    assert.equal(buildQuicMessage(info, "0x1", "f", "write", "lib", CR).client_random, CR);
});

test("a bound client_random follows the connection", () => {
    const tracker = new QuicConnectionTracker();
    const linked = tracker.resolveLinked("0xc0", null, PEER);
    assert.equal(linked.clientRandom, undefined);
    assert.equal(tracker.bindClientRandom("0xc0", linked.connKey, CR), true);
    // The provisional local side is upgraded in place: same key, binding kept.
    const upgraded = tracker.resolveLinked("0xc0", SELF, PEER);
    assert.equal(upgraded.connKey, "0xc0");
    assert.equal(upgraded.clientRandom, CR);
});

test("a connection with unreadable addresses still gets its client_random", () => {
    const tracker = new QuicConnectionTracker();
    const unlinked = tracker.resolveLinked("0xdead", null, null);
    assert.equal(unlinked.reuseUndetectable, true);
    assert.equal(tracker.bindClientRandom("0xdead", unlinked.connKey, CR), true);
    assert.equal(tracker.resolveLinked("0xdead", null, null).clientRandom, CR);
});

test("an unlinked binding is kept when the connection's addresses become readable", () => {
    const tracker = new QuicConnectionTracker();
    tracker.bindClientRandom("0xc0", "0xc0", CR);
    const linked = tracker.resolveLinked("0xc0", SELF, PEER);
    assert.equal(linked.connKey, "0xc0");
    assert.equal(linked.clientRandom, CR);
    assert.equal(linked.reuseUndetectable, undefined);
});

test("a new handshake on a reused unlinked pointer replaces the old client_random", () => {
    const tracker = new QuicConnectionTracker();
    tracker.bindClientRandom("0xc0", "0xc0", CR);
    assert.equal(tracker.bindClientRandom("0xc0", "0xc0", CR2), true);
    assert.equal(tracker.resolveLinked("0xc0", null, null).clientRandom, CR2);
});

test("a later generation without its linked entry cannot be bound", () => {
    const tracker = new QuicConnectionTracker();
    assert.equal(tracker.bindClientRandom("0xdead", "0xdead#1", CR), false);
    assert.equal(tracker.bindClientRandom("0xdead", "0xdead", ""), false);
    assert.equal(tracker.resolveLinked("0xdead", null, null).clientRandom, undefined);
});

// ---- generation / address reuse -------------------------------------------------

test("a reused address starts a new generation without the old client_random", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.bindClientRandom("0xc0", first.connKey, CR);
    const reused = tracker.resolveLinked("0xc0", SELF, OTHER_PEER);
    assert.equal(reused.connKey, "0xc0#1");
    assert.equal(reused.clientRandom, undefined);
});

test("a binding for a stale generation is dropped", () => {
    const tracker = new QuicConnectionTracker();
    tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.resolveLinked("0xc0", SELF, OTHER_PEER);
    assert.equal(tracker.bindClientRandom("0xc0", "0xc0", CR), false);
    assert.equal(tracker.resolveLinked("0xc0", SELF, OTHER_PEER).clientRandom, undefined);
    assert.equal(tracker.bindClientRandom("0xc0", "0xc0#1", CR2), true);
    assert.equal(tracker.resolveLinked("0xc0", SELF, OTHER_PEER).clientRandom, CR2);
});

const MIGRATED_SELF: QuicSocketAddress = { ...SELF, port: 41228 };

// Chrome moves a handshaked connection to a new local port (one Initial on the wire).
test("a new local port with the same peer keeps the key and client_random (port migration)", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.bindClientRandom("0xc0", first.connKey, CR);
    const migrated = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(migrated.connKey, "0xc0");
    assert.equal(migrated.clientRandom, CR);
    assert.equal(migrated.selfChanged, true);
    // Post-migration CRYPTO frames of the same handshake do not rotate it.
    assert.equal(tracker.bindClientRandom("0xc0", "0xc0", CR), true);
    assert.equal(tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER).connKey, "0xc0");
});

test("records after a port migration carry the new local port; key, client_random and reuse detection stay", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.bindClientRandom("0xc0", first.connKey, CR);
    const migrated = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(migrated.connKey, "0xc0");
    assert.equal(migrated.clientRandom, CR);
    assert.equal(migrated.info.localPort, MIGRATED_SELF.port);
    assert.equal(migrated.info.localAddr, MIGRATED_SELF.addr);
    const msg = buildQuicMessage(migrated.info, migrated.connKey, "f", "write", "lib", migrated.clientRandom);
    assert.equal(msg.src_port, MIGRATED_SELF.port);
    assert.equal(msg.dst_port, PEER.port);
    assert.equal(msg.client_random, CR);
    // Later records resolve to the same updated entry.
    const later = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(later.info.localPort, MIGRATED_SELF.port);
    assert.equal(later.selfChanged, true);
    // A second handshake after the migration is still detected as pointer reuse.
    assert.equal(tracker.bindClientRandom("0xc0", later.connKey, CR2), true);
    const reused = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(reused.connKey, "0xc0#1");
    assert.equal(reused.clientRandom, CR2);
    assert.equal(reused.info.localPort, MIGRATED_SELF.port);
});

test("a reused pointer to the same peer gets a new generation on its handshake, and its records carry it", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.bindClientRandom("0xc0", first.connKey, CR);
    const reused = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(tracker.bindClientRandom("0xc0", reused.connKey, CR2), true);
    const record = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(record.connKey, "0xc0#1");
    assert.equal(record.clientRandom, CR2);
    assert.equal(record.selfChanged, undefined);
    assert.equal(record.info.localPort, MIGRATED_SELF.port);
    const msg = buildQuicMessage(record.info, record.connKey, "f", "read", "lib", record.clientRandom);
    assert.equal(msg.client_random, CR2);
    // The old generation's binding is now stale.
    assert.equal(tracker.bindClientRandom("0xc0", "0xc0", CR), false);
});

// ---- CryptoConnect marks a new connection (reuse without a client_random) ------

test("a reused pointer without a client_random gets a new generation at its CryptoConnect", () => {
    const tracker = new QuicConnectionTracker();
    // Mid-stream attach: the old connection's records went out, its handshake was never seen.
    const old = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.noteLinkedTraffic(old);
    const fresh = tracker.resolveNewHandshake("0xc0", MIGRATED_SELF, PEER);
    assert.equal(fresh.connKey, "0xc0#1");
    assert.equal(fresh.clientRandom, undefined);
    assert.equal(fresh.info.localPort, MIGRATED_SELF.port);
    assert.equal(tracker.bindClientRandom("0xc0", fresh.connKey, CR), true);
    const record = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(record.connKey, "0xc0#1");
    assert.equal(record.clientRandom, CR);
});

test("a migration after the connection's own CryptoConnect keeps the key; the next CryptoConnect splits", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveNewHandshake("0xc0", null, PEER);
    assert.equal(first.connKey, "0xc0");
    tracker.noteLinkedTraffic(first);
    assert.equal(tracker.resolveLinked("0xc0", SELF, PEER).connKey, "0xc0");
    assert.equal(tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER).connKey, "0xc0");
    assert.equal(tracker.resolveNewHandshake("0xc0", MIGRATED_SELF, PEER).connKey, "0xc0#1");
});

test("noteLinkedTraffic marks the returned generation; an unlinked identity is ignored", () => {
    const tracker = new QuicConnectionTracker();
    tracker.noteLinkedTraffic(tracker.resolveLinked("0xc0", SELF, PEER));
    // It carried records: a new handshake on the same pointer is reuse.
    assert.equal(tracker.resolveNewHandshake("0xc0", SELF, PEER).connKey, "0xc0#1");
    const unlinked = tracker.resolveLinked("0xd0", null, null);
    tracker.noteLinkedTraffic(unlinked);
    assert.equal((unlinked as any).carriedTraffic, undefined);
});

test("a first CryptoConnect keeps generation 0 and its unlinked client_random", () => {
    const tracker = new QuicConnectionTracker();
    tracker.bindClientRandom("0xc0", "0xc0", CR);
    const linked = tracker.resolveNewHandshake("0xc0", SELF, PEER);
    assert.equal(linked.connKey, "0xc0");
    assert.equal(linked.clientRandom, CR);
});

test("without CryptoConnect a migration with no client_random keeps the key (reuse undetectable)", () => {
    const tracker = new QuicConnectionTracker();
    const old = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.noteLinkedTraffic(old);
    const migrated = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(migrated.connKey, "0xc0");
    assert.equal(tracker.bindClientRandom("0xc0", migrated.connKey, CR), true);
    assert.equal(tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER).connKey, "0xc0");
});

test("a reused pointer with a different client_random still splits without CryptoConnect", () => {
    const tracker = new QuicConnectionTracker();
    const old = tracker.resolveLinked("0xc0", SELF, PEER);
    tracker.bindClientRandom("0xc0", old.connKey, CR);
    tracker.noteLinkedTraffic(old);
    const reused = tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER);
    assert.equal(tracker.bindClientRandom("0xc0", reused.connKey, CR2), true);
    assert.equal(tracker.resolveLinked("0xc0", MIGRATED_SELF, PEER).connKey, "0xc0#1");
});

// ---- observe-only never emits keys ----------------------------------------------

test("the observe-only run is once per module and fails closed without hooking or sending", async () => {
    const attached: any[] = [];
    const previousAttach = G.Interceptor.attach;
    G.Interceptor.attach = (target: any) => { attached.push(target); return {}; };
    try {
        const observed: any[] = [];
        const first = runAnchorLocatorObserveOnly("libobserve.so", (ssl) => observed.push(ssl));
        assert.equal(runAnchorLocatorObserveOnly("libobserve.so", (ssl) => observed.push(ssl)), first);
        assert.equal(await first, false);  // the test stubs are x64: no ssl_log_secret scan
        assert.deepEqual(attached, []);
        assert.deepEqual(observed, []);
        assert.deepEqual(sent, []);
    } finally {
        G.Interceptor.attach = previousAttach;
    }
});

test("an observe-only binding sends no message at all", () => {
    const { binder, binds } = fakeBinder();
    setKeylogEnabled(false);
    binder.enterCryptoFrame({ connPtr: "0xc0", connKey: "0xc0" });
    binder.onSslSecret(fakeSsl(0x55), "libcronet.so");
    assert.equal(binds.length, 1);
    assert.deepEqual(sent, []);
});

// ---- keylog path (-k) ---------------------------------------------------------

test("keylog lines reach a QUIC listener with their client_random", () => {
    const seen: string[] = [];
    // Stays registered: harmless, it only records into `seen`.
    addKeylogSslListener((_ssl: any, cr: string) => { seen.push(cr); });
    sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR.toUpperCase()} ${"ee".repeat(32)}`, fakeSsl(0x55), "libcronet.so");
    sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR} ${"ee".repeat(32)}`);  // no SSL*: not observed
    assert.deepEqual(seen, [CR]);
});

// ---- gating -------------------------------------------------------------------

test("observe-only runs with or without -k, but not with --pairip-safe or off arm64", () => {
    assert.equal(wantsObserveOnlySslHook({ keylogEnabled: false, pairipSafe: false, arch: "arm64" }), true);
    assert.equal(wantsObserveOnlySslHook({ keylogEnabled: true, pairipSafe: false, arch: "arm64" }), true);
    assert.equal(wantsObserveOnlySslHook({ keylogEnabled: false, pairipSafe: true, arch: "arm64" }), false);
    assert.equal(wantsObserveOnlySslHook({ keylogEnabled: false, pairipSafe: false, arch: "x64" }), false);
});

test("OnCryptoFrame is hooked only when some path reports the handshake", () => {
    assert.equal(wantsCryptoFrameBinding({ keylogEnabled: true, pairipSafe: true, arch: "arm64" }), true);
    assert.equal(wantsCryptoFrameBinding({ keylogEnabled: false, pairipSafe: false, arch: "arm64" }), true);
    assert.equal(wantsCryptoFrameBinding({ keylogEnabled: false, pairipSafe: true, arch: "arm64" }), false);
});

// ---- OnCryptoFrame hook end to end (layout unknown, no -k) -----------------------

/** Layout state whose memory counts reads; no connection layout learned. */
function unlearnedState(): { state: QuicheLayoutState; reads: () => number } {
    let reads = 0;
    const mem = {
        pointerSize: 8,
        readPointer: () => { reads++; return null; },
        readBytes: () => { reads++; return null; },
        isModuleAddress: () => false,
    };
    const state: QuicheLayoutState = {
        moduleName: "libcronet.so", mem, layout: null, attempts: 0, triedStreams: new Set(),
        connLayout: null, sessionConnection: null, connAttempts: 0,
    };
    return { state, reads: () => reads };
}

test("resolving a CRYPTO frame's connection spends no layout discovery attempt", () => {
    const { state, reads } = unlearnedState();
    const linked = resolveConnectionIdentity(state, 0xc1000n);
    assert.equal(linked.connKey, "0xc1000");
    assert.equal(state.connAttempts, 0);
    assert.equal(reads(), 0);
});

test("without -k a keylog line inside OnCryptoFrame binds an unlinked connection", () => {
    const listeners: any[] = [];
    const previousAttach = G.Interceptor.attach;
    const previousArch = G.Process.arch;
    G.Interceptor.attach = (_target: any, cb: any) => { listeners.push(cb); return {}; };
    G.Process.arch = "arm64";
    setKeylogEnabled(false);
    try {
        const { state } = unlearnedState();
        assert.equal(installQuicheCryptoBinding("libcronet.so", state, fakeSsl(0x1234)), true);
        const conn = { toString: () => "0xc2000" };
        const ctx: any = {};
        listeners[0].onEnter.call(ctx, [conn]);
        sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR} ${"ee".repeat(32)}`, fakeSsl(0x55), "libcronet.so");
        listeners[0].onLeave.call(ctx);
        assert.equal(resolveConnectionIdentity(state, 0xc2000n).clientRandom, CR);
        assert.equal(state.connAttempts, 0);
        // No -k: the keylog line itself never leaves the agent.
        assert.deepEqual(sent.filter((m) => m.contentType === "keylog"), []);
    } finally {
        G.Interceptor.attach = previousAttach;
        G.Process.arch = previousArch;
    }
});

test("a reused unlinked pointer is re-entered so its new handshake rebinds", () => {
    const listeners: any[] = [];
    const previousAttach = G.Interceptor.attach;
    const previousArch = G.Process.arch;
    G.Interceptor.attach = (_target: any, cb: any) => { listeners.push(cb); return {}; };
    G.Process.arch = "arm64";
    try {
        const { state } = unlearnedState();
        installQuicheCryptoBinding("libcronet_reuse.so", state, fakeSsl(0x1234));
        const conn = { toString: () => "0xc3000" };
        for (const cr of [CR, CR2]) {
            const ctx: any = {};
            listeners[0].onEnter.call(ctx, [conn]);
            assert.equal(ctx.entered, true);
            sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${cr} ${"ee".repeat(32)}`, fakeSsl(0x55), "libcronet_reuse.so");
            listeners[0].onLeave.call(ctx);
        }
        assert.equal(resolveConnectionIdentity(state, 0xc3000n).clientRandom, CR2);
    } finally {
        G.Interceptor.attach = previousAttach;
        G.Process.arch = previousArch;
    }
});

// ---- CryptoConnect hook (0-RTT early secret, before any CRYPTO frame) ----------

const HANDSHAKER = 0xd1000n;
const SESSION = 0xd2000n;
const CONNECTION = 0xd3000n;
const CONNECTION_VTABLE = 0x5000100n;

/** Layout state with session+0x58 -> connection learned; handshaker+0x108 -> session. */
function learnedState(moduleName: string): QuicheLayoutState {
    const words = new Map<bigint, bigint>([
        [HANDSHAKER + 0x108n, SESSION], [SESSION + 0x58n, CONNECTION], [CONNECTION, CONNECTION_VTABLE],
    ]);
    const mem = {
        pointerSize: 8,
        readPointer: (a: bigint) => words.get(a) ?? null,
        readBytes: () => null,
        isModuleAddress: () => false,
    };
    return {
        moduleName, mem, layout: null, attempts: 0, triedStreams: new Set(),
        connLayout: { connectionAddresses: 0x248, connectionVtable: CONNECTION_VTABLE },
        sessionConnection: 0x58, connAttempts: 0,
    };
}

test("a fallback session_ offset is adopted only after two different handshakers agree", () => {
    const state = learnedState("libcronet_scan.so");
    const words = new Map<bigint, bigint>([[SESSION + 0x58n, CONNECTION], [CONNECTION, CONNECTION_VTABLE]]);
    const [first, second] = [0x7600000n, 0x7700000n];
    words.set(first + 0x110n, SESSION);
    words.set(second + 0x110n, SESSION);
    state.mem = { ...state.mem, readPointer: (a: bigint) => words.get(a) ?? null };
    assert.equal(handshakerConnection(state, first), CONNECTION);
    assert.equal(handshakerConnection(state, first), CONNECTION);
    assert.equal(state.handshakerSession, undefined);
    assert.equal(handshakerConnection(state, second), CONNECTION);
    assert.equal(state.handshakerSession, 0x110);
});

/** Installs both hooks of `moduleName` with -k off; returns [OnCryptoFrame, CryptoConnect] listeners. */
function withCryptoHooks(run: (listeners: any[]) => void): void {
    const listeners: any[] = [];
    const previousAttach = G.Interceptor.attach;
    const previousArch = G.Process.arch;
    G.Interceptor.attach = (_target: any, cb: any) => { listeners.push(cb); return {}; };
    G.Process.arch = "arm64";
    setKeylogEnabled(false);
    try {
        run(listeners);
    } finally {
        G.Interceptor.attach = previousAttach;
        G.Process.arch = previousArch;
    }
}

const handshakerArg = { toString: () => "0x" + HANDSHAKER.toString(16) };

test("an early secret logged inside CryptoConnect binds the handshaker's connection, emitting no key", () => {
    withCryptoHooks((listeners) => {
        const state = learnedState("libcronet_0rtt.so");
        assert.equal(installQuicheCryptoBinding("libcronet_0rtt.so", state, fakeSsl(0x1234), fakeSsl(0x5678)), true);
        assert.equal(listeners.length, 2);
        const ctx: any = {};
        listeners[1].onEnter.call(ctx, [handshakerArg]);
        assert.equal(ctx.entered, true);
        sendKeylog(`CLIENT_EARLY_TRAFFIC_SECRET ${CR} ${"ee".repeat(32)}`, fakeSsl(0x55), "libcronet_0rtt.so");
        listeners[1].onLeave.call(ctx);
        assert.equal(resolveConnectionIdentity(state, CONNECTION).clientRandom, CR);
        assert.equal(state.handshakerSession, 0x108);
        assert.equal(state.connAttempts, 0);
        assert.deepEqual(sent.filter((m) => m.contentType === "keylog"), []);
        // Scope closed on leave: a later secret on this thread binds nothing new.
        sendKeylog(`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR2} ${"ee".repeat(32)}`, fakeSsl(0x55), "libcronet_0rtt.so");
        assert.equal(resolveConnectionIdentity(state, CONNECTION).clientRandom, CR);
    });
});

test("CryptoConnect before the session layout is learned stays unbound and spends no discovery attempt", () => {
    withCryptoHooks((listeners) => {
        const { state, reads } = unlearnedState();
        state.moduleName = "libcronet_0rtt_unlearned.so";
        installQuicheCryptoBinding(state.moduleName, state, fakeSsl(0x1234), fakeSsl(0x5678));
        const ctx: any = {};
        listeners[1].onEnter.call(ctx, [handshakerArg]);
        listeners[1].onLeave.call(ctx);
        assert.equal(ctx.entered, false);
        assert.equal(state.connAttempts, 0);
        assert.equal(reads(), 0);
    });
});

// ---- CryptoConnect with cached layout hints (first connection of a run) ---------

const HINT_BASE = 0x5000000n;
// Own objects: the tracker is process-wide and the tests above already bound CONNECTION.
const SEEDED_HANDSHAKER = 0xe1000n;
const SEEDED_SESSION = 0xe2000n;
const SEEDED_CONNECTION = 0xe3000n;
const seededHandshakerArg = { toString: () => "0x" + SEEDED_HANDSHAKER.toString(16) };
const HINT_MODULE: any = { name: "libcronet_seeded.so", base: { toString: () => "0x" + HINT_BASE.toString(16) }, size: 0x100000 };

/** QuicSocketAddress bytes; family 2 (unspecified) for a 0-RTT self address. */
function socketAddress(ip: number[], port: number, family: number): number[] {
    const out = new Array(24).fill(0);
    ip.forEach((b, i) => { out[i] = b; });
    out[16] = family;
    out[20] = port & 0xff; out[21] = port >> 8;
    return out;
}

/** Nothing learned yet; handshaker+0x108 -> session+0x58 -> 0-RTT connection (peer known, self unspecified). */
function freshHandshakeState(moduleName: string): QuicheLayoutState {
    const words = new Map<bigint, bigint>([
        [SEEDED_HANDSHAKER + 0x108n, SEEDED_SESSION], [SEEDED_SESSION + 0x58n, SEEDED_CONNECTION],
        [SEEDED_CONNECTION, CONNECTION_VTABLE],
    ]);
    const pair = Uint8Array.from([...socketAddress([0, 0, 0, 0], 0, 2), ...socketAddress([8, 8, 8, 8], 443, 0)]);
    const mem = {
        pointerSize: 8,
        readPointer: (a: bigint) => words.get(a) ?? null,
        readBytes: (a: bigint, n: number) => (a === SEEDED_CONNECTION + 0x248n ? pair.slice(0, n) : null),
        isModuleAddress: (a: bigint) => a >= HINT_BASE && a < HINT_BASE + 0x100000n,
    };
    return { moduleName, mem, layout: null, attempts: 0, triedStreams: new Set(), connLayout: null,
             sessionConnection: null, connAttempts: 0 };
}

function withHints(layout: Record<string, number>, run: (sent: any[]) => void): void {
    const sent: any[] = [];
    installLearnedModuleCache({ "cc01|1048576|arm64": { module: "libcronet_seeded.so", layout } }, {
        identify: () => ({ buildId: "cc01", size: 0x100000, arch: "arm64" }),
        emit: (p) => sent.push(p), schedule: (flush) => flush(), arch: () => "arm64",
    });
    try { run(sent); } finally { installLearnedModuleCache({}); }
}

const SESSION_HINTS = {
    "quiche.layout.sessionConnection": 0x58, "quiche.layout.connectionAddresses": 0x248,
    "quiche.layout.connectionVtableRva": Number(CONNECTION_VTABLE - HINT_BASE),
};

test("a seeded session layout lets the first CryptoConnect bind its 0-RTT secret before any discovery", () => {
    withCryptoHooks((listeners) => withHints(SESSION_HINTS, (sent) => {
        const state = freshHandshakeState("libcronet_seeded.so");
        installQuicheCryptoBinding(state.moduleName, state, fakeSsl(0x1234), fakeSsl(0x5678));
        assert.equal(handshakerConnection(state, SEEDED_HANDSHAKER), null);   // unseeded: cannot bind yet
        seedQuicheLayout(state, HINT_MODULE);
        const ctx: any = {};
        listeners[1].onEnter.call(ctx, [seededHandshakerArg]);
        assert.equal(ctx.entered, true);
        sendKeylog(`CLIENT_EARLY_TRAFFIC_SECRET ${CR} ${"ee".repeat(32)}`, fakeSsl(0x55), state.moduleName);
        listeners[1].onLeave.call(ctx);
        assert.equal(resolveConnectionIdentity(state, SEEDED_CONNECTION).clientRandom, CR);
        assert.equal(state.connAttempts, 0);
        assert.equal(state.seeded?.has("connection"), false);           // validated on the live connection
        // Only the newly found handshaker offset is reported; the seeded values are not.
        assert.deepEqual(sent.filter((m) => m.layout).map((m) => m.layout), [{ "quiche.layout.handshakerSession": 0x108 }]);
    }));
});

test("a stale handshakerSession hint is dropped when the slot scan finds session_ elsewhere", () => {
    withHints({ ...SESSION_HINTS, "quiche.layout.handshakerSession": 0x110 }, () => {
        const state = freshHandshakeState("libcronet_seeded.so");
        seedQuicheLayout(state, HINT_MODULE);
        assert.equal(state.handshakerSession, 0x110);
        assert.equal(handshakerConnection(state, SEEDED_HANDSHAKER), SEEDED_CONNECTION);
        assert.equal(state.handshakerSession, 0x110, "one failed check is tolerated");
        assert.equal(handshakerConnection(state, SEEDED_HANDSHAKER), SEEDED_CONNECTION);
        assert.equal(state.handshakerSession, 0x108);
        assert.equal(state.seeded?.has("handshakerSession"), false);
    });
});

// Own objects: the tracker is process-wide.
const REUSE_HANDSHAKER = 0xf1000n;
const REUSE_SESSION = 0xf2000n;
const REUSE_CONNECTION = 0xf3000n;

/** Learned layout whose connection has a readable self + peer (192.168.0.2:`selfPort` -> 8.8.8.8:443). */
function linkedHandshakeState(moduleName: string, selfPort: { port: number }): QuicheLayoutState {
    const state = learnedState(moduleName);
    const words = new Map<bigint, bigint>([
        [REUSE_HANDSHAKER + 0x108n, REUSE_SESSION], [REUSE_SESSION + 0x58n, REUSE_CONNECTION],
        [REUSE_CONNECTION, CONNECTION_VTABLE],
    ]);
    state.mem = {
        ...state.mem,
        readPointer: (a: bigint) => words.get(a) ?? null,
        readBytes: (a: bigint, n: number) => (a === REUSE_CONNECTION + 0x248n
            ? Uint8Array.from([...socketAddress([192, 168, 0, 2], selfPort.port, 0),
                               ...socketAddress([8, 8, 8, 8], 443, 0)]).slice(0, n)
            : null),
    };
    return state;
}

test("CryptoConnect on a pointer whose old connection carried records starts a new generation for its secret", () => {
    withCryptoHooks((listeners) => {
        const self = { port: 50000 };
        const state = linkedHandshakeState("libcronet_reuse_cc.so", self);
        installQuicheCryptoBinding(state.moduleName, state, fakeSsl(0x1234), fakeSsl(0x5678));
        // Attached mid-stream: the old connection's record goes out without a client_random.
        const old = resolveConnectionRecord(state, REUSE_CONNECTION, 0, "f", "write");
        const oldKey = old!.message.ssl_session_id;
        assert.equal(old!.message.client_random, undefined);
        // A new connection reuses the pointer from a new UDP socket to the same peer.
        self.port = 41228;
        const ctx: any = {};
        listeners[1].onEnter.call(ctx, [{ toString: () => "0x" + REUSE_HANDSHAKER.toString(16) }]);
        assert.equal(ctx.entered, true);
        sendKeylog(`CLIENT_EARLY_TRAFFIC_SECRET ${CR2} ${"ee".repeat(32)}`, fakeSsl(0x55), state.moduleName);
        listeners[1].onLeave.call(ctx);
        const fresh = resolveConnectionIdentity(state, REUSE_CONNECTION);
        assert.equal(fresh.connKey, oldKey + "#1");
        assert.equal(fresh.clientRandom, CR2);
        assert.equal(fresh.info.localPort, 41228);
    });
});

test("without a located CryptoConnect only OnCryptoFrame is hooked", () => {
    withCryptoHooks((listeners) => {
        installQuicheCryptoBinding("libcronet_no_cc.so", learnedState("libcronet_no_cc.so"), fakeSsl(0x1234), null);
        assert.equal(listeners.length, 1);
    });
});
