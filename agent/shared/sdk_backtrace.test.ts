// Unit tests for the opt-in SDK/caller-attribution helper (shared/sdk_backtrace.ts).
//
// Run: npm run test:agent
//
// Covers (without a device): the pure native-frame symbolizer (mapping, 32-frame
// cap, per-frame failure fallback) and the CRITICAL flag-off guarantee — when
// --attribute-sdk is off (the default; config_batch is empty in tests, so
// attribute_sdk stays false), maybeCaptureCallerStack() reads no SSL state (the
// join provider is never invoked) and emits no message. The on-device capture
// path (Thread.backtrace / Java stack) is exercised manually on a device.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;

// DebugSymbol stub: module + symbol derived from the address string.
G.DebugSymbol = {
    fromAddress: (p: any) => ({ moduleName: "libfoo.so", name: "sym_" + p.toString() }),
};

import { symbolizeNativeFrames, maybeCaptureCallerStack, forgetSsl } from "./sdk_backtrace.js";

function ptr(s: string): any { return { toString: () => s }; }

test("symbolizeNativeFrames maps module/symbol/address", () => {
    const frames = symbolizeNativeFrames([ptr("0x10"), ptr("0x20")]);
    assert.equal(frames.length, 2);
    assert.deepEqual(frames[0], { module: "libfoo.so", symbol: "sym_0x10", address: "0x10" });
    assert.equal(frames[1].address, "0x20");
});

test("symbolizeNativeFrames caps at 32 frames by default", () => {
    const addrs = Array.from({ length: 50 }, (_, i) => ptr("0x" + i));
    assert.equal(symbolizeNativeFrames(addrs).length, 32);
});

test("symbolizeNativeFrames honours an explicit max", () => {
    const addrs = Array.from({ length: 10 }, (_, i) => ptr("0x" + i));
    assert.equal(symbolizeNativeFrames(addrs, 4).length, 4);
});

test("symbolizeNativeFrames falls back to the raw address when symbolization throws", () => {
    const prev = G.DebugSymbol.fromAddress;
    G.DebugSymbol.fromAddress = () => { throw new Error("no symbol"); };
    try {
        const frames = symbolizeNativeFrames([ptr("0xdead")]);
        assert.deepEqual(frames[0], { module: "", symbol: null, address: "0xdead" });
    } finally {
        G.DebugSymbol.fromAddress = prev;
    }
});

test("maybeCaptureCallerStack is inert when attribute_sdk is off (default)", () => {
    const sent: any[] = [];
    const prevSend = G.send;
    G.send = (m: any) => sent.push(m);
    let providerCalls = 0;
    try {
        maybeCaptureCallerStack(ptr("0x1"), {} as any, () => { providerCalls++; return {}; });
        maybeCaptureCallerStack(ptr("0x2"), {} as any, () => { providerCalls++; return {}; });
    } finally {
        G.send = prevSend;
    }
    assert.equal(sent.length, 0, "no caller_stack message is emitted when the flag is off");
    assert.equal(providerCalls, 0, "the join provider is never invoked when the flag is off (no SSL state read)");
});

test("forgetSsl is a safe no-op when nothing was captured", () => {
    assert.doesNotThrow(() => forgetSsl("0xabc"));
});

// ---------------------------------------------------------------------------
// CallerStackCache (design P1 B5): pure, every Frida dependency injected.
// ---------------------------------------------------------------------------

import { CallerStackCache, recordJoinFields, captureJavaFrames, readProcThreadName } from "./sdk_backtrace.js";
import { sendCallerStack } from "./shared_structures.js";
import { setPlatform } from "./frida-test-stubs.js";

const CR = "ab".repeat(32);
const TUPLE = { src_addr: "10.0.0.2", dst_addr: "1.2.3.4", src_port: 40000, dst_port: 443, ss_family: "AF_INET" };

interface Harness {
    cache: CallerStackCache;
    sent: any[];
    captures: number;
    threadNameReads: number;
    dropped: number;
    mayArrive: { value: boolean };
}

function harness(capacity = 1024, tid = 7): Harness {
    const h: any = { sent: [], captures: 0, threadNameReads: 0, dropped: 0, mayArrive: { value: true } };
    h.cache = new CallerStackCache({
        send: (join, java, native, meta) => h.sent.push({ join, java, native, meta }),
        capture: () => { h.captures++; return { native: [{ module: "m", symbol: "s", address: "0x1" }], java: ["a.B"] }; },
        now: () => 1000,
        currentThreadId: () => tid,
        pid: () => 4242,
        readThreadName: (t) => { h.threadNameReads++; return ` Chrome_IOThread${t}\n`; },
        clientRandomMayArrive: () => h.mayArrive.value,
        onDroppedUnsent: (total) => { h.dropped = total; },
    }, capacity);
    return h as Harness;
}

function captureOn(h: Harness, ssl: string, gen: number, join: any, module = "libwebviewchromium.so"): boolean {
    return h.cache.capture({ sslKey: ssl, generation: gen, module, context: {}, join: () => ({ ...join }) });
}

test("CallerStackCache captures frames once per (SSL*, generation)", () => {
    const h = harness();
    assert.equal(captureOn(h, "0x10", 1, { client_random: CR }), true);
    assert.equal(captureOn(h, "0x10", 1, { client_random: CR }), false);
    assert.equal(h.captures, 1, "never re-unwinds the same connection");
    assert.equal(h.sent.length, 1);
});

test("CallerStackCache captures again for a new generation (after SSL_free/forget)", () => {
    const h = harness();
    captureOn(h, "0x10", 1, { client_random: CR });
    h.cache.forget("0x10", 1);
    assert.equal(captureOn(h, "0x10", 2, { client_random: "cd".repeat(32) }), true);
    assert.equal(h.captures, 2);
    assert.equal(h.sent.length, 2);
});

test("CallerStackCache holds a cr-less capture until a join with client_random is offered, then sends once", () => {
    const h = harness();
    captureOn(h, "0x20", 3, TUPLE);
    assert.equal(h.sent.length, 0, "held: a client_random may still arrive");
    assert.equal(h.cache.offer("0x20", 3, { ...TUPLE }), false, "tuple-only offer still held");
    assert.equal(h.cache.offer("0x20", 3, { ...TUPLE, client_random: CR, src_port: 40001 }), true);
    assert.equal(h.cache.offer("0x20", 3, { ...TUPLE, client_random: CR }), false, "sent at most once");
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].join.client_random, CR);
    assert.equal(h.sent[0].join.src_port, 40001, "the record's own tuple wins");
    assert.equal(h.captures, 1);
});

test("CallerStackCache offer for an unknown or other-generation key is ignored", () => {
    const h = harness();
    captureOn(h, "0x21", 1, {});
    assert.equal(h.cache.offer("0x21", 2, { client_random: CR }), false);
    assert.equal(h.cache.offer("0x99", 1, { client_random: CR }), false);
    assert.equal(h.sent.length, 0);
});

test("CallerStackCache sends tuple-only only once no client_random can arrive (no layout, locator settled)", () => {
    const h = harness();
    captureOn(h, "0x30", 1, TUPLE);
    assert.equal(h.sent.length, 0);
    h.mayArrive.value = false;
    assert.equal(h.cache.offer("0x30", 1, { ...TUPLE }), true);
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].join.client_random, undefined);

    captureOn(h, "0x31", 1, TUPLE);
    assert.equal(h.sent.length, 2, "settled module: a tuple-only capture is sent immediately");
    captureOn(h, "0x32", 1, {});
    assert.equal(h.sent.length, 2, "no tuple and no cr: held even when settled");
});

test("CallerStackCache LRU eviction drops held entries and counts them", () => {
    const h = harness(2);
    captureOn(h, "0x40", 1, { client_random: CR });  // sent: eviction not counted
    captureOn(h, "0x41", 1, TUPLE);                   // held
    captureOn(h, "0x42", 1, TUPLE);                   // evicts 0x40 (sent)
    assert.equal(h.cache.droppedUnsentCount, 0);
    captureOn(h, "0x43", 1, TUPLE);                   // evicts 0x41 (held)
    assert.equal(h.cache.droppedUnsentCount, 1);
    assert.equal(h.dropped, 1);
    assert.equal(h.cache.size, 2);
    assert.equal(h.cache.offer("0x41", 1, { client_random: CR }), false, "evicted entry cannot be sent");
});

const UNJOINABLE = { src_port: 40000 };

test("CallerStackCache forget of a held entry without a usable join counts it as dropped", () => {
    const h = harness();
    captureOn(h, "0x50", 1, UNJOINABLE);
    h.cache.forget("0x50", 1);
    assert.equal(h.cache.droppedUnsentCount, 1);
    assert.doesNotThrow(() => h.cache.forget("0x50", 1));
});

test("CallerStackCache message meta: tid, trimmed thread_name (cached), pid, transport_module", () => {
    const h = harness(1024, 99);
    captureOn(h, "0x60", 1, { client_random: CR });
    captureOn(h, "0x61", 1, { client_random: CR });
    assert.deepEqual(h.sent[0].meta, {
        tid: 99, thread_name: "Chrome_IOThread99", pid: 4242, transport_module: "libwebviewchromium.so",
    });
    assert.equal(h.threadNameReads, 1, "thread name read once per tid");
});

test("CallerStackCache treats a throwing join provider as an empty join", () => {
    const h = harness();
    h.cache.capture({ sslKey: "0x70", generation: 1, module: "", context: {}, join: () => { throw new Error("x"); } });
    assert.equal(h.sent.length, 0);
    assert.equal(h.cache.size, 1);
});

test("recordJoinFields copies only present join fields and skips an empty client_random", () => {
    assert.deepEqual(recordJoinFields({ ...TUPLE, client_random: "", data: "x", ssl_session_id: "s" }),
        { ...TUPLE, ssl_session_id: "s" });
    assert.deepEqual(recordJoinFields({ client_random: CR }), { client_random: CR });
});

test("captureJavaFrames skips Java entirely when the current thread has no JNIEnv", () => {
    let performed = false;
    const bridge = { available: true, vm: { tryGetEnv: () => null }, perform: () => { performed = true; }, use: () => null };
    assert.deepEqual(captureJavaFrames(bridge), []);
    assert.equal(performed, false, "never Java.perform on an unattached thread");
    assert.deepEqual(captureJavaFrames({ available: false }), []);
    assert.deepEqual(captureJavaFrames({ available: true, vm: null, perform: () => { performed = true; } }), []);
    assert.equal(performed, false);
});

test("captureJavaFrames reads the stack when the current thread is attached", () => {
    const elems = [{ getClassName: () => "a.B" }, { getClassName: () => "c.D" }];
    const bridge = {
        available: true, vm: { tryGetEnv: () => ({}) },
        perform: (fn: () => void) => fn(),
        use: () => ({ currentThread: () => ({ getStackTrace: () => elems }) }),
    };
    assert.deepEqual(captureJavaFrames(bridge), ["a.B", "c.D"]);
});

test("readProcThreadName returns '' off Linux and on read errors", () => {
    const prevFile = G.File;
    try {
        setPlatform("darwin");
        G.File = { readAllText: () => "x\n" };
        assert.equal(readProcThreadName(1), "");
        setPlatform("linux");
        assert.equal(readProcThreadName(1), "x");
        G.File = { readAllText: () => { throw new Error("ENOENT"); } };
        assert.equal(readProcThreadName(1), "");
    } finally {
        G.File = prevFile;
        setPlatform("linux");
    }
});

test("sendCallerStack carries client_random and the meta fields additively", () => {
    const sent: any[] = [];
    const prevSend = G.send;
    G.send = (m: any) => sent.push(m);
    try {
        sendCallerStack({ ...TUPLE, client_random: CR }, ["a.B"], [], {
            tid: 5, thread_name: "t", pid: 9, transport_module: "libssl.so",
        });
        sendCallerStack({ ...TUPLE }, [], []);
    } finally {
        G.send = prevSend;
    }
    const msg = sent[0].payload ?? sent[0];
    assert.equal(msg.contentType, "caller_stack");
    assert.equal(msg.client_random, CR);
    assert.equal(msg.tid, 5);
    assert.equal(msg.thread_name, "t");
    assert.equal(msg.pid, 9);
    assert.equal(msg.transport_module, "libssl.so");
    const legacy = sent[1].payload ?? sent[1];
    assert.equal(legacy.tid, undefined, "no meta: unchanged wire shape");
});

// ---------------------------------------------------------------------------
// Tuple fallback for held entries (on-device P1 gap: -p held caller_stacks forever)
// ---------------------------------------------------------------------------

import { TUPLE_FALLBACK_AFTER_OFFERS } from "./caller_stack_cache.js";
import { clientRandomMayArrive } from "./sdk_backtrace.js";
import {
    markLayoutLocatorSettled, markLayoutLocatorStarted, resetSslIdentityState, setSslLayout,
} from "./ssl_identity.js";

test("CallerStackCache sends tuple-only after N cr-less offers, exactly once", () => {
    const h = harness();
    captureOn(h, "0x40", 1, TUPLE);
    for (let i = 1; i < TUPLE_FALLBACK_AFTER_OFFERS; i++) {
        assert.equal(h.cache.offer("0x40", 1, { ...TUPLE }), false, `offer ${i} still held`);
    }
    assert.equal(h.cache.offer("0x40", 1, { ...TUPLE }), true, "Nth cr-less offer sends");
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].join.client_random, undefined);
    assert.equal(h.sent[0].join.dst_port, 443);
    assert.equal(h.cache.offer("0x40", 1, { ...TUPLE }), false, "never twice");
    assert.equal(h.cache.offer("0x40", 1, { ...TUPLE, client_random: CR }), false, "a late cr sends nothing more");
    assert.equal(h.sent.length, 1);
});

test("CallerStackCache: N cr-less offers without any tuple stay held", () => {
    const h = harness();
    captureOn(h, "0x41", 1, {});
    for (let i = 0; i < TUPLE_FALLBACK_AFTER_OFFERS * 2; i++) h.cache.offer("0x41", 1, { ssl_session_id: "" } as any);
    assert.equal(h.sent.length, 0);
});

test("CallerStackCache: a cr offered before N wins over the tuple fallback", () => {
    const h = harness();
    captureOn(h, "0x42", 1, TUPLE);
    for (let i = 1; i < TUPLE_FALLBACK_AFTER_OFFERS; i++) h.cache.offer("0x42", 1, { ...TUPLE });
    assert.equal(h.cache.offer("0x42", 1, { ...TUPLE, client_random: CR }), true);
    assert.equal(h.sent[0].join.client_random, CR);
});

test("shouldSend: tuple after N offers even while a client_random may arrive", () => {
    const h = harness();
    assert.equal(TUPLE_FALLBACK_AFTER_OFFERS, 8);
    assert.equal(h.cache.shouldSend({ ...TUPLE }, "m", TUPLE_FALLBACK_AFTER_OFFERS - 1), false);
    assert.equal(h.cache.shouldSend({ ...TUPLE }, "m", TUPLE_FALLBACK_AFTER_OFFERS), true);
    assert.equal(h.cache.shouldSend({}, "m", TUPLE_FALLBACK_AFTER_OFFERS), false);
});

test("clientRandomMayArrive: pending locator -> true; settled with no/unusable layout -> false; usable -> true", () => {
    resetSslIdentityState();
    const mod = "libwebviewchromium.so";
    try {
        assert.equal(clientRandomMayArrive(mod), false, "never started, no layout");
        markLayoutLocatorStarted(mod);
        setSslLayout(mod, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
        assert.equal(clientRandomMayArrive(mod), true, "locator still running");
        markLayoutLocatorSettled(mod);
        assert.equal(clientRandomMayArrive(mod), false, "settled; stock layout not usable (one SSL*)");
        setSslLayout(mod, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
        assert.equal(clientRandomMayArrive(mod), true, "decoded layout is usable");
    } finally {
        resetSslIdentityState();
    }
});

test("CallerStackCache: held entry falls back to its tuple once the layout is unusable after settle", () => {
    resetSslIdentityState();
    const mod = "libwebviewchromium.so";
    const h = harness();
    // The harness's injected predicate stands in for the real one; drive it from ssl_identity state.
    h.mayArrive.value = true;
    try {
        markLayoutLocatorStarted(mod);
        setSslLayout(mod, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
        h.mayArrive.value = clientRandomMayArrive(mod);
        captureOn(h, "0x43", 1, TUPLE, mod);
        assert.equal(h.sent.length, 0, "held while the locator runs");
        markLayoutLocatorSettled(mod);
        h.mayArrive.value = clientRandomMayArrive(mod);
        assert.equal(h.cache.offer("0x43", 1, { ...TUPLE }), true, "first offer after settle sends the tuple");
        assert.equal(h.sent.length, 1);
    } finally {
        resetSslIdentityState();
    }
});

test("CallerStackCache forget only drops the given generation", () => {
    const h = harness();
    captureOn(h, "0x80", 1, UNJOINABLE);
    h.cache.forget("0x80", 2);
    assert.equal(h.cache.size, 1, "other generation untouched");
    assert.equal(h.cache.droppedUnsentCount, 0);
    h.cache.forget("0x80", 1);
    assert.equal(h.cache.size, 0);
    assert.equal(h.cache.droppedUnsentCount, 1);
});

test("CallerStackCache hasHeldEntries/isHeld track unsent entries through send, forget and eviction", () => {
    const h = harness(2);
    assert.equal(h.cache.hasHeldEntries, false);
    captureOn(h, "0x90", 1, { client_random: CR });
    assert.equal(h.cache.hasHeldEntries, false, "sent immediately: nothing held");
    assert.equal(h.cache.isHeld("0x90", 1), false);
    captureOn(h, "0x91", 1, TUPLE);
    assert.equal(h.cache.hasHeldEntries, true);
    assert.equal(h.cache.isHeld("0x91", 1), true);
    assert.equal(h.cache.isHeld("0x91", 2), false);
    h.cache.offer("0x91", 1, { client_random: CR });
    assert.equal(h.cache.hasHeldEntries, false, "sent on offer");
    captureOn(h, "0x92", 1, TUPLE);
    h.cache.forget("0x92", 1);
    assert.equal(h.cache.hasHeldEntries, false, "forgotten");
    captureOn(h, "0x93", 1, TUPLE);
    captureOn(h, "0x94", 1, TUPLE);
    captureOn(h, "0x95", 1, TUPLE); // evicts 0x93 (held)
    assert.equal(h.cache.isHeld("0x93", 1), false);
    h.cache.forget("0x94", 1);
    h.cache.forget("0x95", 1);
    assert.equal(h.cache.hasHeldEntries, false, "held count back to zero after eviction + forgets");
});

import { safeJoin } from "./caller_stack_cache.js";

test("safeJoin returns {} for a throwing or nullish provider", () => {
    assert.deepEqual(safeJoin(() => { throw new Error("x"); }), {});
    assert.deepEqual(safeJoin(() => undefined as any), {});
    assert.deepEqual(safeJoin(() => ({ dst_port: 443 } as any)), { dst_port: 443 });
});

// ---------------------------------------------------------------------------
// forget (SSL_free) sends a held, joinable entry once instead of dropping it
// ---------------------------------------------------------------------------

test("CallerStackCache forget sends a held entry with a tuple once instead of dropping it", () => {
    const h = harness();
    captureOn(h, "0xa0", 1, TUPLE);
    assert.equal(h.sent.length, 0, "held while a client_random may arrive");
    h.cache.forget("0xa0", 1);
    assert.equal(h.sent.length, 1, "sent on SSL_free: the tuple is a usable join");
    assert.equal(h.sent[0].join.dst_port, 443);
    assert.equal(h.cache.droppedUnsentCount, 0);
    assert.equal(h.cache.hasHeldEntries, false);
    h.cache.forget("0xa0", 1);
    assert.equal(h.sent.length, 1, "never sent twice");
});

test("CallerStackCache forget sends with the join a cr-less record offered earlier", () => {
    const h = harness();
    captureOn(h, "0xa1", 1, {});
    h.cache.offer("0xa1", 1, TUPLE);
    assert.equal(h.sent.length, 0, "one cr-less offer keeps it held");
    h.cache.forget("0xa1", 1);
    assert.equal(h.sent.length, 1);
    assert.equal(h.sent[0].join.dst_port, 443, "the offered tuple is the join");
    assert.equal(h.cache.droppedUnsentCount, 0);
});

test("CallerStackCache forget drops (and counts) a held entry without any usable join", () => {
    const h = harness();
    captureOn(h, "0xa2", 1, UNJOINABLE);
    h.cache.forget("0xa2", 1);
    assert.equal(h.sent.length, 0);
    assert.equal(h.cache.droppedUnsentCount, 1);
    assert.equal(h.cache.hasHeldEntries, false);
});

test("CallerStackCache forget of an already-sent entry sends nothing more", () => {
    const h = harness();
    captureOn(h, "0xa3", 1, { client_random: CR });
    h.cache.forget("0xa3", 1);
    assert.equal(h.sent.length, 1);
    assert.equal(h.cache.droppedUnsentCount, 0);
});
