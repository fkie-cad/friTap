// Unit tests for the Google QUICHE stream -> connection layout discovery
// (quiche_layout.ts) and the per-connection key/4-tuple resolution
// (QuicConnectionTracker.resolveLinked).
//
// Run: npm run test:agent
//
// WHY: Chrome's QUIC hooks keyed their synthetic 4-tuple by whatever `this` a
// hook got (QuicSpdyStream / its HttpDecoderVisitor / the embedded sequencer),
// so a request and its response got different made-up client ports, and the
// "server" was the last UDP connect() (Chrome's IPv6 probe). The fake objects
// below mirror the layout measured in Chrome 133 (libmonochrome_64.so, arm64):
// stream+0x80 id_, +0x88 session_, +0x90 stream_delegate_ (session+0x28);
// session+0x58 connection_; connection+0x248 and +0x1260 (self, peer); the
// connection's visitor_ back-pointer at +0x1018.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    Address, QuicheMemory, containsPointer, decodeQuicSocketAddress, discoverConnectionLayout, discoverQuicheLayout,
    discoverSessionLayout, findAddressPairOffset, readConnectionLink, readSessionLink, readStreamLink,
    streamFromHookObject, findHandshakerConnection, HANDSHAKER_SESSION_OFFSET,
} from "./quiche_layout.js";
import { QuicConnectionTracker, buildQuicMessage } from "./quic_connection_tracker.js";
import {
    QuicheLayoutState, resolveConnectionRecord, resolveStreamRecord, seedQuicheLayout, sessionConnection,
} from "./quiche_records.js";
import { installLearnedModuleCache } from "../../shared/learned_module_cache.js";
import { readQuicheLayoutHints, reportQuicheLayout } from "./quiche_layout_hints.js";

// ---- fake memory -----------------------------------------------------------

class FakeMemory implements QuicheMemory {
    readonly pointerSize = 8;
    private regions: Array<{ base: bigint; bytes: Uint8Array }> = [];
    constructor(private moduleLo: bigint, private moduleHi: bigint) {}

    region(base: bigint, size: number): Uint8Array {
        const bytes = new Uint8Array(size);
        this.regions.push({ base, bytes });
        return bytes;
    }
    private find(a: bigint): { base: bigint; bytes: Uint8Array } | null {
        for (const r of this.regions) if (a >= r.base && a < r.base + BigInt(r.bytes.length)) return r;
        return null;
    }
    writePointer(a: bigint, v: bigint): void {
        const r = this.find(a)!;
        let off = Number(a - r.base);
        for (let i = 0; i < 8; i++) { r.bytes[off++] = Number(v & 0xffn); v >>= 8n; }
    }
    writeBytes(a: bigint, data: number[]): void {
        const r = this.find(a)!;
        r.bytes.set(data, Number(a - r.base));
    }
    readPointer(a: Address): Address | null {
        const r = this.find(a);
        if (!r) return null;
        const off = Number(a - r.base);
        if (off + 8 > r.bytes.length) return null;
        let v = 0n;
        for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(r.bytes[off + i]);
        return v;
    }
    readBytes(a: Address, length: number): Uint8Array | null {
        const r = this.find(a);
        if (!r) return null;
        const off = Number(a - r.base);
        return r.bytes.slice(off, Math.min(r.bytes.length, off + length));
    }
    isModuleAddress(a: Address): boolean { return a >= this.moduleLo && a < this.moduleHi; }
}

const MOD = 0x1000000n;
const STREAM = 0x7000000n;
const SESSION = 0x7100000n;
const CONNECTION = 0x7200000n;
const DECOY = 0x7300000n;          // polymorphic object that also points at the session
const VISITOR = 0x7400000n;        // QuicSpdyStream::HttpDecoderVisitor
const CONNECTION_VTABLE = MOD + 0x5b410cn;

/** QuicSocketAddress bytes: address union[16], int family, uint16 port, pad. */
function v4Address(ip: number[], port: number, family = 0): number[] {
    const out = new Array(24).fill(0);
    ip.forEach((b, i) => { out[i] = b; });
    out.fill(0xef, 4, 16);                         // uninitialised union tail
    out[16] = family;
    out[20] = port & 0xff; out[21] = port >> 8;
    return out;
}

const SELF = v4Address([10, 0, 2, 16], 50221);
const PEER = v4Address([142, 251, 155, 119], 443);

function buildChromeLikeObjects(opts: { self?: number[]; connectionVtable?: bigint } = {}): FakeMemory {
    const mem = new FakeMemory(MOD, MOD + 0x10000000n);
    mem.region(MOD, 0x1000);
    mem.region(MOD + 0x5af000n, 0x10000);          // vtables live inside the module
    mem.region(STREAM, 0x200);
    mem.region(SESSION, 0x200);
    mem.region(CONNECTION, 0x2000);
    mem.region(DECOY, 0x400);
    mem.region(VISITOR, 0x10);

    // QuicSpdyStream
    mem.writePointer(STREAM, MOD + 0x5af388n);     // vptr
    mem.writePointer(STREAM + 0x8n, STREAM);       // sequencer_.stream_ (back-pointer)
    mem.writePointer(STREAM + 0x80n, 0x78_00000004n); // id_ = 4 (+ garbage padding)
    mem.writePointer(STREAM + 0x88n, SESSION);     // session_
    mem.writePointer(STREAM + 0x90n, SESSION + 0x28n); // stream_delegate_
    mem.writePointer(STREAM + 0xe8n, SESSION);     // flow_controller_.session_
    mem.writePointer(STREAM + 0xf0n, CONNECTION);  // flow_controller_.connection_ (negative delta)

    // QuicChromiumClientSession: several base-class vptrs, then members
    for (let i = 0n; i < 7n; i++) mem.writePointer(SESSION + i * 8n, MOD + 0x5aef6cn + i * 0x40n);
    mem.writePointer(SESSION + 0x58n, CONNECTION);
    mem.writePointer(SESSION + 0x70n, DECOY);

    // Decoy: polymorphic, points back at the session, but holds no address pair.
    mem.writePointer(DECOY, MOD + 0x5b4d10n);
    mem.writePointer(DECOY + 0x388n, SESSION);

    // QuicConnection
    mem.writePointer(CONNECTION, opts.connectionVtable ?? CONNECTION_VTABLE);
    // A plausible but unrepeated "pair" earlier in the object must be ignored.
    mem.writeBytes(CONNECTION + 0x94n, [...v4Address([255, 255, 255, 255], 4), ...v4Address([6, 0, 0, 0], 135)]);
    const self = opts.self ?? SELF;
    mem.writeBytes(CONNECTION + 0x248n, [...self, ...PEER]);   // default_path_
    mem.writePointer(CONNECTION + 0x1018n, SESSION);           // visitor_
    mem.writeBytes(CONNECTION + 0x1260n, [...self, ...PEER]);  // last received packet

    // HttpDecoderVisitor { vptr; QuicSpdyStream* stream_; }
    mem.writePointer(VISITOR, MOD + 0x5b0000n);
    mem.writePointer(VISITOR + 0x8n, STREAM);
    return mem;
}

// ---- QuicSocketAddress decoding ------------------------------------------

test("decodes an IPv4 QuicSocketAddress into the pcap encoding (host-order int, host-order port)", () => {
    const a = decodeQuicSocketAddress(Uint8Array.from(SELF), 0);
    assert.deepEqual(a, { family: "AF_INET", addr: 0x0A000210, port: 50221 });
});

test("decodes an IPv6 QuicSocketAddress as 32 uppercase hex chars", () => {
    const bytes = new Array(24).fill(0);
    [0x20, 0x01, 0x48, 0x60].forEach((b, i) => { bytes[i] = b; });
    bytes[15] = 0x88; bytes[16] = 1; bytes[20] = 0xbb; bytes[21] = 0x01;
    const a = decodeQuicSocketAddress(Uint8Array.from(bytes), 0);
    assert.deepEqual(a, { family: "AF_INET6", addr: "20014860000000000000000000000088", port: 443 });
});

test("an unspecified or invalid family is not a usable endpoint", () => {
    assert.equal(decodeQuicSocketAddress(Uint8Array.from(v4Address([0, 0, 0, 0], 0, 2)), 0)!.family, "UNSPEC");
    assert.equal(decodeQuicSocketAddress(Uint8Array.from(v4Address([1, 2, 3, 4], 5, 7)), 0), null);
});

test("the address pair is the one QuicConnection stores twice, not an earlier lookalike", () => {
    const mem = buildChromeLikeObjects();
    assert.equal(findAddressPairOffset(mem.readBytes(CONNECTION, 0x2000)!), 0x248);
});

// ---- layout discovery ------------------------------------------------------

test("learns stream->session->connection->address offsets from one live stream", () => {
    const layout = discoverQuicheLayout(buildChromeLikeObjects(), STREAM);
    assert.deepEqual(layout, {
        streamSession: 0x88, sessionConnection: 0x58, connectionAddresses: 0x248,
        connectionVtable: CONNECTION_VTABLE,
    });
});

test("a 0-RTT connection without a self address yet cannot teach the layout (retry later)", () => {
    const unspecified = v4Address([0, 0, 0, 0], 0, 2);
    assert.equal(discoverQuicheLayout(buildChromeLikeObjects({ self: unspecified }), STREAM), null);
});

test("a learned layout resolves the real stream id and the connection's real 4-tuple", () => {
    const mem = buildChromeLikeObjects();
    const link = readStreamLink(mem, discoverQuicheLayout(mem, STREAM)!, STREAM)!;
    assert.equal(link.connection, CONNECTION);
    assert.equal(link.streamId, 4);
    assert.deepEqual(link.self, { family: "AF_INET", addr: 0x0A000210, port: 50221 });
    assert.deepEqual(link.peer, { family: "AF_INET", addr: 0x8EFB9B77, port: 443 });
});

test("decoder-visitor and sequencer `this` resolve to the same stream as the stream hooks", () => {
    const mem = buildChromeLikeObjects();
    assert.equal(streamFromHookObject(mem, VISITOR, "decoder-visitor"), STREAM);
    assert.equal(streamFromHookObject(mem, STREAM + 0x8n, "sequencer"), STREAM);
    assert.equal(streamFromHookObject(mem, STREAM, "stream"), STREAM);
});

test("a connection with a different vtable is rejected instead of misread", () => {
    const good = buildChromeLikeObjects();
    const layout = discoverQuicheLayout(good, STREAM)!;
    const other = buildChromeLikeObjects({ connectionVtable: MOD + 0x123450n });
    assert.equal(readStreamLink(other, layout, STREAM), null);
});

test("session-level hooks resolve the same connection through the learned layout", () => {
    const mem = buildChromeLikeObjects();
    const link = readSessionLink(mem, discoverQuicheLayout(mem, STREAM)!, SESSION, 8)!;
    assert.equal(link.connection, CONNECTION);
    assert.equal(link.streamId, 8);
    assert.equal(link.peer!.port, 443);
});

// ---- per-connection key / 4-tuple ------------------------------------------

const SELF_EP = { family: "AF_INET", addr: 0x0A000210, port: 50221 };
const PEER_EP = { family: "AF_INET", addr: 0x8EFB9B77, port: 443 };

test("request and response of one connection share one key and the real 4-tuple", () => {
    const tracker = new QuicConnectionTracker();
    const a = tracker.resolveLinked("0x7200000", SELF_EP, PEER_EP);
    const b = tracker.resolveLinked("0x7200000", SELF_EP, PEER_EP);
    assert.equal(a.connKey, b.connKey);
    const request = buildQuicMessage(a.info, a.connKey, "QuicSpdyStream_WriteHeaders", "write");
    const response = buildQuicMessage(b.info, b.connKey, "QuicSpdyStream_OnDataFramePayload", "read");
    assert.deepEqual([request.src_addr, request.src_port, request.dst_addr, request.dst_port],
                     [0x0A000210, 50221, 0x8EFB9B77, 443]);
    assert.deepEqual([response.src_addr, response.src_port, response.dst_addr, response.dst_port],
                     [0x8EFB9B77, 443, 0x0A000210, 50221]);
});

test("a 0-RTT record gets a synthetic client that is upgraded in place, keeping the key", () => {
    const tracker = new QuicConnectionTracker();
    const early = tracker.resolveLinked("0x7200000", null, PEER_EP);
    assert.equal(early.info.peerAddr, PEER_EP.addr);
    assert.equal(early.info.localAddr, 0x0A000001);
    const later = tracker.resolveLinked("0x7200000", SELF_EP, PEER_EP);
    assert.equal(later.connKey, early.connKey);
    assert.equal(later.info.localPort, 50221);
});

test("a new connection reusing the same memory gets a new key", () => {
    const tracker = new QuicConnectionTracker();
    const first = tracker.resolveLinked("0x7200000", SELF_EP, PEER_EP);
    const reused = tracker.resolveLinked("0x7200000", { ...SELF_EP, port: 40000 },
                                         { ...PEER_EP, addr: 0x8EFA1B71 });
    assert.notEqual(reused.connKey, first.connKey);
    assert.equal(reused.connKey, "0x7200000#1");
});

test("without any address the connection keeps a deterministic synthetic tuple", () => {
    const tracker = new QuicConnectionTracker();
    const a = tracker.resolveLinked("0x7200000", null, null);
    const b = tracker.resolveLinked("0x7200000", null, null);
    assert.equal(a.connKey, "0x7200000");
    assert.deepEqual(a.info, b.info);
});

// ---- connection-level hooks (QuicConnection::OnStreamFrame / QuicSession::WriteStreamData) ----

test("a connection hook learns the address pair from the QuicConnection itself", () => {
    const mem = buildChromeLikeObjects();
    const layout = discoverConnectionLayout(mem, CONNECTION);
    assert.deepEqual(layout, { connectionAddresses: 0x248, connectionVtable: CONNECTION_VTABLE });
    const link = readConnectionLink(mem, layout!, CONNECTION, 11);
    assert.equal(link?.streamId, 11);
    assert.deepEqual(link?.peer, { family: "AF_INET", addr: 0x8EFB9B77, port: 443 });
    assert.deepEqual(link?.self, { family: "AF_INET", addr: 0x0A000210, port: 50221 });
});

test("a non-polymorphic or pair-less object does not teach a connection layout", () => {
    const mem = buildChromeLikeObjects();
    assert.equal(discoverConnectionLayout(mem, DECOY), null);
    assert.equal(discoverConnectionLayout(mem, 0n), null);
});

test("a session hook learns session->connection, skipping the back-pointing decoy", () => {
    const mem = buildChromeLikeObjects();
    const learned = discoverSessionLayout(mem, SESSION);
    assert.equal(learned?.sessionConnection, 0x58);
    assert.equal(learned?.connectionAddresses, 0x248);
});

test("session discovery without a known layout reads the connection's bytes once", () => {
    const mem = buildChromeLikeObjects();
    const readBytes = mem.readBytes.bind(mem);
    let connectionReads = 0;
    mem.readBytes = (addr: Address, length: number) => {
        if (addr === CONNECTION) connectionReads++;
        return readBytes(addr, length);
    };
    assert.equal(discoverSessionLayout(mem, SESSION)?.connectionAddresses, 0x248);
    assert.equal(connectionReads, 1);
});

test("with the connection layout known, a 0-RTT session (no repeated pair yet) still resolves", () => {
    const known = discoverConnectionLayout(buildChromeLikeObjects(), CONNECTION)!;
    const mem = buildChromeLikeObjects({ self: v4Address([0, 0, 0, 0], 0, 2) });
    assert.equal(discoverSessionLayout(mem, SESSION), null);               // pair alone: not yet
    assert.equal(discoverSessionLayout(mem, SESSION, known)?.sessionConnection, 0x58);
});

test("a connection whose vtable differs from the learned one is not read", () => {
    const layout = discoverConnectionLayout(buildChromeLikeObjects(), CONNECTION)!;
    const other = buildChromeLikeObjects({ connectionVtable: MOD + 0x5b9000n });
    assert.equal(readConnectionLink(other, layout, CONNECTION, 0), null);
});

test("containsPointer matches only aligned full-width little-endian words", () => {
    const bytes = new Uint8Array(32);
    const view = new DataView(bytes.buffer);
    view.setBigUint64(16, 0xb400007a12345678n, true);
    assert.equal(containsPointer(bytes, 0xb400007a12345678n, 8), true);
    assert.equal(containsPointer(bytes, 0x0000007a12345678n, 8), false);   // high half differs
    assert.equal(containsPointer(bytes.subarray(4), 0xb400007a12345678n, 8), false); // misaligned
    view.setUint32(4, 0x12345678, true);
    assert.equal(containsPointer(bytes, 0x12345678n, 4), true);
    assert.equal(containsPointer(bytes, 0x112345678n, 4), false);         // wider than a pointer
});

// ---- TlsClientHandshaker -> connection (CryptoConnect) ------------------------

const HANDSHAKER = 0x7500000n;
const HS_LINK = { sessionConnection: 0x58, connectionVtable: CONNECTION_VTABLE };

/** handshaker -> session (at `sessionSlot`) -> connection (session+0x58) with `vtable`. */
function handshakerFixture(sessionSlot: number, vtable: bigint = CONNECTION_VTABLE): FakeMemory {
    const mem = new FakeMemory(MOD, MOD + 0x1000000n);
    mem.region(HANDSHAKER, 0x200);
    mem.region(SESSION, 0x200);
    mem.region(CONNECTION, 0x100);
    mem.writePointer(HANDSHAKER, MOD + 0x100n);
    mem.writePointer(HANDSHAKER + BigInt(sessionSlot), SESSION);
    mem.writePointer(SESSION + 0x58n, CONNECTION);
    mem.writePointer(CONNECTION, vtable);
    return mem;
}

test("a handshaker's session_ at +0x108 leads to its connection", () => {
    const mem = handshakerFixture(HANDSHAKER_SESSION_OFFSET);
    assert.deepEqual(findHandshakerConnection(mem, HANDSHAKER, HS_LINK),
                     { handshakerSession: 0x108, connection: CONNECTION });
});

test("a handshaker with session_ elsewhere is found by the slot scan", () => {
    const mem = handshakerFixture(0x110);
    assert.deepEqual(findHandshakerConnection(mem, HANDSHAKER, HS_LINK),
                     { handshakerSession: 0x110, connection: CONNECTION });
    // A cached offset is tried first.
    assert.deepEqual(findHandshakerConnection(mem, HANDSHAKER, HS_LINK, 0x110),
                     { handshakerSession: 0x110, connection: CONNECTION });
});

test("a connection with another vtable, or a null handshaker, resolves to nothing", () => {
    const mem = handshakerFixture(HANDSHAKER_SESSION_OFFSET, MOD + 0x999n);
    assert.equal(findHandshakerConnection(mem, HANDSHAKER, HS_LINK), null);
    assert.equal(findHandshakerConnection(mem, 0n, HS_LINK), null);
});

// ---- cross-run layout hints (seeded, validated live) -----------------------------

const CACHE_KEY = "b1d0|268435456|arm64";
const CRONET_MODULE: any = { name: "/data/app/lib/arm64/libcronet.so", base: { toString: () => "0x" + MOD.toString(16) },
                             size: 0x10000000 };
const GOOD_HINTS = {
    "quiche.layout.streamSession": 0x88, "quiche.layout.sessionConnection": 0x58,
    "quiche.layout.connectionAddresses": 0x248, "quiche.layout.connectionVtableRva": Number(CONNECTION_VTABLE - MOD),
};

/** Installs a learned cache holding `layout` for libcronet.so; returns what it emits (flushed). */
function withLayoutCache(layout: Record<string, number> | null, run: (emitted: () => any[]) => void): void {
    const sent: any[] = [];
    const flushes: (() => void)[] = [];
    const raw = layout ? { [CACHE_KEY]: { module: "libcronet.so", layout } } : {};
    installLearnedModuleCache(raw, {
        identify: () => ({ buildId: "b1d0", size: 0x10000000, arch: "arm64" }),
        emit: (p) => sent.push(p), schedule: (flush) => flushes.push(flush), arch: () => "arm64",
    });
    try {
        run(() => { flushes.splice(0).forEach((f) => f()); return sent; });
    } finally {
        installLearnedModuleCache({});
    }
}

function seededState(mem: QuicheMemory): QuicheLayoutState {
    const state: QuicheLayoutState = { moduleName: "libcronet.so", mem, layout: null, attempts: 0, triedStreams: new Set(),
                                       connLayout: null, sessionConnection: null, connAttempts: 0 };
    seedQuicheLayout(state, CRONET_MODULE);
    return state;
}

const layoutReports = (sent: any[]) => sent.filter((m) => m.layout).map((m) => m.layout);

test("a seeded layout resolves the first stream without discovery and is not reported back", () => {
    withLayoutCache(GOOD_HINTS, (emitted) => {
        const state = seededState(buildChromeLikeObjects());
        assert.equal(state.layout?.streamSession, 0x88);
        const record = resolveStreamRecord(state, STREAM, "read", "read");
        assert.equal(record?.connection, CONNECTION);
        assert.equal(record?.streamId, 4);
        assert.equal(state.attempts, 0);
        assert.deepEqual([...state.seeded!.keys()], []);                      // every hint validated
        assert.equal(emitted().filter((m) => m.cache_hit).length, 1);
        assert.deepEqual(layoutReports(emitted()), []);
    });
});

test("a bad streamSession hint is dropped on its second failure and discovery learns (and reports) the real one", () => {
    withLayoutCache({ ...GOOD_HINTS, "quiche.layout.streamSession": 0xe8 }, (emitted) => {
        const state = seededState(buildChromeLikeObjects());
        resolveStreamRecord(state, STREAM, "read", "read");
        assert.equal(state.layout?.streamSession, 0xe8, "one failed check is tolerated");
        assert.equal(state.attempts, 0);
        const record = resolveStreamRecord(state, STREAM, "read", "read");
        assert.equal(record?.streamId, 4);
        assert.equal(state.attempts, 1);
        assert.equal(state.layout?.streamSession, 0x88);
        assert.deepEqual(layoutReports(emitted()), [{ "quiche.layout.streamSession": 0x88 }]);
    });
});

test("a bad connectionAddresses hint is rejected on the second connection hook and rediscovered", () => {
    withLayoutCache({ ...GOOD_HINTS, "quiche.layout.connectionAddresses": 0x400 }, (emitted) => {
        const state = seededState(buildChromeLikeObjects());
        resolveConnectionRecord(state, CONNECTION, 3, "read", "read");
        assert.equal(state.connLayout?.connectionAddresses, 0x400, "one failed check is tolerated");
        const record = resolveConnectionRecord(state, CONNECTION, 3, "read", "read");
        assert.notEqual(record, null);
        assert.equal(state.connLayout?.connectionAddresses, 0x248);
        assert.equal(state.layout, null);                              // the seeded full layout embedded it
        assert.deepEqual(layoutReports(emitted()), [{ "quiche.layout.connectionAddresses": 0x248 }]);
    });
});

test("a bad sessionConnection hint is rejected on the second session and rediscovered", () => {
    withLayoutCache({ ...GOOD_HINTS, "quiche.layout.sessionConnection": 0x70 }, (emitted) => {  // the decoy slot
        const state = seededState(buildChromeLikeObjects());
        assert.equal(sessionConnection(state, SESSION), DECOY, "one failed check is tolerated");
        assert.equal(sessionConnection(state, SESSION), CONNECTION);
        assert.equal(state.sessionConnection, 0x58);
        assert.equal(state.layout, null);                              // the seeded full layout embedded it
        assert.deepEqual([...state.seeded!.keys()], ["connection"]);          // streamSession dropped with it
        assert.deepEqual(layoutReports(emitted()), [{ "quiche.layout.sessionConnection": 0x58 }]);
    });
});

test("a seeded connection hint survives one hook on a torn-down connection, then is confirmed for good", () => {
    withLayoutCache(GOOD_HINTS, (emitted) => {
        const mem = buildChromeLikeObjects();
        const tornDown = 0x7600000n;
        mem.region(tornDown, 0x400);                                    // zeroed: no vtable, no addresses
        const state = seededState(mem);
        assert.equal(resolveConnectionRecord(state, tornDown, 3, "read", "read"), null);
        assert.equal(state.connLayout?.connectionAddresses, 0x248, "a single failed check keeps connLayout");
        assert.ok(state.seeded!.has("connection"));
        assert.notEqual(resolveConnectionRecord(state, CONNECTION, 3, "read", "read"), null);
        assert.equal(state.seeded!.has("connection"), false, "confirmed by the live connection");
        resolveConnectionRecord(state, tornDown, 3, "read", "read");
        resolveConnectionRecord(state, tornDown, 3, "read", "read");
        assert.equal(state.connLayout?.connectionAddresses, 0x248, "a confirmed seed is not rechecked");
        assert.equal(state.connAttempts, 0);
        assert.deepEqual(layoutReports(emitted()), []);
    });
});

test("without hints a discovered layout is reported once, vtable as a module RVA", () => {
    withLayoutCache(null, (emitted) => {
        const state = seededState(buildChromeLikeObjects());
        resolveStreamRecord(state, STREAM, "read", "read");
        resolveStreamRecord(state, STREAM, "write", "write");
        assert.deepEqual(layoutReports(emitted()), [GOOD_HINTS]);
    });
});

test("a vtable hint outside the module is not seeded", () => {
    withLayoutCache(GOOD_HINTS, () => {
        const mem = buildChromeLikeObjects();
        const outside = { ...mem, pointerSize: 8, readPointer: mem.readPointer.bind(mem), readBytes: mem.readBytes.bind(mem),
                          isModuleAddress: () => false };
        const state = seededState(outside);
        assert.equal(state.connLayout, null);
        assert.equal(state.layout, null);
        assert.equal(state.sessionConnection, 0x58);
    });
});

// WHY: a hint discarded before seeding must be rejected in the cache too, or
// the value discovered later is never reported and the stale one sticks.
test("a discarded stale vtable hint does not block reporting the discovered value", () => {
    const stale = { ...GOOD_HINTS, "quiche.layout.connectionVtableRva": 0x20000000 };    // past the module
    withLayoutCache(stale, (emitted) => {
        const state = seededState(buildChromeLikeObjects());
        assert.equal(state.connLayout, null);
        assert.equal(state.layout, null);
        resolveStreamRecord(state, STREAM, "read", "read");
        assert.deepEqual(layoutReports(emitted()), [{
            "quiche.layout.connectionVtableRva": Number(CONNECTION_VTABLE - MOD),
        }]);
    });
});

test("a vtable RVA past Module.size (macOS __TEXT-only size) is reported and seeded", () => {
    const textOnly: any = { ...CRONET_MODULE, size: 0x100000 };
    const rva = Number(CONNECTION_VTABLE - MOD);
    assert.ok(rva > textOnly.size);
    withLayoutCache(null, (emitted) => {
        reportQuicheLayout(textOnly, { connection: { connectionAddresses: 0x248, connectionVtable: CONNECTION_VTABLE } });
        assert.deepEqual(layoutReports(emitted()), [{
            "quiche.layout.connectionAddresses": 0x248, "quiche.layout.connectionVtableRva": rva,
        }]);
    });
    withLayoutCache(GOOD_HINTS, () => {
        const hints = readQuicheLayoutHints(textOnly, () => true);
        assert.equal(hints.connection?.connectionVtable, CONNECTION_VTABLE);
    });
});

