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
    streamFromHookObject,
} from "./quiche_layout.js";
import { QuicConnectionTracker, buildQuicMessage } from "./quic_connection_tracker.js";

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
