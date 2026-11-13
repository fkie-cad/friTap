// Unit tests for the JS side of shared/native_socket_observer.ts (cursors, drains, consumers)
// against a JS model of the C ring buffers. The C itself is exercised in a live Frida process.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    nativeSocketObserver, resetNativeSocketObserverForTests, CLOSED_FD_CONSUMER,
} from "./native_socket_observer.js";
import { getPortsAndAddresses, isUnwantedFd } from "./shared_functions.js";
import { unwantedFDs } from "./shared_structures.js";
import { QuicConnectionTracker } from "../quic/shared/quic_connection_tracker.js";

const G = globalThis as any;

/** A NativePointer into a JS ArrayBuffer (little-endian), enough for the observer's reads. */
class FakeBlock {
    constructor(readonly bytes: Uint8Array, readonly offset = 0) { }
    private get view(): DataView { return new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset); }
    add(n: number): FakeBlock { return new FakeBlock(this.bytes, this.offset + Number(n)); }
    isNull(): boolean { return false; }
    readU32(): number { return this.view.getUint32(0, true); }
    writeU32(v: number): void { this.view.setUint32(0, v >>> 0, true); }
    readU8(): number { return this.view.getUint8(0); }
    readByteArray(n: number): ArrayBuffer {
        const start = this.bytes.byteOffset + this.offset;
        return this.bytes.buffer.slice(start, start + n);
    }
}

const CLOSED_RING = 4096;
const UDP_RING = 64;
const SLOT = 32;

/** JS model of the C rings; head/tail cursors live in the state block like FtState's head. */
class FakeNativeRings {
    closed: number[] = [];
    udp: Uint8Array[] = [];
    nativeCalls = 0;
    constructor(readonly state: FakeBlock) { }
    private u32(offset: number): FakeBlock { return this.state.add(offset); }
    get closedHead(): number { return this.u32(0).readU32(); }
    tail(consumer: number): number { return this.u32(4 + 4 * consumer).readU32(); }

    close(fd: number): void {
        this.closed[this.closedHead % CLOSED_RING] = fd;
        this.u32(0).writeU32(this.closedHead + 1);
    }
    udpConnect(sockaddr: number[]): void {
        const head = this.u32(12).readU32();
        this.udp[head % UDP_RING] = Uint8Array.from(sockaddr);
        this.u32(12).writeU32(head + 1);
    }
    skip(consumer: number): void { this.u32(4 + 4 * consumer).writeU32(this.closedHead); }
    udpSkip(): void { this.u32(16).writeU32(this.u32(12).readU32()); }
    drainClosed(consumer: number, out: FakeBlock): number {
        this.nativeCalls++;
        const pending = this.closedHead - this.tail(consumer);
        this.skip(consumer);
        if (pending > CLOSED_RING) return -1;
        for (let n = 0; n < pending; n++) {
            new DataView(out.bytes.buffer).setInt32(n * 4, this.closed[(this.closedHead - pending + n) % CLOSED_RING], true);
        }
        return pending;
    }
    drainUdp(out: FakeBlock): number {
        const head = this.u32(12).readU32();
        const pending = Math.min(head - this.u32(16).readU32(), UDP_RING);
        for (let n = 0; n < pending; n++) out.bytes.set(this.udp[(head - pending + n) % UDP_RING], n * SLOT);
        this.u32(16).writeU32(head);
        return pending;
    }
}

let rings: FakeNativeRings;

function installFakeNativeWorld(): void {
    G.Memory.alloc = (size: number) => new FakeBlock(new Uint8Array(Number(size)));
    G.Module.findGlobalExportByName = (name: string) => ({ name, isNull: () => false, toString: () => `0x${name}` });
    G.Interceptor.attach = () => ({ detach: () => { } });
    G.CModule = function (_source: string, symbols: any) {
        rings = new FakeNativeRings(symbols.ft_state);
        return new Proxy({}, { get: (_t, name) => ({ name, isNull: () => false }) });
    };
    G.NativeFunction = function (target: any) {
        switch (target?.name) {
            case "ft_closed_skip": return (consumer: number) => rings.skip(consumer);
            case "ft_drain_closed": return (consumer: number, out: FakeBlock) => rings.drainClosed(consumer, out);
            case "ft_udp_skip": return () => rings.udpSkip();
            case "ft_drain_udp_peers": return (out: FakeBlock) => rings.drainUdp(out);
            default: return () => 0;
        }
    };
    resetNativeSocketObserverForTests();
}

installFakeNativeWorld();

test("each closed-fd consumer drains the ring through its own cursor", () => {
    const observer = nativeSocketObserver()!;
    assert.ok(observer.armClosedFdConsumer(CLOSED_FD_CONSUMER.socketFdTracker));
    assert.ok(observer.armClosedFdConsumer(CLOSED_FD_CONSUMER.unwantedFds));
    rings.close(5);
    rings.close(6);
    assert.deepEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker), [5, 6]);
    rings.close(7);
    assert.deepEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.unwantedFds), [5, 6, 7]);
    assert.deepEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker), [7]);
});

test("an empty drain is decided from the cursors without a native call", () => {
    const observer = nativeSocketObserver()!;
    observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker);
    const calls = rings.nativeCalls;
    assert.deepEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker), []);
    assert.equal(rings.nativeCalls, calls);
});

test("an overrun consumer gets \"lost\"; the other consumer is unaffected", () => {
    const observer = nativeSocketObserver()!;
    observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker);
    for (let fd = 0; fd < CLOSED_RING + 1; fd++) {
        rings.close(fd);
        if (fd % 1000 === 0) observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker);
    }
    assert.equal(observer.drainClosedFds(CLOSED_FD_CONSUMER.unwantedFds), "lost");
    assert.notEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.socketFdTracker), "lost");
    assert.deepEqual(observer.drainClosedFds(CLOSED_FD_CONSUMER.unwantedFds), []);
});

test("unwanted-fd eviction drains closed fds at getPortsAndAddresses and isUnwantedFd", () => {
    assert.equal(getPortsAndAddresses(-1, true, {}, false), null);    // arms the eviction consumer
    unwantedFDs.add(40);
    unwantedFDs.add(41);
    assert.equal(isUnwantedFd(40), true);
    rings.close(40);
    assert.equal(isUnwantedFd(40), false, "close(40) evicts the blacklisted fd");
    assert.equal(isUnwantedFd(41), true);
    for (let i = 0; i < CLOSED_RING + 1; i++) rings.close(1000);
    assert.equal(isUnwantedFd(41), false, "an overrun clears the blacklist");
    unwantedFDs.clear();
});

test("UDP connect() peers drain oldest first, at most one ring's worth", () => {
    const observer = nativeSocketObserver()!;
    assert.ok(observer.armUdpPeerRecording());
    assert.deepEqual(observer.drainUdpPeers(), []);
    for (let port = 1; port <= UDP_RING + 2; port++) rings.udpConnect([2, 0, 0, port]);
    const peers = observer.drainUdpPeers();
    assert.equal(peers.length, UDP_RING);
    assert.equal((peers[0] as any).add(3).readU8(), 3, "the two oldest were overwritten");
    assert.equal((peers[UDP_RING - 1] as any).add(3).readU8(), UDP_RING + 2);
    assert.deepEqual(observer.drainUdpPeers(), []);
});

test("the QUIC tracker pulls queued peers before it synthesizes a 4-tuple", () => {
    const tracker = new QuicConnectionTracker();
    let feeds = 0;
    tracker.setObservedPeerFeed(() => {
        feeds++;
        tracker.setObservedPeer({ addr: 0x5db8d70e, port: 443, family: "AF_INET" });
    });
    const info = tracker.synthesizeInfo("0x1234");
    assert.equal(feeds, 1);
    assert.equal(info.peerAddr, 0x5db8d70e);
    assert.equal(info.peerPort, 443);
});
