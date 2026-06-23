// Unit tests for the darwin-aware sockaddr decoders in shared_functions.ts
// (readSockaddrFamily / decodeSockaddr).
//
// Run: npm run test:agent   (node --import tsx --test agent/shared/*.test.ts)
//
// These need no Frida runtime: we stub the minimal Frida global surface so the
// shared_functions.js import graph loads under Node, and back each NativePointer
// with a Buffer. The suite exists because the BSD-sockaddr layout footgun on
// macOS/iOS (1-byte sa_len@0, sa_family@1, AF_INET6=30) silently dropped every
// TLS/QUIC peer address on darwin until it was read platform-aware.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines the Frida globals BEFORE sockaddr.js loads.
// Process.platform is read at call time inside readSockaddrFamily, so tests flip
// it per case via setPlatform().
import { setPlatform } from "./frida-test-stubs.js";
import { readSockaddrFamily, decodeSockaddr } from "./sockaddr.js";

// --- Buffer-backed fake NativePointer ----------------------------------------
function fakePtr(buf: Buffer, off = 0): any {
    return {
        isNull: () => false,
        add: (n: number) => fakePtr(buf, off + n),
        readU8: () => buf.readUInt8(off),
        readU16: () => buf.readUInt16LE(off),   // Frida readU16 is host-endian (LE here)
        readU32: () => buf.readUInt32LE(off),
    };
}
function fakeNull(): any {
    return { isNull: () => true, add: () => fakeNull(), readU8: () => 0, readU16: () => 0, readU32: () => 0 };
}
const sa = (bytes: number[]) => fakePtr(Buffer.from(bytes));

// AF_INET sockaddr_in for 1.2.3.4:443 in the two on-wire layouts.
// port 443 = 0x01BB (network order: 0x01, 0xBB); addr bytes 1.2.3.4.
const LINUX_V4 = [0x02, 0x00, 0x01, 0xBB, 1, 2, 3, 4];           // family@0 = 2 (LE)
const BSD_V4   = [16,   0x02, 0x01, 0xBB, 1, 2, 3, 4];           // sa_len@0=16, family@1=2
const V4_HOST_INT = ((1 << 24) | (2 << 16) | (3 << 8) | 4) >>> 0;

// AF_INET6 sockaddr_in6 for 2001:db8::1 :443. family + port + 4-byte flowinfo + 16-byte addr.
const V6_ADDR = [0x20, 0x01, 0x0d, 0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,0x01];
const V6_HEX  = "20010DB8000000000000000000000001";
const LINUX_V6 = [0x0A, 0x00, 0x01, 0xBB, 0,0,0,0, ...V6_ADDR];  // family@0 = 10 (LE)
const BSD_V6   = [28,   0x1E, 0x01, 0xBB, 0,0,0,0, ...V6_ADDR];  // sa_len@0=28, family@1=30
const PRNET_V6 = [0x1E, 0x00, 0x01, 0xBB, 0,0,0,0, ...V6_ADDR];  // family@0 = 30 (LE), PRNetAddr

// IPv4-mapped IPv6 (::ffff:1.2.3.4) — must fold to AF_INET.
const V4MAPPED_ADDR = [0,0,0,0, 0,0,0,0, 0,0,0xFF,0xFF, 1,2,3,4];
const LINUX_V4MAPPED = [0x0A, 0x00, 0x01, 0xBB, 0,0,0,0, ...V4MAPPED_ADDR];

const AF_INET = 2, AF_INET6 = 10;

test("readSockaddrFamily: linux/PRNetAddr family@0 (bsdSockaddr=false)", () => {
    setPlatform("linux");
    assert.equal(readSockaddrFamily(sa(LINUX_V4), false), AF_INET);
    assert.equal(readSockaddrFamily(sa(LINUX_V6), false), AF_INET6);
});

test("readSockaddrFamily: darwin BSD sockaddr (bsdSockaddr=true) reads family@1, maps 30->10", () => {
    setPlatform("darwin");
    assert.equal(readSockaddrFamily(sa(BSD_V4), true), AF_INET);
    assert.equal(readSockaddrFamily(sa(BSD_V6), true), AF_INET6);
});

test("readSockaddrFamily: darwin PRNetAddr (bsdSockaddr=false) normalizes AF_INET6 30->10", () => {
    setPlatform("darwin");
    assert.equal(readSockaddrFamily(sa(PRNET_V6), false), AF_INET6);   // 30 -> 10
    assert.equal(readSockaddrFamily(sa(LINUX_V4), false), AF_INET);    // 2 unchanged
});

test("decodeSockaddr: darwin BSD sockaddr (bsdSockaddr=true) decodes v4 + v6", () => {
    setPlatform("darwin");
    const v4 = decodeSockaddr(sa(BSD_V4), false, undefined, true);
    assert.deepEqual(v4, { family: "AF_INET", port: 443, addr: V4_HOST_INT });
    const v6 = decodeSockaddr(sa(BSD_V6), false, undefined, true);
    assert.deepEqual(v6, { family: "AF_INET6", port: 443, addr: V6_HEX });
});

test("decodeSockaddr: darwin PRNetAddr v6 (family@0=30, bsdSockaddr=false) -> AF_INET6", () => {
    setPlatform("darwin");
    const v6 = decodeSockaddr(sa(PRNET_V6), false, undefined, false);
    assert.deepEqual(v6, { family: "AF_INET6", port: 443, addr: V6_HEX });
});

test("decodeSockaddr: v4-mapped IPv6 folds to AF_INET", () => {
    setPlatform("linux");
    const d = decodeSockaddr(sa(LINUX_V4MAPPED), false, undefined, false);
    assert.deepEqual(d, { family: "AF_INET", port: 443, addr: V4_HOST_INT });
});

test("decodeSockaddr: linux regression unchanged", () => {
    setPlatform("linux");
    assert.deepEqual(decodeSockaddr(sa(LINUX_V4), false, undefined, false),
        { family: "AF_INET", port: 443, addr: V4_HOST_INT });
    assert.deepEqual(decodeSockaddr(sa(LINUX_V6), false, undefined, false),
        { family: "AF_INET6", port: 443, addr: V6_HEX });
});

test("decodeSockaddr: null pointer and unsupported family return null", () => {
    setPlatform("linux");
    assert.equal(decodeSockaddr(fakeNull(), false, undefined, false), null);
    assert.equal(decodeSockaddr(sa([0x01, 0x00, 0, 0, 0, 0, 0, 0]), false, undefined, false), null); // AF_UNIX
});
