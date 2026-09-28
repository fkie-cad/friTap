// Unit tests for the Tier E ConnectionSocket peer-address decoder
// (readConnectionEndpoint / formatIPv4 / formatIPv6 in endpoint.ts).
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/engines/mtproto/endpoint.test.ts)
//
// endpoint.ts is pure (no Frida globals), so these need no Frida runtime: each
// NativePointer is faked by a Buffer, matching agent/shared/sockaddr.test.ts.
// The offsets under test are the LIVE-VALIDATED libtmessages.49 layout:
//   sockaddr_in  @0x90 (144): family u16 host-order @+0, port u16 BE @+2, addr 4B @+4
//   sockaddr_in6 @0xA0 (160): family u16 host-order @+0, port u16 BE @+2, addr 16B @+8

import { test } from "node:test";
import assert from "node:assert/strict";
import { readConnectionEndpoint, formatIPv4, formatIPv6, NO_ENDPOINT } from "./endpoint.js";

// The profile's struct_offsets.Connection endpoint keys.
const OFF = { endpoint_sockaddr_in: 144, endpoint_sockaddr_in6: 160 };

// Buffer-backed fake NativePointer: readU16 is host-endian (LE here, as on the
// arm64 target), readByteArray throws on a short read like Frida does.
function fakePtr(buf: Buffer, off = 0): any {
    return {
        add: (n: number) => fakePtr(buf, off + n),
        readU16: () => buf.readUInt16LE(off),
        readByteArray: (len: number) => {
            if (off + len > buf.length) throw new Error("short read");
            const out = new Uint8Array(len);
            for (let i = 0; i < len; i++) out[i] = buf[off + i];
            return out.buffer;
        },
    };
}

test("formatIPv4 renders a dotted quad", () => {
    assert.equal(formatIPv4(new Uint8Array([149, 154, 167, 41])), "149.154.167.41");
});

test("formatIPv6 renders colon-hex, all eight groups", () => {
    const a = new Uint8Array([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    assert.equal(formatIPv6(a), "2001:db8:0:0:0:0:0:1");
});

test("AF_INET at 0x90 decodes to dotted quad + big-endian port", () => {
    const buf = Buffer.alloc(0x100, 0);
    buf.writeUInt16LE(2, 0x90);          // sin_family = AF_INET (host-order)
    buf[0x92] = 0x14; buf[0x93] = 0x66;  // sin_port = 0x1466 = 5222 (network/BE order)
    buf[0x94] = 149; buf[0x95] = 154; buf[0x96] = 167; buf[0x97] = 41; // 149.154.167.41
    assert.equal(readConnectionEndpoint(fakePtr(buf), OFF), "149.154.167.41:5222");
});

test("AF_INET6 at 0xA0 decodes to bracketed colon-hex + big-endian port", () => {
    const buf = Buffer.alloc(0x100, 0);
    // 0x90 family stays 0 so the IPv4 branch falls through to the IPv6 branch.
    buf.writeUInt16LE(10, 0xA0);         // sin6_family = AF_INET6 (host-order)
    buf[0xA2] = 0x01; buf[0xA3] = 0xBB;  // sin6_port = 0x01BB = 443 (BE)
    const addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    for (let i = 0; i < 16; i++) buf[0xA8 + i] = addr[i];
    assert.equal(readConnectionEndpoint(fakePtr(buf), OFF), "[2001:db8:0:0:0:0:0:1]:443");
});

test("unknown family falls back to '-'", () => {
    const buf = Buffer.alloc(0x100, 0);  // both family fields are 0 (neither AF_INET nor AF_INET6)
    assert.equal(readConnectionEndpoint(fakePtr(buf), OFF), NO_ENDPOINT);
});

test("a short/faulting read never throws and yields '-'", () => {
    // Buffer ends inside the sockaddr_in addr field: family reads AF_INET but the
    // addr read faults, so the decoder must degrade to '-' rather than throw.
    const buf = Buffer.alloc(0x96, 0);
    buf.writeUInt16LE(2, 0x90);
    buf[0x92] = 0x14; buf[0x93] = 0x66;
    assert.equal(readConnectionEndpoint(fakePtr(buf), OFF), NO_ENDPOINT);
});
