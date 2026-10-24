// Unit tests for the ClientHello client_random parser used on the LibreSSL
// stripped-static path (client_random is recovered from the plaintext
// ClientHello written to send()).
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

import { extractClientRandomFromHandshake } from "./clienthello_random.js";

// Minimal NativePointer over a byte buffer (only the ops the parser uses).
function fakePtr(bytes: number[], base = 0): any {
    return {
        _b: bytes, _o: base,
        isNull() { return false; },
        readU8() { return this._b[this._o] & 0xff; },
        add(n: number) { return fakePtr(this._b, this._o + n); },
        readByteArray(len: number) {
            if (this._o + len > this._b.length) return null;
            return new Uint8Array(this._b.slice(this._o, this._o + len)).buffer;
        },
    };
}

const RANDOM = Array.from({ length: 32 }, (_, i) => i + 1); // 01 02 ... 20
const RANDOM_HEX = RANDOM.map((b) => b.toString(16).padStart(2, "0")).join("");

test("parses client_random from a TLS record ClientHello (0x16 framing)", () => {
    // record hdr: 16 03 01 LL LL | hs: 01 LLL LLL LLL | ver: 03 03 | random[32]
    const buf = [0x16, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x03, ...RANDOM];
    const cr = extractClientRandomFromHandshake(fakePtr(buf), buf.length);
    assert.equal(cr, RANDOM_HEX);
});

test("parses client_random from a bare handshake-message ClientHello (0x01 framing)", () => {
    // hs: 01 LLL LLL LLL | ver: 03 03 | random[32]
    const buf = [0x01, 0x00, 0x00, 0x00, 0x03, 0x03, ...RANDOM];
    const cr = extractClientRandomFromHandshake(fakePtr(buf), buf.length);
    assert.equal(cr, RANDOM_HEX);
});

test("rejects non-ClientHello / application data / short buffers", () => {
    // application data record
    assert.equal(extractClientRandomFromHandshake(fakePtr([0x17, 0x03, 0x03, 0, 0, ...RANDOM]), 37), null);
    // handshake record but not ClientHello (ServerHello = 0x02)
    const sh = [0x16, 0x03, 0x03, 0x00, 0x00, 0x02, 0, 0, 0, 0x03, 0x03, ...RANDOM];
    assert.equal(extractClientRandomFromHandshake(fakePtr(sh), sh.length), null);
    // too short
    assert.equal(extractClientRandomFromHandshake(fakePtr([0x16, 0x03, 0x01]), 3), null);
});
