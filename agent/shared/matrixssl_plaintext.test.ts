// Unit tests for shared/matrixssl_plaintext.ts (MatrixSSL plaintext capture).
//
// Run: npm run test:agent
//
// WHY: the hooks read `unsigned char **` out-params as if they were the buffer, and used
// the `uint32 *ptlen` POINTER as the byte count. Plaintext is (*ptbuf, *ptlen), present
// only when the call returned MATRIXSSL_APP_DATA, and a write commits only the `len`
// bytes passed to matrixSslEncodeWritebuf.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    MATRIXSSL_APP_DATA, receivedPlaintext, encodedLength, hookMatrixSslReads, hookMatrixSslWrites,
} from "./matrixssl_plaintext.js";

const G = globalThis as any;

function addr(name: string): any { return { name, isNull: () => false, toString: () => `0x${name}` }; }
function int(n: number): any { return { toInt32: () => n, toUInt32: () => n >>> 0 }; }
function plaintextBuffer(text: string): any {
    const buf = Buffer.from(text);
    return { isNull: () => false, readByteArray: (n: number) => buf.subarray(0, Number(n)) };
}
/** `T **` / `uint32 *` out-param slot, filled by the "library" during the call. */
function slot(): any {
    const s: any = { value: null, isNull: () => false };
    s.readPointer = () => s.value;
    s.readU32 = () => s.value;
    return s;
}

const listeners = new Map<string, any>();
G.Interceptor.attach = (target: any, callbacks: any) => {
    listeners.set(String(target), callbacks);
    return { detach: () => { } };
};

test("receivedPlaintext: only MATRIXSSL_APP_DATA yields (*ptbuf, *ptlen)", () => {
    const ptbuf = slot(), ptlen = slot();
    ptbuf.value = plaintextBuffer("HTTP/1.1 200 OK");
    ptlen.value = 8;
    assert.equal(Buffer.from(receivedPlaintext(MATRIXSSL_APP_DATA, ptbuf, ptlen)!).toString(), "HTTP/1.1");
    for (const status of [0, 1, 2, 3, 5, 6, 7, -1]) {
        assert.equal(receivedPlaintext(status, ptbuf, ptlen), null, `status ${status}`);
    }
    ptlen.value = 0;
    assert.equal(receivedPlaintext(MATRIXSSL_APP_DATA, ptbuf, ptlen), null);
});

test("encodedLength: the committed len, clamped to the buffer handed out", () => {
    assert.equal(encodedLength(10, 16384), 10);
    assert.equal(encodedLength(20000, 16384), 16384);
    assert.equal(encodedLength(0, 16384), 0);
    assert.equal(encodedLength(10, -1), 0);
});

test("reads: ReceivedData and ProcessedData emit the dereferenced plaintext", () => {
    const emitted: Array<[string, string]> = [];
    hookMatrixSslReads(addr("recv"), addr("processed"), (_ssl, data, fn) => emitted.push([fn, Buffer.from(data).toString()]));

    const ctx: any = {}, ptbuf = slot(), ptlen = slot();
    listeners.get("0xrecv").onEnter.call(ctx, [addr("ssl"), int(1500), ptbuf, ptlen]);
    ptbuf.value = plaintextBuffer("first record");
    ptlen.value = 5;
    listeners.get("0xrecv").onLeave.call(ctx, int(MATRIXSSL_APP_DATA));

    const hs: any = {};
    listeners.get("0xrecv").onEnter.call(hs, [addr("ssl"), int(100), slot(), slot()]);
    listeners.get("0xrecv").onLeave.call(hs, int(1));          // REQUEST_SEND: handshake, no app data

    const next: any = {}, ptbuf2 = slot(), ptlen2 = slot();
    listeners.get("0xprocessed").onEnter.call(next, [addr("ssl"), ptbuf2, ptlen2]);
    ptbuf2.value = plaintextBuffer("second");
    ptlen2.value = 6;
    listeners.get("0xprocessed").onLeave.call(next, int(MATRIXSSL_APP_DATA));

    assert.deepEqual(emitted, [["matrixSslReceivedData", "first"], ["matrixSslProcessedData", "second"]]);
});

test("writes: GetWritebuf's *buf is read with EncodeWritebuf's len", () => {
    const emitted: string[] = [];
    hookMatrixSslWrites(addr("getbuf"), addr("encode"), (_ssl, data) => emitted.push(Buffer.from(data).toString()));

    const ctx: any = {}, bufOut = slot();
    listeners.get("0xgetbuf").onEnter.call(ctx, [addr("ssl"), bufOut, int(16)]);
    bufOut.value = plaintextBuffer("GET / HTTP/1.1\r\n<stale tail>");
    listeners.get("0xgetbuf").onLeave.call(ctx, int(16384));   // bytes AVAILABLE, not written
    listeners.get("0xencode").onEnter.call({}, [addr("ssl"), int(16)]);

    // An EncodeWritebuf without a preceding GetWritebuf emits nothing.
    listeners.get("0xencode").onEnter.call({}, [addr("ssl"), int(16)]);
    assert.deepEqual(emitted, ["GET / HTTP/1.1\r\n"]);
});

test("writes: a failed GetWritebuf leaves nothing pending", () => {
    const emitted: string[] = [];
    hookMatrixSslWrites(addr("getbuf2"), addr("encode2"), (_ssl, data) => emitted.push(Buffer.from(data).toString()));
    const ctx: any = {};
    listeners.get("0xgetbuf2").onEnter.call(ctx, [addr("ssl"), slot(), int(16)]);
    listeners.get("0xgetbuf2").onLeave.call(ctx, int(-1));
    listeners.get("0xencode2").onEnter.call({}, [addr("ssl"), int(16)]);
    assert.deepEqual(emitted, []);
});
