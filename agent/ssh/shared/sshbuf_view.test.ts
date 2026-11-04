// Unit tests for ssh/shared/sshbuf_view.ts (crash-safe OpenSSH sshbuf / struct kex reads).
//
// WHY: the SSH hooks used to call the target's sshbuf_len() on probe candidates; OpenSSH's
// sshbuf_check_sanity() raise(SIGSEGV)s on a non-sshbuf, killing ssh right after start.
// These tests pin the replacement: sanity-checked struct reads that reject instead of abort.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import {
    frameSshMessage, isKexinitBody, kexinitCookie, probeKexLayout, readConnectionFd, readShortCString, readSshbuf,
    sharedSecretBytes,
    SSHBUF_SIZE_MAX,
} from "./sshbuf_view.js";
import { isDecodedIncomingPacket, isPendingOutgoingPacket } from "../platforms/linux/ssh_packet_hooks.js";

// ── A tiny 64-bit little-endian address space ────────────────────────────────
// Reads outside an allocated block throw, like Frida's access-violation exception.

const blocks: Array<{ base: number; bytes: Buffer }> = [];
let nextBase = 0x10000;

function locate(addr: number, n: number): { bytes: Buffer; off: number } {
    for (const b of blocks) {
        if (addr >= b.base && addr + n <= b.base + b.bytes.length) return { bytes: b.bytes, off: addr - b.base };
    }
    throw new Error(`access violation accessing 0x${addr.toString(16)}`);
}

function P(addr: number): any {
    const at = (n: number) => locate(addr, n);
    return {
        addr,
        isNull: () => addr === 0,
        equals: (o: any) => o.addr === addr,
        add: (n: number) => P(addr + Number(n)),
        toString: () => `0x${addr.toString(16)}`,
        readPointer: () => { const { bytes, off } = at(8); return P(Number(bytes.readBigUInt64LE(off))); },
        readU64: () => { const { bytes, off } = at(8); return bytes.readBigUInt64LE(off); },
        readU32: () => { const { bytes, off } = at(4); return bytes.readUInt32LE(off); },
        readS32: () => { const { bytes, off } = at(4); return bytes.readInt32LE(off); },
        readU8: () => { const { bytes, off } = at(1); return bytes.readUInt8(off); },
        readByteArray: (n: number) => { const { bytes, off } = at(n); return new Uint8Array(bytes.subarray(off, off + n)).buffer; },
    };
}

function alloc(size: number): number {
    const base = nextBase;
    blocks.push({ base, bytes: Buffer.alloc(size) });
    nextBase += size + 0x1000; // gap: the bytes past a block are unmapped
    return base;
}

function write(addr: number, data: Buffer): void {
    if (data.length > 0) data.copy(locate(addr, data.length).bytes, addr - blockBase(addr));
}
function blockBase(addr: number): number { return blocks.find((b) => addr >= b.base && addr < b.base + b.bytes.length)!.base; }
function u64(addr: number, v: number): void { locate(addr, 8).bytes.writeBigUInt64LE(BigInt(v), addr - blockBase(addr)); }
function u32(addr: number, v: number): void { locate(addr, 4).bytes.writeUInt32LE(v >>> 0, addr - blockBase(addr)); }

/** A sane sshbuf holding `content` with `off` bytes already consumed. */
function sshbuf(content: Buffer, off = 0, fields: Partial<Record<string, number>> = {}): number {
    const data = alloc(Math.max(content.length, 1));
    write(data, content);
    const b = alloc(72);
    u64(b, fields.d ?? data);
    u64(b + 8, fields.cd ?? data);
    u64(b + 16, fields.off ?? off);
    u64(b + 24, fields.size ?? content.length);
    u64(b + 32, fields.max_size ?? SSHBUF_SIZE_MAX);
    u64(b + 40, fields.alloc ?? content.length);
    u32(b + 48, fields.readonly ?? 0);
    if (fields.dont_free !== undefined) {
        u32(b + 52, fields.dont_free);           // OpenSSH 8.x: int dont_free before refcount
        u32(b + 56, fields.refcount ?? 1);
    } else {
        u32(b + 52, fields.refcount ?? 1);
    }
    return b;
}

function kexinitBody(cookie: Buffer): Buffer {
    const names = Buffer.from("curve25519-sha256,ext-info-c");
    const len = Buffer.alloc(4); len.writeUInt32BE(names.length);
    return Buffer.concat([cookie, len, names, Buffer.alloc(40)]);
}

const hex = (b: ArrayBuffer) => Buffer.from(b).toString("hex");
const COOKIE = Buffer.from("00112233445566778899aabbccddeeff", "hex");

// ── readSshbuf ───────────────────────────────────────────────────────────────

test("readSshbuf: a sane buffer yields cd+off and size-off", () => {
    const b = sshbuf(Buffer.from("headerPAYLOAD"), 6);
    const v = readSshbuf(P(b))!;
    assert.ok(v);
    assert.equal(v.len, 7);
    assert.equal(v.off, 6);
    assert.equal(Buffer.from(v.data.readByteArray(v.len)).toString(), "PAYLOAD");
});

test("readSshbuf: rejects (never throws on) everything sshbuf_check_sanity would SIGSEGV on", () => {
    const content = Buffer.from("abcdef");
    assert.equal(readSshbuf(P(0)), null, "NULL");
    assert.equal(readSshbuf(P(0xdead0000)), null, "unmapped pointer");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { refcount: 0 }))), null, "refcount 0");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { d: 0x1234 }))), null, "d != cd while writable");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { cd: 0, d: 0 }))), null, "cd NULL");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { off: 7 }))), null, "off > size");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { size: 99 }))), null, "size > alloc");
    assert.equal(readSshbuf(P(sshbuf(content, 0, { max_size: SSHBUF_SIZE_MAX + 1 }))), null, "max_size too big");
    // A plain struct of unrelated pointers (what an offset probe meets most of the time).
    const junk = alloc(64); u64(junk, junk); u64(junk + 8, 0x4141); u64(junk + 16, 3);
    assert.equal(readSshbuf(P(junk)), null, "non-sshbuf struct");
    assert.ok(readSshbuf(P(sshbuf(content, 0, { readonly: 1, d: 0 }))), "readonly buffers may have d != cd");
});

// ── KEXINIT bodies, cookies and the struct ssh -> kex -> my/peer probe ──────

test("isKexinitBody/kexinitCookie: cookie || name-list, no message-type byte", () => {
    const my = sshbuf(kexinitBody(COOKIE));
    assert.ok(isKexinitBody(readSshbuf(P(my))));
    assert.equal(kexinitCookie(P(my), hex), COOKIE.toString("hex"));
    const typed = sshbuf(Buffer.concat([Buffer.from([0x14]), kexinitBody(COOKIE)]));
    assert.equal(isKexinitBody(readSshbuf(P(typed))), false, "a 0x14 type byte shifts the name-list");
    assert.equal(kexinitCookie(P(sshbuf(Buffer.from("short"))), hex), null);
    assert.equal(kexinitCookie(P(0xdead0000), hex), null);
});

test("probeKexLayout: finds kex as the 2nd struct ssh field and my/peer inside struct kex", () => {
    const my = sshbuf(kexinitBody(COOKIE));
    const peer = sshbuf(Buffer.alloc(0));          // empty until kex_input_kexinit
    const kex = alloc(256);
    u64(kex, alloc(16)); u64(kex + 8, 0);           // newkeys[2]
    u64(kex + 24, alloc(16));                       // some char* before my
    u64(kex + 80, my); u64(kex + 88, peer);
    const state = alloc(256); u64(state + 8, sshbuf(Buffer.from("not a kexinit")));
    const ssh = alloc(64); u64(ssh, state); u64(ssh + 8, kex);
    assert.deepEqual(probeKexLayout(P(ssh)), { kexInSsh: 8, myInKex: 80 });
    assert.equal(probeKexLayout(P(alloc(64))), null, "no kex: no layout, no throw");
});

// ── packet buffers ──────────────────────────────────────────────────────────

test("isPendingOutgoingPacket: 5 zeroed header bytes then a non-zero type", () => {
    assert.ok(isPendingOutgoingPacket(readSshbuf(P(sshbuf(Buffer.from([0, 0, 0, 0, 0, 94, 1, 2]))))));
    assert.equal(isPendingOutgoingPacket(readSshbuf(P(sshbuf(Buffer.from([0, 0, 0, 12, 4, 94, 1, 2]))))), false);
    assert.equal(isPendingOutgoingPacket(readSshbuf(P(sshbuf(Buffer.from([0, 0, 0, 0, 0]))))), false);
    assert.equal(isPendingOutgoingPacket(null), false);
});

test("isDecodedIncomingPacket: header + type consumed, type matches *typep", () => {
    const raw = Buffer.from([0, 0, 0, 16, 6, 94, 0xaa, 0xbb]);
    assert.ok(isDecodedIncomingPacket(readSshbuf(P(sshbuf(raw, 6))), 94));
    assert.equal(isDecodedIncomingPacket(readSshbuf(P(sshbuf(raw, 6))), 95), false, "wrong type");
    assert.equal(isDecodedIncomingPacket(readSshbuf(P(sshbuf(raw, 5))), 94), false, "type not consumed");
});

test("frameSshMessage: RFC 4253 framing with 4 bytes of padding", () => {
    const framed = Buffer.from(frameSshMessage(Buffer.from([94, 1, 2])));
    assert.equal(framed.readUInt32BE(0), 1 + 3 + 4);
    assert.equal(framed[4], 4);
    assert.deepEqual([...framed.subarray(5, 8)], [94, 1, 2]);
    assert.equal(framed.length, 4 + framed.readUInt32BE(0));
});

// ── shared secret K ─────────────────────────────────────────────────────────

test("sharedSecretBytes: strips the mpint/string length prefix Wireshark adds itself", () => {
    const mpint = Buffer.concat([Buffer.from("00000021", "hex"), Buffer.from([0]), Buffer.alloc(32, 0xc9)]);
    assert.equal(hex(sharedSecretBytes(readSshbuf(P(sshbuf(mpint))))!), "00" + "c9".repeat(32));
    const str = Buffer.concat([Buffer.from("00000040", "hex"), Buffer.alloc(64, 0x0d)]);
    assert.equal(hex(sharedSecretBytes(readSshbuf(P(sshbuf(str))))!), "0d".repeat(64));
    assert.equal(hex(sharedSecretBytes(readSshbuf(P(sshbuf(Buffer.from("abcdef0102", "hex")))))!), "abcdef0102",
        "no matching prefix: the bytes as they are");
    assert.equal(sharedSecretBytes(null), null);
});

// ── connection descriptors (stripped builds lack ssh_packet_get_connection_in/_out) ──

test("readConnectionFd: ssh->state->connection_in / connection_out", () => {
    const state = alloc(16);
    u32(state, 3);        // connection_in
    u32(state + 4, 4);    // connection_out
    const ssh = alloc(16);
    u64(ssh, state);
    assert.equal(readConnectionFd(P(ssh), "in"), 3);
    assert.equal(readConnectionFd(P(ssh), "out"), 4);
});

test("readConnectionFd: -1 for a closed (-1), implausible or unreadable descriptor", () => {
    const state = alloc(16);
    u32(state, 0xffffffff);          // -1: connection closed
    u32(state + 4, 0x7fffffff);      // not a descriptor
    const ssh = alloc(16);
    u64(ssh, state);
    assert.equal(readConnectionFd(P(ssh), "in"), -1);
    assert.equal(readConnectionFd(P(ssh), "out"), -1);
    const dangling = alloc(16);
    u64(dangling, 0x7fff0000);       // state pointer into unmapped memory
    assert.equal(readConnectionFd(P(dangling), "in"), -1);
    assert.equal(readConnectionFd(P(alloc(16)), "in"), -1, "state == NULL");
});

// ── bounded C strings (sshenc->name of an unverified newkeys candidate) ─────────

test("readShortCString: stops at the NUL, not at the bound (unlike readCString(size))", () => {
    const at = alloc(32);
    write(at, Buffer.concat([Buffer.from("aes128-ctr\0"), Buffer.from([0xa7, 0xff, 0x13])]));
    assert.equal(readShortCString(P(at), 32), "aes128-ctr");
});

test("readShortCString: null without a NUL in bound, on unmapped memory and NULL", () => {
    const at = alloc(8);
    write(at, Buffer.from("abcdefgh"));
    assert.equal(readShortCString(P(at), 4), null, "no terminator within the bound");
    assert.equal(readShortCString(P(at), 64), null, "runs into unmapped memory");
    assert.equal(readShortCString(P(0), 8), null);
    assert.equal(readShortCString(null, 8), null);
});

// ── OpenSSH 8.x sshbuf (int dont_free before refcount, e.g. Ubuntu 22.04's 8.9p1) ──

test("readSshbuf: accepts the 8.x layout (dont_free 0 or 1, refcount 4 bytes later)", () => {
    const content = Buffer.from("0123456789");
    for (const dontFree of [0, 1]) {
        const v = readSshbuf(P(sshbuf(content, 2, { dont_free: dontFree, refcount: 1 })));
        assert.ok(v, `dont_free=${dontFree}`);
        assert.equal(v!.len, 8);
        assert.equal(hex(v!.data.readByteArray(v!.len)), Buffer.from("23456789").toString("hex"));
    }
});

test("readSshbuf: 8.x layout still rejects an insane refcount", () => {
    assert.equal(readSshbuf(P(sshbuf(Buffer.from("abc"), 0, { dont_free: 0, refcount: 0 }))), null);
    assert.equal(readSshbuf(P(sshbuf(Buffer.from("abc"), 0, { dont_free: 0x200000, refcount: 1 }))), null,
        "neither a sane refcount nor dont_free (0/1) + refcount");
});
