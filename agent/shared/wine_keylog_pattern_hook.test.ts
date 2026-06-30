// Unit tests for the dual-ABI register reader in wine_keylog_pattern_hook.ts.
//
// Run: npm run test:agent  (node --import tsx --test agent/shared/wine_keylog_pattern_hook.test.ts)
//
// No Frida runtime needed: we side-effect import the Frida stubs first, stub
// send(), then feed readWineKeylogLine() a fake CpuContext built from fake
// NativePointers. The point is to lock down (a) ABI register selection
// (win64 = rcx/rdx/r8/r9, sysv = rdi/rsi/rdx/rcx) and (b) the bounds/null
// rejection that stops a wrong-ABI or non-code match from dumping garbage.

import { test } from "node:test";
import assert from "node:assert/strict";
// Side-effect import: defines Process/Memory/Interceptor/etc. BEFORE the module loads.
import "./frida-test-stubs.js";

const G = globalThis as any;
// shared_structures.sendKeylog() ultimately calls send(); make it a no-op sink.
G.send = G.send ?? ((_msg: any) => { });

import { readWineKeylogLine } from "./wine_keylog_pattern_hook.js";

// A fake NativePointer carrying either a string, a byte array, or an int, plus
// an optional map of offset -> bytes returned by add(off).readByteArray().
class FakePtr {
    private _null: boolean;
    private _str: string | null;
    private _bytes: number[] | null;
    private _int: number;
    private _atOffset: Record<number, number[]>;

    constructor(opts: {
        isNull?: boolean;
        str?: string | null;
        bytes?: number[] | null;
        int?: number;
        atOffset?: Record<number, number[]>;
    } = {}) {
        this._null = opts.isNull ?? false;
        this._str = opts.str ?? null;
        this._bytes = opts.bytes ?? null;
        this._int = opts.int ?? 0;
        this._atOffset = opts.atOffset ?? {};
    }
    isNull() { return this._null; }
    toInt32() { return this._int; }
    readUtf8String() { return this._str; }
    readByteArray(n: number) {
        if (this._bytes === null) throw new Error("no bytes");
        return new Uint8Array(this._bytes.slice(0, n)).buffer;
    }
    add(off: number) {
        const b = this._atOffset[off];
        if (b === undefined) throw new Error(`no bytes at offset ${off}`);
        return new FakePtr({ bytes: b });
    }
}

const CR = Array.from({ length: 32 }, (_, i) => i);          // 00 01 02 ... 1f
const CR_HEX = CR.map((n) => n.toString(16).padStart(2, "0")).join("");
const SECRET = [0xaa, 0xbb, 0xcc, 0xdd];
const SECRET_HEX = "aabbccdd";

function gnutlsSig(abi: "sysv" | "win64") {
    return { id: "t", library: "gnutls", abi, pattern: "", clientRandomOffset: 0x50 } as any;
}

test("win64 reads label/secret/size from rcx,rdx,r8,r9 and CR from rcx+offset", () => {
    const session = new FakePtr({ atOffset: { 0x50: CR } });   // rcx
    const label = new FakePtr({ str: "CLIENT_HANDSHAKE_TRAFFIC_SECRET" }); // rdx
    const secret = new FakePtr({ bytes: SECRET });             // r8
    const size = new FakePtr({ int: SECRET.length });          // r9
    // Put DECOY values in the System V registers to prove they are NOT read.
    const ctx: any = {
        rcx: session, rdx: label, r8: secret, r9: size,
        rdi: new FakePtr({ isNull: true }), rsi: new FakePtr({ isNull: true }),
    };
    const line = readWineKeylogLine(ctx, gnutlsSig("win64"));
    assert.equal(line, `CLIENT_HANDSHAKE_TRAFFIC_SECRET ${CR_HEX} ${SECRET_HEX}`);
});

test("sysv reads label/secret/size from rdi,rsi,rdx,rcx and CR from rdi+offset", () => {
    const session = new FakePtr({ atOffset: { 0x50: CR } });   // rdi
    const label = new FakePtr({ str: "SERVER_TRAFFIC_SECRET_0" }); // rsi
    const secret = new FakePtr({ bytes: SECRET });             // rdx
    const size = new FakePtr({ int: SECRET.length });          // rcx
    const ctx: any = {
        rdi: session, rsi: label, rdx: secret, rcx: size,
        r8: new FakePtr({ isNull: true }), r9: new FakePtr({ isNull: true }),
    };
    const line = readWineKeylogLine(ctx, gnutlsSig("sysv"));
    assert.equal(line, `SERVER_TRAFFIC_SECRET_0 ${CR_HEX} ${SECRET_HEX}`);
});

test("rejects implausible secret length (<=0 and >=1024)", () => {
    const mk = (size: number) => {
        const ctx: any = {
            rcx: new FakePtr({ atOffset: { 0x50: CR } }),
            rdx: new FakePtr({ str: "LBL" }),
            r8: new FakePtr({ bytes: SECRET }),
            r9: new FakePtr({ int: size }),
        };
        return readWineKeylogLine(ctx, gnutlsSig("win64"));
    };
    assert.equal(mk(0), null);
    assert.equal(mk(-1), null);
    assert.equal(mk(1024), null);
    assert.equal(mk(99999), null);
});

test("rejects null session/label/secret pointers", () => {
    const base: any = {
        rcx: new FakePtr({ atOffset: { 0x50: CR } }),
        rdx: new FakePtr({ str: "LBL" }),
        r8: new FakePtr({ bytes: SECRET }),
        r9: new FakePtr({ int: SECRET.length }),
    };
    assert.equal(readWineKeylogLine({ ...base, rcx: new FakePtr({ isNull: true }) } as any, gnutlsSig("win64")), null);
    assert.equal(readWineKeylogLine({ ...base, rdx: new FakePtr({ isNull: true }) } as any, gnutlsSig("win64")), null);
    assert.equal(readWineKeylogLine({ ...base, r8: new FakePtr({ isNull: true }) } as any, gnutlsSig("win64")), null);
});

test("rejects empty/null label", () => {
    const ctx: any = {
        rcx: new FakePtr({ atOffset: { 0x50: CR } }),
        rdx: new FakePtr({ str: "" }),
        r8: new FakePtr({ bytes: SECRET }),
        r9: new FakePtr({ int: SECRET.length }),
    };
    assert.equal(readWineKeylogLine(ctx, gnutlsSig("win64")), null);
});

test("openssl win64 uses SSL*+0x184 for client_random", () => {
    const sslSig = { id: "o", library: "openssl", abi: "win64", pattern: "", clientRandomOffset: 0x184 } as any;
    const ssl = new FakePtr({ atOffset: { 0x184: CR } });
    const ctx: any = {
        rcx: ssl, rdx: new FakePtr({ str: "CLIENT_RANDOM" }),
        r8: new FakePtr({ bytes: SECRET }), r9: new FakePtr({ int: SECRET.length }),
    };
    const line = readWineKeylogLine(ctx, sslSig);
    assert.equal(line, `CLIENT_RANDOM ${CR_HEX} ${SECRET_HEX}`);
});
