// Unit tests for the is_base_hook decision in the shared SSL_write / SSL_write_ex hooks
// (shared/ssl_plaintext_hooks.ts).
//
// Run: npm run test:agent
//
// WHY: the write hooks used to read `this.is_base_hook` inside the Interceptor onEnter,
// where `this` is Frida's InvocationContext — always undefined. So every library, even
// the base-hooked one, took the "dynamically loaded" branch when SSL_get_fd threw and
// rebound its SSL helpers to init_addresses (a lookup that itself threw for non-Apple
// modules, killing the write record). The flag must come from the hooker instance.

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import { SslPlaintextHooks, SslPlaintextHost } from "./ssl_plaintext_hooks.js";
import {
    SslMemoryReader, noteSslClientRandom, resetSslIdentityState, setSslLayout, setSslMemoryReader,
} from "./ssl_identity.js";

const G = globalThis as any;

function addr(name: string): any {
    return { name, isNull: () => false, toString: () => `0x${name}` };
}
function int(n: number): any { return { toInt32: () => n, toString: () => String(n) }; }

const listeners = new Map<string, any>();
G.Interceptor.attach = (target: any, callbacks: any) => {
    listeners.set(String(target), callbacks);
    return { detach: () => { } };
};
/** NativeFunction(address) -> a callable tagged with the address it was bound to. */
G.NativeFunction = function (target: any) {
    const fn: any = () => -1;
    fn.boundTo = target?.name;
    return fn;
};

function throwingSslGetFd(): any {
    const fn: any = () => { throw new Error("access violation accessing 0x0"); };
    fn.boundTo = "original";
    return fn;
}

function makeHost(isBaseHook: boolean): SslPlaintextHost {
    return {
        moduleName: "libssl.so.3",
        module_name: "libssl.so.3",
        addresses: { "libssl.so.3": {} },
        is_base_hook: isBaseHook,
        SSL_get_fd: throwingSslGetFd(),
        SSL_get_session: () => null,
        SSL_SESSION_get_id: () => null,
        getSslSessionId: () => "",
    };
}

const NO_MODS = { readmod: null, writemod: null };

/** Drive a write hook's onEnter with a fresh InvocationContext (no is_base_hook on it). */
function callWrite(host: SslPlaintextHost, ex: boolean): void {
    const hooks = new SslPlaintextHooks(host, NO_MODS, false);
    const name = ex ? "SSL_write_ex" : "SSL_write";
    if (ex) hooks.attachWriteEx(addr(name)); else hooks.attachWrite(addr(name));
    const invocationContext: any = {};
    listeners.get(`0x${name}`).onEnter.call(invocationContext, [addr("ssl"), addr("buf"), int(4)]);
}

beforeEach(() => {
    G.init_addresses = {
        "libssl.base.so": {
            SSL_get_fd: addr("base_SSL_get_fd"),
            SSL_get_session: addr("base_SSL_get_session"),
            SSL_SESSION_get_id: addr("base_SSL_SESSION_get_id"),
        },
    };
});

for (const ex of [false, true]) {
    const fn = ex ? "SSL_write_ex" : "SSL_write";

    test(`${fn}: a base hook keeps its own SSL helpers when SSL_get_fd throws`, () => {
        const host = makeHost(true);
        callWrite(host, ex);
        assert.equal((host.SSL_get_fd as any).boundTo, "original");
    });

    test(`${fn}: a dynamically loaded hook rebinds to the base hook's helpers`, () => {
        const host = makeHost(false);
        callWrite(host, ex);
        assert.equal((host.SSL_get_fd as any).boundTo, "base_SSL_get_fd");
        assert.equal((host.SSL_get_session as any).boundTo, "base_SSL_get_session");
        assert.equal((host.SSL_SESSION_get_id as any).boundTo, "base_SSL_SESSION_get_id");
    });

    test(`${fn}: no base-hook fallback leaves the helpers alone instead of throwing`, () => {
        G.init_addresses = {};
        const host = makeHost(false);
        assert.doesNotThrow(() => callWrite(host, ex));
        assert.equal((host.SSL_get_fd as any).boundTo, "original");
    });
}

// ── written-byte accounting and writemod buffer lifetime ─────────────────────
// WHY: write records used to carry the REQUESTED length (num), emitted from onEnter.
// On a partial write the app retries with the remainder, so the capture duplicated
// plaintext. And the writemod replacement buffer lived only in an onEnter local, so
// it was collectable while SSL_write still read it.

function bytes(text: string, off = 0): any {
    const buf = Buffer.from(text);
    return {
        isNull: () => false,
        readByteArray: (n: number) => buf.subarray(off, off + Number(n)),
        readU32: () => buf.readUInt32LE(off),
    };
}
function outParam(value: number): any {
    const buf = Buffer.alloc(8);
    buf.writeUInt32LE(value, 0);
    return { isNull: () => false, readU32: () => buf.readUInt32LE(0) };
}

const datalogs: string[] = [];
G.send = (message: any, data?: any) => {
    if (message?.contentType === "datalog") datalogs.push(Buffer.from(data).toString());
};

/** Hooks on a host with a working SSL_get_fd; buildMessage always attributes. */
function attributedHooks(mods: any, ex: boolean): any {
    const host = makeHost(true);
    host.SSL_get_fd = (() => 5) as any;
    const hooks: any = new SslPlaintextHooks(host, mods, false);
    hooks.buildMessage = () => ({ function: ex ? "SSL_write_ex" : "SSL_write" });
    const name = ex ? "attr_SSL_write_ex" : "attr_SSL_write";
    if (ex) hooks.attachWriteEx(addr(name)); else hooks.attachWrite(addr(name));
    return listeners.get(`0x${name}`);
}

test("SSL_write: emitted in onLeave with min(num, retval) bytes; a retry does not duplicate", () => {
    datalogs.length = 0;
    const hook = attributedHooks(NO_MODS, false);
    const first: any = {};
    hook.onEnter.call(first, [addr("ssl"), bytes("0123456789"), int(10)]);
    assert.equal(datalogs.length, 0, "nothing emitted before the written count is known");
    hook.onLeave.call(first, int(4));
    const retry: any = {};
    hook.onEnter.call(retry, [addr("ssl"), bytes("0123456789", 4), int(6)]);
    hook.onLeave.call(retry, int(6));
    assert.deepEqual(datalogs, ["0123", "456789"]);
});

test("SSL_write: a failed write (retval <= 0) emits nothing", () => {
    datalogs.length = 0;
    const hook = attributedHooks(NO_MODS, false);
    const ctx: any = {};
    hook.onEnter.call(ctx, [addr("ssl"), bytes("retry me"), int(8)]);
    hook.onLeave.call(ctx, int(-1));
    assert.deepEqual(datalogs, []);
});

test("SSL_write_ex: emits *written bytes on success, nothing on failure", () => {
    datalogs.length = 0;
    const hook = attributedHooks(NO_MODS, true);
    const ok: any = {};
    hook.onEnter.call(ok, [addr("ssl"), bytes("POST /upload"), int(12), outParam(4)]);
    hook.onLeave.call(ok, int(1));
    const failed: any = {};
    hook.onEnter.call(failed, [addr("ssl"), bytes("POST /upload"), int(12), outParam(12)]);
    hook.onLeave.call(failed, int(0));
    assert.deepEqual(datalogs, ["POST"]);
});

for (const ex of [false, true]) {
    test(`${ex ? "SSL_write_ex" : "SSL_write"}: the writemod replacement buffer is kept on the invocation context`, () => {
        datalogs.length = 0;
        const replacement = Buffer.from("REPLACED");
        const allocated: any[] = [];
        const alloc = G.Memory.alloc;
        G.Memory.alloc = (size: number) => {
            const block: any = {
                isNull: () => false,
                writeByteArray: (data: ArrayBuffer) => { block.data = Buffer.from(data); },
                readByteArray: (n: number) => block.data.subarray(0, n),
                toInt32: () => size,
            };
            allocated.push(block);
            return block;
        };
        G.NativePointer = function (n: number) { return { toInt32: () => n, isNull: () => n === 0 }; };
        try {
            const hook = attributedHooks({ readmod: null, writemod: replacement.buffer.slice(replacement.byteOffset, replacement.byteOffset + replacement.length) }, ex);
            const ctx: any = {};
            const args = [addr("ssl"), bytes("original"), int(8), outParam(8)];
            hook.onEnter.call(ctx, args);
            assert.equal(allocated.length, 1);
            assert.equal(ctx.replacement, allocated[0], "replacement must be referenced by the context");
            assert.equal(args[1], allocated[0], "the library is handed the replacement");
            hook.onLeave.call(ctx, int(ex ? 1 : 8));
            assert.deepEqual(datalogs, ["REPLACED"]);
        } finally {
            G.Memory.alloc = alloc;
        }
    });
}

// ── client_random lookup (P1 design B4): cache -> module layout -> export -> none ──

function memPtr(address: number): any {
    return {
        address, isNull: () => address === 0, toString: () => "0x" + address.toString(16),
        equals: (other: any) => other.address === address,
    };
}

/** Fake UInt64 over 8 little-endian bytes: only equals() is used by ssl_identity's anchor check. */
function fakeU64(bytes: Uint8Array): any {
    const value = Array.from(bytes).reduceRight((acc, b) => (acc << 8n) | BigInt(b), 0n);
    return { value, equals: (other: any) => other.value === value };
}

/** Sparse fake memory (pointer slots + byte cells); anything unwritten faults (null). */
class FakeSslMemory implements SslMemoryReader {
    pointers = new Map<number, number>();
    bytes = new Map<number, number>();
    readPointer(base: any, offset: number): any {
        const value = this.pointers.get(base.address + offset);
        return value === undefined ? null : memPtr(value);
    }
    readBytes(base: any, offset: number, length: number): Uint8Array | null {
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            const b = this.bytes.get(base.address + offset + i);
            if (b === undefined) return null;
            out[i] = b;
        }
        return out;
    }
    readU64(base: any, offset: number): any {
        const bytes = this.readBytes(base, offset, 8);
        return bytes === null ? null : fakeU64(bytes);
    }
    /** ssl->s3 at ssl+s3Off, cr at s3+crOff. */
    place(ssl: number, s3: number, cr: string, s3Off = 0x30, crOff = 0x30): void {
        this.pointers.set(ssl + s3Off, s3);
        for (let i = 0; i < 32; i++) this.bytes.set(s3 + crOff + i, parseInt(cr.slice(i * 2, i * 2 + 2), 16));
    }
}

function crHex(seed: number): string {
    let out = "";
    for (let i = 0; i < 32; i++) out += (((seed * 31 + i * 7) % 255) + 1).toString(16).padStart(2, "0");
    return out;
}

function crHooks(moduleName: string, viaExport?: (ssl: any) => string): SslPlaintextHooks {
    const host = { ...makeHost(true), moduleName, module_name: moduleName, clientRandomViaExport: viaExport };
    if (!viaExport) host.clientRandomViaExport = () => "";
    return new SslPlaintextHooks(host, NO_MODS, false);
}

function withFakeMemory(run: (mem: FakeSslMemory) => void): void {
    resetSslIdentityState();
    const mem = new FakeSslMemory();
    setSslMemoryReader(mem);
    try { run(mem); } finally { setSslMemoryReader(null); resetSslIdentityState(); }
}

test("clientRandomFor: a keylog-noted SSL* anchored by the module's layout is a cache hit (no export call)", () => withFakeMemory((mem) => {
    setSslLayout("libmonochrome.so", { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: true });
    let exportCalls = 0;
    const hooks = crHooks("libmonochrome.so", () => { exportCalls++; return crHex(9); });
    const ssl = memPtr(0x10000);
    mem.place(0x10000, 0x11000, crHex(1));
    noteSslClientRandom(ssl, crHex(1).toUpperCase(), "libmonochrome.so");
    assert.equal(hooks.clientRandomFor(ssl), crHex(1));
    assert.equal(hooks.clientRandomFor(ssl), crHex(1));
    assert.equal(exportCalls, 0);
}));

test("clientRandomFor: an anchorless keylog note is not served ahead of the export; it is the fallback", () => withFakeMemory(() => {
    let exported = crHex(9);
    let exportCalls = 0;
    const hooks = crHooks("libmonochrome.so", () => { exportCalls++; return exported; });
    const ssl = memPtr(0x10000);
    noteSslClientRandom(ssl, crHex(1).toUpperCase());
    assert.equal(hooks.clientRandomFor(ssl), crHex(9), "the export reflects a reused SSL* address");
    assert.equal(exportCalls, 1);
    noteSslClientRandom(ssl, crHex(1));
    exported = "";
    assert.equal(hooks.clientRandomFor(ssl), crHex(1), "the note answers when the export yields nothing");
}));

test("clientRandomFor: layouts are per module (two modules, only one has a layout)", () => withFakeMemory((mem) => {
    setSslLayout("libmonochrome.so", { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: true });
    const chrome = crHooks("libmonochrome.so");
    const other = crHooks("libssl.so");
    const sslA = memPtr(0x20000);
    const sslB = memPtr(0x30000);
    mem.place(0x20000, 0x21000, crHex(2));
    mem.place(0x30000, 0x31000, crHex(3));
    assert.equal(chrome.clientRandomFor(sslA), crHex(2), "read through libmonochrome's layout");
    assert.equal(other.clientRandomFor(sslB), "", "libmonochrome's layout is never applied to libssl");
}));

test("clientRandomFor: an unvalidated layout answers after 3 distinct plausible SSL*", () => withFakeMemory((mem) => {
    setSslLayout("libwebviewchromium.so", { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
    const hooks = crHooks("libwebviewchromium.so");
    const results: string[] = [];
    for (let i = 0; i < 3; i++) {
        mem.place(0x40000 + i * 0x1000, 0x50000 + i * 0x1000, crHex(10 + i));
        results.push(hooks.clientRandomFor(memPtr(0x40000 + i * 0x1000)));
    }
    assert.deepEqual(results, ["", "", crHex(12)]);
}));

test("clientRandomFor: falls back to the SSL_get_client_random export, asked per record (never an anchorless cache hit)", () => withFakeMemory(() => {
    let exportCalls = 0;
    let exported = crHex(4).toUpperCase();
    const hooks = crHooks("libssl.so", () => { exportCalls++; return exported; });
    const ssl = memPtr(0x60000);
    assert.equal(hooks.clientRandomFor(ssl), crHex(4));
    exported = crHex(6);
    assert.equal(hooks.clientRandomFor(ssl), crHex(6), "a reused SSL* address yields the new connection's cr");
    assert.equal(exportCalls, 2);
}));

test("clientRandomFor: nothing known -> \"\" and nothing is negative-cached", () => withFakeMemory(() => {
    let answer = "";
    const hooks = crHooks("libssl.so", () => answer);
    const ssl = memPtr(0x70000);
    assert.equal(hooks.clientRandomFor(ssl), "");
    answer = crHex(5);
    assert.equal(hooks.clientRandomFor(ssl), crHex(5));
}));

test("clientRandomFor: without a host override, a module with no export resolves to none", () => withFakeMemory(() => {
    const host = { ...makeHost(true), moduleName: "libmonochrome.so", module_name: "libmonochrome.so" };
    const hooks = new SslPlaintextHooks(host, NO_MODS, false);
    assert.equal(hooks.clientRandomFor(memPtr(0x80000)), "");
}));
