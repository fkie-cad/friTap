// Unit tests for string_anchor_functions.ts ("which functions reference string X").
//
// Run: npm run test:agent
//
// A synthetic module (data range + code range in one buffer) backs a minimal
// NativePointer/Module/Memory polyfill, as in arm64_xref.test.ts. The code range is
// filled with arm64 or x86-64 load sequences per test; a fake bounds source plays the
// .eh_frame_hdr table so function grouping and the agreement rule are deterministic.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

const BASE = 0x100000;
const SIZE = 0x4000;
const DATA = { base: BASE, size: 0x1000 };           // 0x100000 .. 0x101000 (r--)
const CODE = { base: BASE + 0x1000, size: 0x3000 };  // 0x101000 .. 0x104000 (r-x)
const buf = new Uint8Array(SIZE);

class BufPtr {
    constructor(public addr: number) {}
    isNull() { return this.addr === 0; }
    toString() { return "0x" + this.addr.toString(16); }
    equals(o: BufPtr) { return this.addr === o.addr; }
    compare(o: BufPtr) { return this.addr < o.addr ? -1 : this.addr > o.addr ? 1 : 0; }
    add(n: number | BufPtr) { return new BufPtr(this.addr + (typeof n === "number" ? n : n.addr)); }
    sub(n: number | BufPtr) { return new BufPtr(this.addr - (typeof n === "number" ? n : n.addr)); }
    and(o: BufPtr | number) { return new BufPtr(this.addr & (typeof o === "number" ? o : o.addr)); }
    not() { return new BufPtr(~this.addr); }
    toInt32() { return this.addr | 0; }
    private off(n: number) {
        const off = this.addr - BASE;
        if (off < 0 || off + n > SIZE) throw new Error("read out of range");
        return off;
    }
    readU8() { return buf[this.off(1)]; }
    readU32() {
        const o = this.off(4);
        return (buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24)) >>> 0;
    }
    readPointer() {
        const o = this.off(8);
        let v = 0;
        for (let i = 0; i < 8; i++) v += buf[o + i] * 2 ** (8 * i);
        return new BufPtr(v);
    }
    readByteArray(n: number) {
        const o = this.off(n);
        return buf.slice(o, o + n).buffer;
    }
}

const fakeModule = {
    base: new BufPtr(BASE),
    size: SIZE,
    name: "fake",
    enumerateRanges(prot: string) {
        const code = { base: new BufPtr(CODE.base), size: CODE.size, protection: "r-x" };
        const data = { base: new BufPtr(DATA.base), size: DATA.size, protection: "r--" };
        return prot === "r-x" ? [code] : [data, code]; // Frida's "r--" also returns r-x ranges
    },
} as unknown as Module;

G.ptr = (v: any) => new BufPtr(typeof v === "string" ? parseInt(v, 16) : Number(v));
G.Memory.scanSync = (base: any, size: number, pattern: string) => {
    const [needleStr, maskStr] = pattern.split(":");
    const needle = needleStr.trim().split(/\s+/).map((h) => parseInt(h, 16));
    const mask = maskStr ? maskStr.trim().split(/\s+/).map((h) => parseInt(h, 16)) : needle.map(() => 0xff);
    const start = base.addr - BASE;
    const hits: { address: BufPtr }[] = [];
    for (let i = start; i + needle.length <= start + size && i + needle.length <= SIZE; i++) {
        let ok = true;
        for (let j = 0; j < needle.length; j++) {
            if ((buf[i + j] & mask[j]) !== (needle[j] & mask[j])) { ok = false; break; }
        }
        if (ok) hits.push({ address: new BufPtr(BASE + i) });
    }
    return hits;
};

import {
    AnchorFunctions, agreedFunction, anchorTargets, groupSitesByFunction,
    locateFunctionsByAnchor, locateFunctionsByAnchors,
} from "./string_anchor_functions.js";

// ---- builders ----------------------------------------------------------------

function reset(): void { buf.fill(0); }
function writeString(addr: number, s: string): void {
    const o = addr - BASE;
    for (let i = 0; i < s.length; i++) buf[o + i] = s.charCodeAt(i);
    buf[o + s.length] = 0;
}
function writeU32(addr: number, word: number): void {
    const o = addr - BASE;
    for (let i = 0; i < 4; i++) buf[o + i] = (word >>> (8 * i)) & 0xff;
}
function writeBytes(addr: number, bytes: number[]): void { buf.set(bytes, addr - BASE); }

/** arm64 `adrp xR, page(target) ; add xR, xR, #lo12(target)` at pc. */
function armLoad(pc: number, reg: number, target: number): void {
    const pages = (target >> 12) - (pc >> 12);
    writeU32(pc, (0x90000000 | ((pages & 3) << 29) | (((pages >> 2) & 0x7ffff) << 5) | reg) >>> 0);
    writeU32(pc + 4, (0x91000000 | ((target & 0xfff) << 10) | (reg << 5) | reg) >>> 0);
}
/** x86-64 `lea rsi, [rip+disp32]` at pc. */
function x64Lea(pc: number, target: number): void {
    const disp = target - (pc + 7);
    writeBytes(pc, [0x48, 0x8d, 0x35, disp & 0xff, (disp >> 8) & 0xff, (disp >> 16) & 0xff, (disp >>> 24) & 0xff]);
}

/** Bounds source: functions [start, end) at fixed addresses (plays .eh_frame_hdr). */
function boundsOf(fns: [number, number][]) {
    return {
        bounds(addr: BufPtr) {
            const f = fns.find(([s, e]) => addr.addr >= s && addr.addr < e);
            return f ? { start: new BufPtr(f[0]), end: new BufPtr(f[1]) } : null;
        },
    } as any;
}

const FN_A: [number, number] = [CODE.base + 0x000, CODE.base + 0x100];
const FN_B: [number, number] = [CODE.base + 0x100, CODE.base + 0x200];
const FN_C: [number, number] = [CODE.base + 0x200, CODE.base + 0x300];
const FUNCTIONS = boundsOf([FN_A, FN_B, FN_C]);
const immediate = () => Promise.resolve();
const opts = { functions: FUNCTIONS, yieldFn: immediate };
const starts = (r: AnchorFunctions) => r.functions.map((f) => (f.start as any).addr);

function withArch<T>(arch: string, body: () => Promise<T>): Promise<T> {
    const prev = G.Process.arch;
    G.Process.arch = arch;
    return body().finally(() => { G.Process.arch = prev; });
}

// ---- arm64 -----------------------------------------------------------------------

test("arm64: the function that loads a __func__ literal is found", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x10, "kex_derive_keys");
    armLoad(FN_A[0] + 0x20, 1, DATA.base + 0x10);
    armLoad(FN_A[0] + 0x60, 1, DATA.base + 0x10);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "kex_derive_keys" }, opts);
    assert.deepEqual(starts(r), [FN_A[0]]);
    assert.equal(r.functions[0].sites.length, 2);
    assert.deepEqual(r.unboundedSites, []);
}));

test("arm64: a tail-merged literal is found through the tail's address", () => withArch("arm64", async () => {
    reset();
    // Only the long literal exists; "cipher_init" is its tail and FN_B loads the tail.
    writeString(DATA.base + 0x40, "chachapoly_cipher_init");
    armLoad(FN_A[0] + 0x10, 2, DATA.base + 0x40);            // loads the long literal
    armLoad(FN_B[0] + 0x10, 3, DATA.base + 0x40 + 11);       // loads its tail "cipher_init"
    const [tail, long] = await locateFunctionsByAnchors(fakeModule,
        [{ text: "cipher_init" }, { text: "chachapoly_cipher_init" }], opts);
    assert.deepEqual(starts(tail), [FN_B[0]]);
    assert.deepEqual(starts(long), [FN_A[0]]);
}));

test("arm64: every occurrence counts — a standalone copy and a tail copy", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x40, "chachapoly_cipher_init"); // nobody loads its tail
    writeString(DATA.base + 0x80, "cipher_init");             // standalone copy
    armLoad(FN_C[0] + 0x10, 4, DATA.base + 0x80);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "cipher_init" }, opts);
    assert.deepEqual(starts(r), [FN_C[0]]);
}));

test("arm64: literalSuffix xrefs the start of the longer literal", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x100, "../../third_party/ssl/ssl_lib.cc");
    armLoad(FN_B[0] + 0x30, 5, DATA.base + 0x100);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "/ssl/ssl_lib.cc", literalSuffix: true }, opts);
    assert.deepEqual(starts(r), [FN_B[0]]);
}));

test("arm64: an inlined copy shows up as a second function", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x10, "ssh_packet_read_poll2");
    armLoad(FN_A[0] + 0x10, 1, DATA.base + 0x10);
    armLoad(FN_C[0] + 0x40, 1, DATA.base + 0x10);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "ssh_packet_read_poll2" }, opts);
    assert.deepEqual(starts(r), [FN_A[0], FN_C[0]]);
    assert.equal(agreedFunction([r]), null);
}));

test("arm64: a site outside every function is reported as unbounded", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x10, "orphan");
    armLoad(CODE.base + 0x800, 1, DATA.base + 0x10);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "orphan" }, opts);
    assert.deepEqual(r.functions, []);
    assert.deepEqual(r.unboundedSites.map((p: any) => p.addr), [CODE.base + 0x800]);
}));

test("absent or unreferenced literals yield no functions", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x10, "unreferenced");
    const [a, b] = await locateFunctionsByAnchors(fakeModule, [{ text: "unreferenced" }, { text: "absent" }], opts);
    assert.deepEqual(a, { functions: [], unboundedSites: [] });
    assert.deepEqual(b, { functions: [], unboundedSites: [] });
}));

test("no function table: nothing is located (and nothing is scanned)", () => withArch("arm64", async () => {
    reset();
    writeString(DATA.base + 0x10, "kex_derive_keys");
    armLoad(FN_A[0] + 0x20, 1, DATA.base + 0x10);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "kex_derive_keys" }, { functions: null, yieldFn: immediate });
    assert.deepEqual(r, { functions: [], unboundedSites: [] });
}));

test("unsupported architecture: no functions", () => withArch("ia32", async () => {
    reset();
    writeString(DATA.base + 0x10, "kex_derive_keys");
    armLoad(FN_A[0] + 0x20, 1, DATA.base + 0x10);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "kex_derive_keys" }, opts);
    assert.deepEqual(r.functions, []);
}));

test("a literal kept in the r-x range (no separate-code) is still found", () => withArch("arm64", async () => {
    reset();
    writeString(CODE.base + 0x2f00, "kex_send_kexinit");      // rodata inside r-x
    armLoad(FN_B[0] + 0x40, 6, CODE.base + 0x2f00);
    const r = await locateFunctionsByAnchor(fakeModule, { text: "kex_send_kexinit" }, opts);
    assert.deepEqual(starts(r), [FN_B[0]]);
}));

// ---- x86-64 ----------------------------------------------------------------------

test("x64: RIP-relative LEA sites are grouped by function", () => withArch("x64", async () => {
    reset();
    writeString(DATA.base + 0x10, "kex_input_kexinit");
    writeString(DATA.base + 0x30, "SSH2_MSG_KEXINIT received");
    x64Lea(FN_B[0] + 0x05, DATA.base + 0x10);
    x64Lea(FN_B[0] + 0x40, DATA.base + 0x30);
    x64Lea(FN_B[0] + 0x80, DATA.base + 0x10);
    const [fn, msg] = await locateFunctionsByAnchors(fakeModule,
        [{ text: "kex_input_kexinit" }, { text: "SSH2_MSG_KEXINIT received" }], opts);
    assert.deepEqual(starts(fn), [FN_B[0]]);
    assert.equal(fn.functions[0].sites.length, 2);
    assert.deepEqual(starts(msg), [FN_B[0]]);
    assert.equal(agreedFunction([fn, msg])!.start.toString(), new BufPtr(FN_B[0]).toString());
}));

test("x64: a LEA straddling a chunk boundary is found exactly once", () => withArch("x64", async () => {
    reset();
    writeString(DATA.base + 0x10, "ssh_set_newkeys");
    x64Lea(CODE.base + 0x0fd, DATA.base + 0x10);              // starts 3 bytes before a 0x100 chunk edge
    let yields = 0;
    const r = await locateFunctionsByAnchor(fakeModule, { text: "ssh_set_newkeys" },
        { functions: FUNCTIONS, chunkBytes: 0x100, yieldFn: () => { yields++; return Promise.resolve(); } });
    assert.deepEqual(r.functions.map((f) => f.sites.map((s: any) => s.addr)), [[CODE.base + 0x0fd]]);
    assert.ok(yields >= CODE.size / 0x100, "yields between chunks");
}));

test("x64: two anchors sharing one literal both get its sites", () => withArch("x64", async () => {
    reset();
    writeString(DATA.base + 0x10, "kex_derive_keys");
    x64Lea(FN_C[0] + 0x10, DATA.base + 0x10);
    const [a, b] = await locateFunctionsByAnchors(fakeModule,
        [{ text: "kex_derive_keys" }, { text: "kex_derive_keys" }], opts);
    assert.deepEqual(starts(a), [FN_C[0]]);
    assert.deepEqual(starts(b), [FN_C[0]]);
}));

// ---- pure helpers ------------------------------------------------------------------

const P = (a: number) => new BufPtr(a) as unknown as NativePointer;
const one = (start: number): AnchorFunctions =>
    ({ functions: [{ start: P(start), end: P(start + 0x10), sites: [P(start + 4)] }], unboundedSites: [] });
const none: AnchorFunctions = { functions: [], unboundedSites: [] };

test("agreedFunction: one function named by every anchor with sites", () => {
    assert.equal(agreedFunction([one(0x10), none, one(0x10)])!.start.toString(), "0x10");
});

test("agreedFunction: anchors that disagree are rejected", () => {
    assert.equal(agreedFunction([one(0x10), one(0x20)]), null);
});

test("agreedFunction: a literal loaded from two functions is rejected", () => {
    const two: AnchorFunctions = { functions: [...one(0x10).functions, ...one(0x20).functions], unboundedSites: [] };
    assert.equal(agreedFunction([two]), null);
    assert.equal(agreedFunction([one(0x10), two]), null);
});

test("agreedFunction: an unbounded site is rejected", () => {
    assert.equal(agreedFunction([{ ...one(0x10), unboundedSites: [P(0x99)] }]), null);
    assert.equal(agreedFunction([{ functions: [], unboundedSites: [P(0x99)] }]), null);
});

test("agreedFunction: a function that also loads an excluded anchor is rejected", () => {
    // ssh_packet_read_poll2 inlined into ssh_packet_read_poll_seqnr: every read_poll2 anchor
    // agrees on the caller, which also loads the caller's own __func__ (excluded).
    assert.equal(agreedFunction([one(0x10), one(0x10)], [one(0x10)]), null);
    assert.equal(agreedFunction([one(0x10)], [one(0x20), none])!.start.toString(), "0x10",
        "an excluded anchor elsewhere does not matter");
});

test("agreedFunction: no anchor with sites -> null", () => {
    assert.equal(agreedFunction([none, none]), null);
    assert.equal(agreedFunction([]), null);
});

test("groupSitesByFunction sorts, dedupes and splits out unbounded sites", () => {
    const r = groupSitesByFunction([P(FN_B[0] + 8), P(FN_A[0] + 4), P(FN_B[0] + 8), P(CODE.base + 0x900)], FUNCTIONS);
    assert.deepEqual(r.functions.map((f) => [(f.start as any).addr, f.sites.map((s: any) => s.addr)]),
        [[FN_A[0], [FN_A[0] + 4]], [FN_B[0], [FN_B[0] + 8]]]);
    assert.deepEqual(r.unboundedSites.map((s: any) => s.addr), [CODE.base + 0x900]);
});

test("anchorTargets: exact hits are deduped; literalSuffix maps hits to the literal start", () => {
    reset();
    writeString(DATA.base + 0x200, "abc/def.c");
    const hit = P(DATA.base + 0x203);
    assert.deepEqual(anchorTargets({ text: "/def.c" }, [hit, hit]).map(String), [hit.toString()]);
    assert.deepEqual(anchorTargets({ text: "/def.c", literalSuffix: true }, [hit]).map(String),
        [P(DATA.base + 0x200).toString()]);
});
