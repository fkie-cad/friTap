// Run: npm run test:agent
//
// Generic learned-offsets cache, agent side: named functions are accepted only
// with a matching prologue hash under the module's build_id|size|arch key,
// layout values only within the host's bounds; scan results are coalesced into
// one module_offsets_learned message per module and cache-sourced items are
// never reported back.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";
import {
    LearnedModuleCache, LearnedModuleCacheDeps, ModuleIdentity, hasLearnedMiss, installLearnedModuleCache,
    MISS_FINGERPRINT_MAX, isValidLayoutValue, learnedFunction, learnedLayout, learnedMissName,
    missFingerprint, reportLearned, reportLearnedMiss, reportLearnedMisses, sha256FunctionBody, sha256Prologue, verifiedLearnedAddress,
} from "./learned_module_cache.js";
import { memoizePerMapping } from "./module_mapping.js";
import { createHash } from "node:crypto";
import type { ModuleOffsetsLearnedPayload } from "./shared_structures.js";

const G = globalThis as any;
const IDENTITY: ModuleIdentity = { buildId: "deadbeef0011", size: 0x100000, arch: "arm64" };
const KEY = "deadbeef0011|1048576|arm64";
const SSL_LOG_SECRET_HASH = "aa".repeat(32);

class FakePtr {
    constructor(readonly value: number) {}
    add(n: any): FakePtr { return new FakePtr(this.value + Number(n?.value ?? n)); }
    sub(other: any): FakePtr { return new FakePtr(this.value - Number(other?.value ?? other)); }
    and(n: any): FakePtr { return new FakePtr(this.value & Number(n?.value ?? n)); }
    isNull(): boolean { return this.value === 0; }
    equals(other: any): boolean { return this.value === other.value; }
    toString(): string { return "0x" + this.value.toString(16); }
}

const BASE = 0x7000_0000;

function fakeModule(name = "/data/app/lib/arm64/libflutter.so", base = BASE): any {
    return { name, base: new FakePtr(base), size: IDENTITY.size };
}

function hostEntries(): Record<string, unknown> {
    return {
        [KEY]: {
            module: "libflutter.so",
            functions: { "boringssl.ssl_log_secret": { rva: 0x1234, prologue_sha256: SSL_LOG_SECRET_HASH.toUpperCase() } },
            layout: { "boringssl.ssl_st.s3": 0x30, "boringssl.bad": 0x200000, "boringssl.tableRva": 0x2000 },
        },
    };
}

/** Hashes are "aa..." at rva 0x1234 and "<rva hex>" padded otherwise. */
function hashAt(address: any): string | null {
    const rva = address.value - BASE;
    return rva === 0x1234 ? SSL_LOG_SECRET_HASH : rva.toString(16).padStart(64, "0");
}

interface Harness {
    cache: LearnedModuleCache;
    sent: ModuleOffsetsLearnedPayload[];
    flushes: (() => void)[];
}

function harness(raw: unknown = hostEntries(), over: Partial<LearnedModuleCacheDeps> = {}): Harness {
    const sent: ModuleOffsetsLearnedPayload[] = [];
    const flushes: (() => void)[] = [];
    const cache = new LearnedModuleCache(raw, {
        identify: () => IDENTITY, hashPrologue: hashAt, emit: (p) => sent.push(p),
        schedule: (flush) => flushes.push(flush), ...over,
    });
    return { cache, sent, flushes };
}

test("a cached function with a matching prologue hash resolves to base+rva", () => {
    const { cache } = harness();
    const address: any = cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret");
    assert.equal(address?.value, BASE + 0x1234);
});

test("a prologue hash mismatch or an unreadable prologue is a miss", () => {
    assert.equal(harness(hostEntries(), { hashPrologue: () => "ff".repeat(32) })
        .cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
    assert.equal(harness(hostEntries(), { hashPrologue: () => null })
        .cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
    assert.equal(harness(hostEntries(), { hashPrologue: () => { throw new Error("access violation"); } })
        .cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
});

test("another build id, size or arch, an unrelated module or an unknown name is a miss", () => {
    const mod = fakeModule();
    assert.equal(harness(hostEntries(), { identify: () => ({ ...IDENTITY, buildId: "0011223344" }) })
        .cache.learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    assert.equal(harness(hostEntries(), { identify: () => ({ ...IDENTITY, arch: "x64" }) })
        .cache.learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    assert.equal(harness(hostEntries(), { identify: () => null }).cache.learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    assert.equal(harness().cache.learnedFunction(mod, "boringssl.SSL_read"), null);
    let identified = false;
    const { cache } = harness(hostEntries(), { identify: () => { identified = true; return IDENTITY; } });
    assert.equal(cache.learnedFunction(fakeModule("/system/lib64/libssl.so"), "boringssl.ssl_log_secret"), null);
    assert.equal(identified, false, "an unrelated module must not have its ELF headers parsed");
});

test("an out-of-module rva or a malformed hash in the host entry is rejected", () => {
    const entries: any = hostEntries();
    entries[KEY].functions["boringssl.ssl_log_secret"].rva = IDENTITY.size;
    assert.equal(harness(entries).cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
    entries[KEY].functions["boringssl.ssl_log_secret"] = { rva: 0x1234, prologue_sha256: "aa" };
    assert.equal(harness(entries).cache.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
});

test("32-bit ARM keeps the resolver's Thumb parity rule: an even address is not accepted", () => {
    const ARM_IDENTITY = { ...IDENTITY, arch: "arm" };
    const armEntries = (rva: number): any => ({ "deadbeef0011|1048576|arm": {
        module: "libflutter.so", functions: { "boringssl.ssl_log_secret": { rva, prologue_sha256: SSL_LOG_SECRET_HASH } } } });
    const evenAddress = harness(armEntries(0x1234), { identify: () => ARM_IDENTITY }).cache;
    assert.equal(evenAddress.learnedFunction(fakeModule(), "boringssl.ssl_log_secret"), null);
    const thumb = harness(armEntries(0x1235), { identify: () => ARM_IDENTITY, hashPrologue: () => SSL_LOG_SECRET_HASH }).cache;
    assert.equal((thumb.learnedFunction(fakeModule(), "boringssl.ssl_log_secret") as any)?.value, BASE + 0x1235);
});

test("layout values are returned only within the host bounds", () => {
    const { cache } = harness();
    assert.equal(cache.learnedLayout(fakeModule(), "boringssl.ssl_st.s3"), 0x30);
    assert.equal(cache.learnedLayout(fakeModule(), "boringssl.bad"), null);
    assert.equal(cache.learnedLayout(fakeModule(), "boringssl.tableRva"), 0x2000);
    assert.equal(cache.learnedLayout(fakeModule(), "boringssl.missing"), null);
});

test("isValidLayoutValue applies the -0x10000..0x100000 range and 0<v<2**32 for ...Rva names", () => {
    assert.equal(isValidLayoutValue("a.b", -0x10000), true);
    assert.equal(isValidLayoutValue("a.b", -0x10001), false);
    assert.equal(isValidLayoutValue("a.b", 0x100000), true);
    assert.equal(isValidLayoutValue("a.b", 0x100001), false);
    assert.equal(isValidLayoutValue("a.b", 1.5), false);
    assert.equal(isValidLayoutValue("a.fooRva", 0), false);
    assert.equal(isValidLayoutValue("a.fooRva", 9), true);
    // macOS: Module.size covers only __TEXT, the vtable lies past it.
    assert.equal(isValidLayoutValue("a.fooRva", 0x5000_0000), true);
    assert.equal(isValidLayoutValue("a.fooRva", 2 ** 32 - 1), true);
    assert.equal(isValidLayoutValue("a.fooRva", 2 ** 32), false);
    assert.equal(isValidLayoutValue("a.fooRva", -1), false);
});

test("a ...Rva layout value past Module.size is cached and reported", () => {
    const pastSize = 0x1000_0000;
    const { cache, sent, flushes } = harness({
        [KEY]: { module: "libflutter.so", layout: { "quiche.layout.connectionVtableRva": pastSize } },
    });
    const mod = fakeModule();
    assert.ok(pastSize > mod.size);
    assert.equal(cache.learnedLayout(mod, "quiche.layout.connectionVtableRva"), pastSize);
    cache.reportLearned(mod, { layout: { "quiche.layout.otherVtableRva": pastSize + 8 } });
    flushes.forEach((f) => f());
    const reported = sent.filter((p) => p.layout !== undefined);
    assert.equal(reported.length, 1);
    assert.equal(reported[0].layout?.["quiche.layout.otherVtableRva"], pastSize + 8);
});

test("reports within one burst become ONE message per module with rva and lowercase hash", () => {
    const { cache, sent, flushes } = harness({}, { hashPrologue: (a: any) => (a.value === BASE + 0x500 ? "AB".repeat(32) : null) });
    const mod = fakeModule();
    cache.reportLearned(mod, { functions: { "boringssl.ssl_log_secret": mod.base.add(0x500) } });
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.s3": 0x30 } });
    assert.equal(flushes.length, 1, "one scheduled flush per burst");
    assert.equal(sent.length, 0, "nothing is sent before the flush");
    flushes[0]();
    assert.deepEqual(sent, [{
        module: "libflutter.so", build_id: "deadbeef0011", size: 0x100000, arch: "arm64",
        functions: { "boringssl.ssl_log_secret": { rva: 0x500, prologue_sha256: "ab".repeat(32) } },
        layout: { "boringssl.ssl_st.s3": 0x30 },
    }]);
});

test("two modules in one burst produce one message each", () => {
    const { cache, sent, flushes } = harness({});
    const a = fakeModule("/x/liba.so", BASE);
    const b = fakeModule("/x/libb.so", BASE + 0x1000_0000);
    cache.reportLearned(a, { layout: { "boringssl.ssl_st.s3": 0x30 } });
    cache.reportLearned(b, { layout: { "boringssl.ssl_st.s3": 0x38 } });
    assert.equal(flushes.length, 1);
    flushes[0]();
    assert.deepEqual(sent.map((m) => m.module), ["liba.so", "libb.so"]);
});

test("items accepted from the cache, already cached, invalid or repeated are not reported", () => {
    const { cache, sent, flushes } = harness();
    const mod = fakeModule();
    const fromCache = cache.learnedFunction(mod, "boringssl.ssl_log_secret")!;
    assert.equal(cache.learnedLayout(mod, "boringssl.ssl_st.s3"), 0x30);
    sent.length = 0;
    cache.reportLearned(mod, {
        functions: { "boringssl.ssl_log_secret": fromCache, "BadName": mod.base.add(0x10), "boringssl.out": mod.base.add(IDENTITY.size) },
        layout: { "boringssl.ssl_st.s3": 0x30, "boringssl.tableRva": 0x2000, "boringssl.huge": 0x200000 },
    });
    flushes.forEach((f) => f());
    assert.deepEqual(sent, [], "nothing new to report");

    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.cr": 0x30 } });
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.cr": 0x30 } });
    flushes.forEach((f) => f());
    assert.equal(sent.length, 1);
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.cr": 0x30 } });
    flushes.forEach((f) => f());
    assert.equal(sent.length, 1, "the same value is reported once per session");
});

test("after a cached layout value is rejected, a different value found live is reported; the stale one is not", () => {
    const { cache, sent, flushes } = harness();
    const mod = fakeModule();
    assert.equal(cache.learnedLayout(mod, "boringssl.ssl_st.s3"), 0x30);
    sent.length = 0;
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.s3": 0x38 } });
    flushes.forEach((f) => f());
    assert.deepEqual(sent, []);
    cache.reject(mod, "layout", "boringssl.ssl_st.s3");
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.s3": 0x30 } });
    cache.reportLearned(mod, { layout: { "boringssl.ssl_st.s3": 0x38 } });
    flushes.forEach((f) => f());
    assert.deepEqual(sent.map((m) => m.layout), [{ "boringssl.ssl_st.s3": 0x38 }]);
});

test("after a verified cached function is rejected, a different address found live is reported", () => {
    const { cache, sent, flushes } = harness();
    const mod = fakeModule();
    assert.notEqual(cache.learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    sent.length = 0;
    cache.reportLearned(mod, { functions: { "boringssl.ssl_log_secret": mod.base.add(0x500) } });
    flushes.forEach((f) => f());
    assert.deepEqual(sent, [], "an item accepted from the cache is not reported");
    cache.reject(mod, "functions", "boringssl.ssl_log_secret");
    cache.reportLearned(mod, { functions: { "boringssl.ssl_log_secret": mod.base.add(0x500) } });
    flushes.forEach((f) => f());
    assert.equal(sent[0].functions?.["boringssl.ssl_log_secret"]?.rva, 0x500);
});

test("hostEntry returns the raw entry for the module's key, else null", () => {
    const { cache } = harness();
    assert.equal(cache.hostEntry(fakeModule())?.module, "libflutter.so");
    assert.equal(cache.hostEntry(fakeModule("/system/lib64/libssl.so")), null);
    assert.equal(harness(hostEntries(), { identify: () => null }).cache.hostEntry(fakeModule()), null);
});

test("memoizePerMapping computes once per name@base", () => {
    const memo = new Map<string, number>();
    let calls = 0;
    const compute = () => ++calls;
    assert.equal(memoizePerMapping(memo, fakeModule(), compute), 1);
    assert.equal(memoizePerMapping(memo, fakeModule(), compute), 1);
    assert.equal(memoizePerMapping(memo, fakeModule("/data/app/lib/arm64/libflutter.so", BASE + 0x1000), compute), 2);
});

test("verifiedLearnedAddress requires an in-module rva, a SHA-256 hex digest and a matching prologue", () => {
    const mod = fakeModule();
    assert.equal((verifiedLearnedAddress(mod, 0x1234, SSL_LOG_SECRET_HASH.toUpperCase(), hashAt) as any)?.value, BASE + 0x1234);
    assert.equal(verifiedLearnedAddress(mod, IDENTITY.size, SSL_LOG_SECRET_HASH, hashAt), null);
    assert.equal(verifiedLearnedAddress(mod, 0, SSL_LOG_SECRET_HASH, hashAt), null);
    assert.equal(verifiedLearnedAddress(mod, 0x1234, "aa", () => "aa"), null);
    assert.equal(verifiedLearnedAddress(mod, 0x1234, "bb".repeat(32), hashAt), null);
});

test("miss markers round-trip through the installed cache", () => {
    const sent: ModuleOffsetsLearnedPayload[] = [];
    try {
        const entries: any = hostEntries();
        entries[KEY].layout["boringssl.miss.ssl_log_secret"] = 1;
        installLearnedModuleCache(entries, { identify: () => IDENTITY, emit: (p) => sent.push(p), schedule: (f) => f() });
        assert.equal(hasLearnedMiss(fakeModule(), "boringssl.miss.ssl_log_secret"), true);
        assert.equal(hasLearnedMiss(fakeModule(), "boringssl.miss.other"), false);
        reportLearnedMiss(fakeModule(), ["quiche.miss.readv"]);
        assert.deepEqual(sent.filter((p) => p.layout).map((p) => p.layout), [{ "quiche.miss.readv": 1 }]);
    } finally {
        installLearnedModuleCache({});
    }
});

test("missFingerprint is stable, order-sensitive and inside 1..MISS_FINGERPRINT_MAX", () => {
    const fp = missFingerprint(["sym", "patterns", "AA BB ?? CC"]);
    assert.equal(fp, missFingerprint(["sym", "patterns", "AA BB ?? CC"]));
    assert.notEqual(fp, missFingerprint(["sym", "patterns", "AA BB ?? CD"]));
    assert.notEqual(missFingerprint(["a", "b"]), missFingerprint(["b", "a"]));
    assert.notEqual(missFingerprint(["ab"]), missFingerprint(["a", "b"]));
    for (const inputs of [[], [""], ["x"], fp.toString().split("")]) {
        const v = missFingerprint(inputs);
        assert.ok(Number.isInteger(v) && v >= 1 && v <= MISS_FINGERPRINT_MAX, `${v}`);
        assert.ok(isValidLayoutValue("quiche.miss.readv", v));
    }
});

test("a miss marker from other scan inputs does not match and its replacement is reported", () => {
    const sent: ModuleOffsetsLearnedPayload[] = [];
    try {
        const entries: any = hostEntries();
        entries[KEY].layout["quiche.miss.readv"] = 0x1234;
        installLearnedModuleCache(entries, { identify: () => IDENTITY, emit: (p) => sent.push(p), schedule: (f) => f() });
        assert.equal(hasLearnedMiss(fakeModule(), "quiche.miss.readv", 0x1234), true);
        assert.equal(hasLearnedMiss(fakeModule(), "quiche.miss.readv", 0x5678), false);
        reportLearnedMiss(fakeModule(), ["quiche.miss.readv"], 0x1234);
        assert.deepEqual(sent.filter((p) => p.layout), [], "the cached value itself is never re-sent");
        reportLearnedMiss(fakeModule(), ["quiche.miss.readv"], 0x5678);
        assert.deepEqual(sent.filter((p) => p.layout).map((p) => p.layout), [{ "quiche.miss.readv": 0x5678 }]);
    } finally {
        installLearnedModuleCache({});
    }
});

test("learnedMissName puts \"miss\" before the last segment (the names hosts already store)", () => {
    assert.equal(learnedMissName("quiche.readv"), "quiche.miss.readv");
    assert.equal(learnedMissName("quiche.frame.CryptoConnect"), "quiche.frame.miss.CryptoConnect");
    assert.equal(learnedMissName("boringssl.ssl_log_secret"), "boringssl.miss.ssl_log_secret");
});

test("reportLearnedMisses records nothing for an incomplete scan", () => {
    const sent: ModuleOffsetsLearnedPayload[] = [];
    try {
        installLearnedModuleCache(hostEntries(), { identify: () => IDENTITY, emit: (p) => sent.push(p), schedule: (f) => f() });
        reportLearnedMisses(fakeModule(), { "quiche.miss.readv": 7 }, { complete: false });
        assert.deepEqual(sent.filter((p) => p.layout), []);
        reportLearnedMisses(fakeModule(), { "quiche.miss.readv": 7 }, { complete: true });
        assert.deepEqual(sent.filter((p) => p.layout).map((p) => p.layout), [{ "quiche.miss.readv": 7 }]);
    } finally {
        installLearnedModuleCache({});
    }
});

test("a module without a build id is never reported", () => {
    const { cache, sent, flushes } = harness({}, { identify: () => null });
    cache.reportLearned(fakeModule(), { layout: { "boringssl.ssl_st.s3": 0x30 } });
    flushes.forEach((f) => f());
    assert.equal(sent.length, 0);
});

test("an accepted cached item sends one cache_hit per module per session; a miss sends none", () => {
    const { cache, sent } = harness();
    const mod = fakeModule();
    cache.learnedFunction(mod, "boringssl.ssl_log_secret");
    cache.learnedLayout(mod, "boringssl.ssl_st.s3");
    assert.deepEqual(sent, [{ module: "libflutter.so", build_id: "deadbeef0011", size: 0x100000, arch: "arm64", cache_hit: true }]);

    const missing = harness(hostEntries(), { hashPrologue: () => "ff".repeat(32) });
    missing.cache.learnedFunction(mod, "boringssl.ssl_log_secret");
    assert.deepEqual(missing.sent, []);
});

test("the installed instance backs the module-level API and sends module_offsets_learned", async () => {
    const messages: any[] = [];
    const originalSend = G.send;
    G.send = (message: any) => { if (message?.contentType === "module_offsets_learned") messages.push(message); };
    try {
        installLearnedModuleCache(hostEntries(), { identify: () => IDENTITY, hashPrologue: hashAt });
        const mod = fakeModule();
        assert.equal((learnedFunction(mod, "boringssl.ssl_log_secret") as any)?.value, BASE + 0x1234);
        assert.equal(learnedLayout(mod, "boringssl.ssl_st.s3"), 0x30);
        reportLearned(mod, { layout: { "boringssl.ssl_st.cr": 0x30 } });
        reportLearned(mod, { layout: { "boringssl.ssl_st.ctx": 0x68 } });
        await new Promise((resolve) => setTimeout(resolve, 120));
        assert.equal(messages.length, 2);
        assert.equal(messages[0].cache_hit, true);
        assert.equal(messages[0].protocol, "tls");
        assert.deepEqual(messages[1].layout, { "boringssl.ssl_st.cr": 0x30, "boringssl.ssl_st.ctx": 0x68 });
        assert.equal(messages[1].cache_hit, undefined);

        installLearnedModuleCache("not an object");
        assert.equal(learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    } finally {
        G.send = originalSend;
        installLearnedModuleCache({});
    }
});


// ---- hook-proof hash window ----------------------------------------------------

class BytePtr {
    constructor(readonly bytes: Uint8Array, readonly offset = 0) {}
    add(n: any): BytePtr { return new BytePtr(this.bytes, this.offset + Number(n?.value ?? n)); }
    readByteArray(length: number): ArrayBuffer {
        if (this.offset + length > this.bytes.length) throw new Error("access violation");
        return this.bytes.slice(this.offset, this.offset + length).buffer;
    }
}

function withRealChecksum(body: () => void): void {
    const original = G.Checksum;
    G.Checksum = { compute: (_alg: string, bytes: ArrayBuffer) => createHash("sha256").update(Buffer.from(bytes)).digest("hex") };
    try { body(); } finally { G.Checksum = original; }
}

function codeBytes(): Uint8Array {
    return Uint8Array.from({ length: 96 }, (_, i) => (i * 7 + 3) & 0xff);
}

test("sha256FunctionBody ignores a trampoline over the first 32 bytes", () => withRealChecksum(() => {
    const clean = codeBytes();
    const hooked = codeBytes();
    hooked.fill(0xcc, 0, 30);   // x86 worst case: 16-byte redirect + nop padding
    const hash = sha256FunctionBody(new BytePtr(clean) as any);
    assert.match(hash ?? "", /^[0-9a-f]{64}$/);
    assert.equal(sha256FunctionBody(new BytePtr(hooked) as any), hash);
    assert.notEqual(sha256Prologue(new BytePtr(hooked) as any), sha256Prologue(new BytePtr(clean) as any));
}));

test("sha256FunctionBody changes when bytes inside the window differ", () => withRealChecksum(() => {
    for (const index of [32, 47, 63]) {
        const changed = codeBytes();
        changed[index] ^= 0xff;
        assert.notEqual(sha256FunctionBody(new BytePtr(changed) as any), sha256FunctionBody(new BytePtr(codeBytes()) as any));
    }
}));

test("sha256FunctionBody is null for an unreadable window", () => withRealChecksum(() => {
    assert.equal(sha256FunctionBody(new BytePtr(new Uint8Array(48)) as any), null);
}));

test("a function reported while hooked verifies against its clean bytes", () => withRealChecksum(() => {
    const hooked = codeBytes();
    hooked.fill(0xcc, 0, 16);   // arm64 Interceptor redirect
    const reportedHash = sha256FunctionBody(new BytePtr(hooked) as any);
    const cleanModule: any = { name: "m", size: 0x1000, base: { add: () => new BytePtr(codeBytes()) } };
    assert.notEqual(verifiedLearnedAddress(cleanModule, 0x10, reportedHash, sha256FunctionBody), null);
}));

test("isCacheable: a module with a build identity is cacheable, one without (or a throwing identify) is not", () => {
    assert.equal(harness().cache.isCacheable(fakeModule()), true);
    assert.equal(harness(hostEntries(), { identify: () => null }).cache.isCacheable(fakeModule()), false);
    assert.equal(harness(hostEntries(), { identify: () => { throw new Error("unreadable"); } }).cache.isCacheable(fakeModule()), false);
});
