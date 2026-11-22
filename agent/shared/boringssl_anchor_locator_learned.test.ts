// Run: npm run test:agent
//
// locateSslLogSecretCached() consults the learned-offsets cache before the
// label-xref scan: a prologue-verified entry that still decodes skips the scan;
// a stale or undecodable one falls back to it, and a scan hit is reported. A
// clean scan miss is recorded as a miss marker, which later skips the scan.

import { test } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

const G = globalThis as any;
G.send = G.send ?? ((_msg: any) => { });

import {
    BORINGSSL_KEYLOG_LABELS, LEARNED_SSL_LOG_SECRET, LEARNED_SSL_LOG_SECRET_MISS, LOCATOR_REVISION,
    SSL_LOG_SECRET_MISS_FINGERPRINT, SslLogSecretSources, decodeCtxKeylogOffsets, decodeSslLayoutFromWords,
    DECODE_UNREADABLE, locateSslLogSecretCached, memoizedCtxKeylogOffsets, reportDecodedSslLogSecret,
    validatedLearnedSslLogSecret,
} from "./boringssl_anchor_locator.js";
import { installLearnedModuleCache, missFingerprint } from "./learned_module_cache.js";

class FakePtr {
    constructor(readonly value: number) {}
    add(n: any): FakePtr { return new FakePtr(this.value + Number(n?.value ?? n)); }
    sub(other: any): FakePtr { return new FakePtr(this.value - Number(other?.value ?? other)); }
    and(n: any): FakePtr { return new FakePtr(this.value & Number(n?.value ?? n)); }
    isNull(): boolean { return this.value === 0; }
    toString(): string { return "0x" + this.value.toString(16); }
}

const IDENTITY = { buildId: "deadbeef0011", size: 0x100000, arch: "arm64" };
const KEY = "deadbeef0011|1048576|arm64";
const HASH = "aa".repeat(32);
let nextBase = 0x7000_0000;

/** A fresh mapping per test: the locator memoizes per name@base. */
function fakeModule(): any {
    nextBase += 0x1000_0000;
    return { name: "/data/app/lib/arm64/libflutter.so", base: new FakePtr(nextBase), size: IDENTITY.size };
}

interface Recorder { scans: number; reported: any[] }

/** Install a host cache with ssl_log_secret at rva 0x1234 (and the miss marker when `miss`). */
function installCache(hashPrologue: (a: any) => string | null, miss = false,
                      missMarker = SSL_LOG_SECRET_MISS_FINGERPRINT): Recorder {
    const rec: Recorder = { scans: 0, reported: [] };
    installLearnedModuleCache({
        [KEY]: { module: "libflutter.so", functions: { [LEARNED_SSL_LOG_SECRET]: { rva: 0x1234, prologue_sha256: HASH } },
                 layout: miss ? { [LEARNED_SSL_LOG_SECRET_MISS]: missMarker } : {} },
    }, { identify: () => IDENTITY, hashPrologue, emit: (p) => { if (p.cache_hit !== true) rec.reported.push(p); },
         schedule: (flush) => flush() });
    return rec;
}

function sources(rec: Recorder, over: Partial<SslLogSecretSources> = {}): SslLogSecretSources {
    return {
        decodes: () => true,
        scan: async (m) => { rec.scans++; return { found: m.base.add(0x5678), missIsReliable: true }; },
        ...over,
    };
}

const reportedRvas = (rec: Recorder) => rec.reported.map((p) => p.functions?.[LEARNED_SSL_LOG_SECRET]?.rva);

test("a verified, decodable cache entry is used and the scan is skipped", async () => {
    const mod = fakeModule();
    const rec = installCache(() => HASH);
    const fnAddr: any = await locateSslLogSecretCached(mod, "libflutter.so", sources(rec));
    assert.equal(fnAddr.value, mod.base.value + 0x1234);
    assert.equal(rec.scans, 0);
    assert.deepEqual(rec.reported, [], "a cache-sourced address is never reported");
});

test("a prologue-hash mismatch falls back to the scan, whose hit is reported", async () => {
    const mod = fakeModule();
    const rec = installCache(() => "ff".repeat(32));
    const fnAddr: any = await locateSslLogSecretCached(mod, "libflutter.so", sources(rec));
    assert.equal(fnAddr.value, mod.base.value + 0x5678);
    assert.equal(rec.scans, 1);
    assert.deepEqual(reportedRvas(rec), [0x5678]);
});

test("a cache hit that no longer decodes falls back to the scan", async () => {
    const mod = fakeModule();
    const cachedAt = mod.base.value + 0x1234;
    const rec = installCache(() => HASH);
    const fnAddr: any = await locateSslLogSecretCached(mod, "libflutter.so",
        sources(rec, { decodes: (a: any) => a.value !== cachedAt }));
    assert.equal(fnAddr.value, mod.base.value + 0x5678);
    assert.equal(rec.scans, 1);
    assert.deepEqual(reportedRvas(rec), [0x5678]);
});

test("a scan hit that does not decode is neither reported nor recorded as a miss", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null);
    assert.notEqual(await locateSslLogSecretCached(mod, "libflutter.so", sources(rec, { decodes: () => false })), null);
    assert.deepEqual(rec.reported, []);
});

const cleanMiss = async () => ({ found: null, missIsReliable: true });

test("the miss fingerprint covers the label list and the locator revision", () => {
    assert.equal(SSL_LOG_SECRET_MISS_FINGERPRINT,
        missFingerprint(["labels", ...BORINGSSL_KEYLOG_LABELS, "revision", String(LOCATOR_REVISION)]));
    assert.notEqual(SSL_LOG_SECRET_MISS_FINGERPRINT,
        missFingerprint(["labels", ...BORINGSSL_KEYLOG_LABELS, "revision", String(LOCATOR_REVISION + 1)]));
});

test("a clean scan miss resolves null and records the fingerprinted miss marker", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null);
    assert.equal(await locateSslLogSecretCached(mod, "libflutter.so", sources(rec, { scan: cleanMiss })), null);
    assert.deepEqual(rec.reported.map((p) => p.layout), [{ [LEARNED_SSL_LOG_SECRET_MISS]: SSL_LOG_SECRET_MISS_FINGERPRINT }]);
});

test("an unreliable scan miss (no label strings, or read errors) records no marker", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null);
    assert.equal(await locateSslLogSecretCached(mod, "libflutter.so",
        sources(rec, { scan: async () => ({ found: null, missIsReliable: false }) })), null);
    assert.deepEqual(rec.reported, []);
});

test("a marker from another locator revision is stale: the build is rescanned", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null, true, 1);
    await locateSslLogSecretCached(mod, "libflutter.so", sources(rec, { scan: async () => { rec.scans++; return cleanMiss(); } }));
    assert.equal(rec.scans, 1);
    assert.deepEqual(rec.reported.map((p) => p.layout), [{ [LEARNED_SSL_LOG_SECRET_MISS]: SSL_LOG_SECRET_MISS_FINGERPRINT }]);
});

test("ctx/keylog offsets are memoized per mapping: another library at the same base re-decodes", () => {
    const base = new FakePtr(0x6000_0000);
    const libA: any = { name: "/system/lib64/liba.so", base, size: 0x1000 };
    const libB: any = { name: "/system/lib64/libb.so", base, size: 0x1000 };
    const fnAddr: any = base.add(0x100);
    let decodes = 0;
    const decode = (off: number) => () => { decodes++; return { ctxOff: off, cbOff: 0x250 }; };
    assert.equal(memoizedCtxKeylogOffsets(libA, fnAddr, decode(0x68))?.ctxOff, 0x68);
    assert.equal(memoizedCtxKeylogOffsets(libA, fnAddr, decode(0x99))?.ctxOff, 0x68, "same mapping: memoized");
    assert.equal(memoizedCtxKeylogOffsets(libB, fnAddr, decode(0x30))?.ctxOff, 0x30, "new mapping: re-decoded");
    assert.equal(decodes, 2);
});

test("a ctx/keylog decode miss is memoized too", () => {
    const lib: any = { name: "/system/lib64/libmiss.so", base: new FakePtr(0x6100_0000), size: 0x1000 };
    const fnAddr: any = lib.base.add(0x100);
    let decodes = 0;
    const miss = () => { decodes++; return null; };
    assert.equal(memoizedCtxKeylogOffsets(lib, fnAddr, miss), null);
    assert.equal(memoizedCtxKeylogOffsets(lib, fnAddr, () => ({ ctxOff: 0x68, cbOff: 0x250 })), null);
    assert.equal(decodes, 1);
});

test("a recorded miss marker skips the scan", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null, true);
    assert.equal(await locateSslLogSecretCached(mod, "libflutter.so", sources(rec)), null);
    assert.equal(rec.scans, 0);
    assert.deepEqual(rec.reported, []);
});

test("a scan that throws records no miss marker", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null);
    await assert.rejects(locateSslLogSecretCached(mod, "libflutter.so",
        sources(rec, { scan: async () => { throw new Error("xref scan aborted"); } })));
    assert.deepEqual(rec.reported, []);
});

test("the lookup is memoized per mapping: concurrent callers share one scan", async () => {
    const mod = fakeModule();
    const rec = installCache(() => null);
    const src = sources(rec);
    const [a, b]: any[] = await Promise.all([
        locateSslLogSecretCached(mod, "libflutter.so", src), locateSslLogSecretCached(mod, "libflutter.so", src),
    ]);
    assert.equal(a.value, b.value);
    assert.equal(rec.scans, 1);
});

// libsignal_jni.so (Signal 8.x arm64) ssl_log_secret, first 60 words: the stack
// protector pushes the keylog_callback cbz to word 12, past the ctx prologue window.
const LIBSIGNAL_SSL_LOG_SECRET_WORDS = [
    0xd10283ff, 0xa9057bfd, 0xf90033f9, 0xa9075ff8, 0xa90857f6, 0xa9094ff4,
    0x910143fd, 0xd53bd059, 0xf9401728, 0xf81f83a8, 0xf9403408, 0xf9413508,
    0xb4000ae8, 0xaa0003f3, 0xaa0103e0, 0xaa0303f4, 0xaa0203f5, 0xaa0103f6,
    0xa9007fff, 0x9400a2db, 0xaa0003f7, 0xaa1603e0, 0x9400a2d8, 0x6f00e400,
    0x8b140408, 0x91010d18, 0xaa1803e0, 0xad0083e0, 0x3d800fe0, 0x97fef875,
    0xb4000058, 0xb4000720, 0xa9027fe0, 0x52800028, 0x910043e0, 0xd10043a1,
    0xaa1703e2, 0x390063ff, 0xf9000bff, 0xf9001bf8, 0x3900e3e8, 0x97fe9550,
    0x340005c0, 0xb40000b7, 0xf85f03a0, 0xaa1603e1, 0xaa1703e2, 0x9400a28f,
    0x910043e0, 0x52800401, 0x52800022, 0x97fe958a, 0x34000480, 0xf9401a68,
    0x910043e0, 0x9100c101, 0x52800402, 0xaa1f03f6, 0x94000046, 0x360003a0,
];

test("libsignal_jni ssl_log_secret: ctx prologue misses, the s3/cr layout still decodes", () => {
    assert.equal(decodeCtxKeylogOffsets(LIBSIGNAL_SSL_LOG_SECRET_WORDS.slice(0, 12)), null);
    assert.deepEqual(decodeSslLayoutFromWords(LIBSIGNAL_SSL_LOG_SECRET_WORDS),
        { s3Off: 0x30, crOff: 0x30, lengthArgSeen: true, ctxOff: null });
});

test("an unreadable ctx/keylog decode is not memoized: a later readable decode still runs", () => {
    const lib: any = { name: "/system/lib64/libflaky.so", base: new FakePtr(0x6200_0000), size: 0x1000 };
    const fnAddr: any = lib.base.add(0x100);
    assert.equal(memoizedCtxKeylogOffsets(lib, fnAddr, () => DECODE_UNREADABLE), DECODE_UNREADABLE);
    assert.equal((memoizedCtxKeylogOffsets(lib, fnAddr, () => ({ ctxOff: 0x68, cbOff: 0x250 })) as any).ctxOff, 0x68);
});

test("an unreadable learned entry is scanned past but not rejected; an undecodable one is", () => {
    const mod = fakeModule();
    const rec = installCache(() => HASH);
    const other = mod.base.add(0x5678);
    assert.equal(validatedLearnedSslLogSecret(mod, () => null, "t"), null, "unknown: scan instead");
    // Still accepted from the cache, so a scan hit elsewhere is not reported over it.
    reportDecodedSslLogSecret(mod, other as any, () => true);
    assert.deepEqual(reportedRvas(rec), []);
    assert.equal(validatedLearnedSslLogSecret(mod, () => false, "t"), null);
    reportDecodedSslLogSecret(mod, other as any, () => true);
    assert.deepEqual(reportedRvas(rec), [0x5678], "rejected: the scan hit is reported");
});
