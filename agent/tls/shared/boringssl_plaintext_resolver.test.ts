// Run: npm run test:agent
//
// Source order of resolveBoringSslPlaintext: --offsets > learned cache
// (prologue-verified) > locator, per function, with one miss notice per module
// (arm64 only); even addresses are never hooked on 32-bit ARM (Thumb).

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    resolveBoringSslPlaintext, plaintextApiFromOffsets, plaintextApiFromLearned, prologueMatches,
    PlaintextResolverDeps, LearnedPlaintextEntry, BORINGSECRETHUNTER_DOCS, isHookableAddress,
} from "./boringssl_plaintext_resolver.js";

const G = globalThis as any;

function tagged(tag: string): any {
    return { tag, isNull: () => false, add: (n: any) => tagged(`${tag}+${n?.tag ?? n}`) };
}

function fakeModule(name: string, exportsNames: string[] = []): any {
    return {
        name,
        base: tagged("base"),
        size: 0x100000,
        findExportByName: (n: string) => (exportsNames.includes(n) ? tagged(`export:${n}`) : null),
    };
}

/** Real-looking ptr(): keeps the parsed value visible to the assertions. */
function withTaggedPtr<T>(fn: () => T): T {
    const original = G.ptr;
    G.ptr = (v: any) => tagged(`ptr:${v}`);
    try { return fn(); } finally { G.ptr = original; }
}

const LEARNED: LearnedPlaintextEntry = {
    rvas: { SSL_read: 0x100, SSL_write: 0x200 },
    prologueSha256: { SSL_read: "AA".repeat(32), SSL_write: "bb".repeat(32) },
};
const MATCHING_HASHES = (address: any) => ({ "base+256": "aa".repeat(32), "base+512": "BB".repeat(32) } as any)[address.tag] ?? null;

function deps(over: Partial<PlaintextResolverDeps> & { calls?: string[] } = {}): Partial<PlaintextResolverDeps> {
    const calls = over.calls ?? [];
    return {
        readOffsets: () => "{OFFSETS}",
        learned: { lookup: () => null },
        hashPrologue: MATCHING_HASHES,
        locate: async () => { calls.push("locate"); return { sslRead: tagged("loc:read"), sslWrite: tagged("loc:write") }; },
        onLocatorResolved: () => { calls.push("onLocatorResolved"); },
        locatorRuns: () => true,
        warn: (m: string) => { calls.push(`warn:${m}`); },
        now: () => 0,
        ...over,
    };
}

test("exports are not a source: callers filter exporting modules first", async () => {
    const calls: string[] = [];
    const api = await resolveBoringSslPlaintext(fakeModule("libcronet.so", ["SSL_read", "SSL_write"]), deps({ calls }));
    assert.equal(api?.source, "locator");
    assert.deepEqual(calls, ["locate", "onLocatorResolved"]);
});

test("--offsets keyed by module basename beat the learned cache and the locator", async () => {
    const calls: string[] = [];
    const api = await withTaggedPtr(() => resolveBoringSslPlaintext(fakeModule("libflutter.so"), deps({
        calls,
        readOffsets: () => ({ "libflutter.so": {
            SSL_read: { address: "0x10", absolute: false }, SSL_write: { address: "0x7000", absolute: true } } }),
        learned: { lookup: () => LEARNED },
    })));
    assert.equal(api?.source, "offsets");
    assert.equal(api?.sslRead.tag, "base+ptr:0x10");
    assert.equal(api?.sslWrite.tag, "ptr:0x7000");
    assert.deepEqual(calls, []);
});

test("plaintextApiFromOffsets ignores the placeholder, other keys and full paths' directories", () => {
    withTaggedPtr(() => {
        assert.equal(plaintextApiFromOffsets("{OFFSETS}", fakeModule("libx.so")), null);
        assert.equal(plaintextApiFromOffsets({ openssl: { SSL_read: { address: "0x1" } } }, fakeModule("libx.so")), null);
        const api = plaintextApiFromOffsets({ "libx.so": { SSL_write: { address: "0x2", absolute: false } } },
                                            fakeModule("/data/app/lib/libx.so"));
        assert.equal(api?.sslRead, null);
        assert.equal(api?.sslWrite.tag, "base+ptr:0x2");
    });
});

test("a prologue-verified learned entry beats the locator", async () => {
    const calls: string[] = [];
    const api = await resolveBoringSslPlaintext(fakeModule("libmonochrome.so"),
                                                deps({ calls, learned: { lookup: () => LEARNED } }));
    assert.equal(api?.source, "learned");
    assert.equal(api?.sslRead.tag, "base+256");
    assert.equal(api?.sslWrite.tag, "base+512");
    assert.deepEqual(calls, []);
});

test("a learned prologue mismatch falls through to the locator", async () => {
    const calls: string[] = [];
    const stale = { ...LEARNED, prologueSha256: { SSL_read: "aa".repeat(32), SSL_write: "cc".repeat(32) } };
    const api = await resolveBoringSslPlaintext(fakeModule("libchrome.so"),
                                                deps({ calls, learned: { lookup: () => stale } }));
    assert.equal(api?.source, "locator");
    assert.deepEqual(calls, ["locate", "onLocatorResolved"]);
});

test("plaintextApiFromLearned rejects entries without a hash or with an unreadable prologue", () => {
    const mod = fakeModule("libx.so");
    // The host only sends complete entries; anything partial is rejected here too.
    assert.equal(plaintextApiFromLearned({ rvas: { SSL_read: 0x100 }, prologueSha256: { SSL_read: "AA".repeat(32) } } as any,
                                         mod, MATCHING_HASHES), null);
    assert.equal(plaintextApiFromLearned(LEARNED, mod, () => null), null);
    assert.equal(prologueMatches(mod, 0x100, "AA".repeat(32), MATCHING_HASHES), true);
    assert.equal(prologueMatches(mod, 0x100, "ab".repeat(32), MATCHING_HASHES), false);
});

test("onLocatorResolved receives the module, API and elapsed time only on locator hits", async () => {
    const seen: any[] = [];
    let clock = 1000;
    const mod = fakeModule("libwebviewchromium.so");
    const api = await resolveBoringSslPlaintext(mod, deps({
        now: () => (clock += 25),
        onLocatorResolved: (m, a, ms) => { seen.push([m, a.sslRead.tag, ms]); },
    }));
    assert.equal(api?.source, "locator");
    assert.deepEqual(seen, [[mod, "loc:read", 25]]);

    seen.length = 0;
    await resolveBoringSslPlaintext(fakeModule("libothermiss.so"), deps({
        locate: async () => ({ sslRead: null, sslWrite: null }),
        onLocatorResolved: () => { seen.push("called"); },
        warn: () => {},
    }));
    assert.deepEqual(seen, []);
});

test("a miss warns once per module, naming it and the BoringSecretHunter docs", async () => {
    const warnings: string[] = [];
    const miss = deps({ locate: async () => null, warn: (m) => { warnings.push(m); } });
    assert.equal(await resolveBoringSslPlaintext(fakeModule("libmissing.so"), miss), null);
    assert.equal(await resolveBoringSslPlaintext(fakeModule("libmissing.so"), miss), null);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /libmissing\.so/);
    assert.ok(warnings[0].includes(BORINGSECRETHUNTER_DOCS));
    await resolveBoringSslPlaintext(fakeModule("libmissing2.so"), miss);
    assert.equal(warnings.length, 2);
});

test("a throwing locator is a miss, not a rejection", async () => {
    const warnings: string[] = [];
    const api = await resolveBoringSslPlaintext(fakeModule("libthrows.so"), deps({
        locate: async () => { throw new Error("boom"); }, warn: (m) => { warnings.push(m); },
    }));
    assert.equal(api, null);
    assert.equal(warnings.length, 1);
});

test("a miss where the locator cannot run (non-arm64) is debug-logged, not warned", async () => {
    const warnings: string[] = [];
    const api = await resolveBoringSslPlaintext(fakeModule("libx64miss.so"), deps({
        locate: async () => null, locatorRuns: () => false, warn: (m) => { warnings.push(m); },
    }));
    assert.equal(api, null);
    assert.deepEqual(warnings, []);
});

const WRITE_ONLY_OFFSETS = () => ({ "libpartial.so": { SSL_write: { address: "0x7001", absolute: true } } });

test("partial --offsets: the missing function falls through to the learned cache", async () => {
    const calls: string[] = [];
    const api = await withTaggedPtr(() => resolveBoringSslPlaintext(fakeModule("libpartial.so"), deps({
        calls, readOffsets: WRITE_ONLY_OFFSETS, learned: { lookup: () => LEARNED },
    })));
    assert.equal(api?.source, "mixed");
    assert.deepEqual(api?.sources, { SSL_read: "learned", SSL_write: "offsets" });
    assert.equal(api?.sslRead.tag, "base+256");
    assert.equal(api?.sslWrite.tag, "ptr:0x7001");
    assert.deepEqual(calls, [], "nothing is missing after the learned cache, so the locator must not run");
});

test("partial --offsets: the missing function falls through to the locator", async () => {
    const calls: string[] = [];
    const api = await withTaggedPtr(() => resolveBoringSslPlaintext(fakeModule("libpartial.so"), deps({
        calls, readOffsets: WRITE_ONLY_OFFSETS,
    })));
    assert.equal(api?.source, "mixed");
    assert.deepEqual(api?.sources, { SSL_read: "locator", SSL_write: "offsets" });
    assert.equal(api?.sslRead.tag, "loc:read");
    assert.equal(api?.sslWrite.tag, "ptr:0x7001", "--offsets keep priority over the locator");
    assert.deepEqual(calls, ["locate", "onLocatorResolved"]);
});

test("a single-source result reports that source for both functions", async () => {
    const api = await resolveBoringSslPlaintext(fakeModule("libsingle.so"), deps({ learned: { lookup: () => LEARNED } }));
    assert.equal(api?.source, "learned");
    assert.deepEqual(api?.sources, { SSL_read: "learned", SSL_write: "learned" });
});

test("an accepted learned entry is reported through onAccepted (cache hit); a stale one is not", async () => {
    const accepted: any[] = [];
    const learned = { lookup: () => LEARNED, onAccepted: (m: any, e: any) => { accepted.push([m.name, e]); } };
    await resolveBoringSslPlaintext(fakeModule("libhit.so"), deps({ learned }));
    assert.deepEqual(accepted, [["libhit.so", LEARNED]]);
    accepted.length = 0;
    await resolveBoringSslPlaintext(fakeModule("libstale.so"), deps({ learned, hashPrologue: () => "zz" }));
    assert.deepEqual(accepted, []);
});

/** NativePointer-like value whose low bit is visible to isHookableAddress. */
function numericPtr(value: number): any {
    return { value, tag: `num:${value.toString(16)}`, isNull: () => value === 0,
        and: (m: number) => numericPtr(value & m), add: (n: any) => numericPtr(value + Number(n?.value ?? n)),
        toString: () => `0x${value.toString(16)}` };
}

test("32-bit ARM: an even --offsets address is refused with a Thumb hint; an odd one is used as is", async () => {
    const calls: string[] = [];
    const original = G.ptr;
    G.ptr = (v: any) => numericPtr(Number(v));
    try {
        const api = await resolveBoringSslPlaintext(fakeModule("libthumb.so"), deps({
            calls, arch: () => "arm", locatorRuns: () => false, locate: async () => null,
            readOffsets: () => ({ "libthumb.so": { SSL_read: { address: "0x4000", absolute: true },
                                                   SSL_write: { address: "0x5001", absolute: true } } }),
        }));
        assert.equal(api?.sslRead, null);
        assert.equal(api?.sslWrite.value, 0x5001);
        assert.equal(api?.source, "offsets");
        const warnings = calls.filter((c) => c.startsWith("warn:"));
        assert.equal(warnings.length, 1);
        assert.match(warnings[0], /libthumb\.so.*SSL_read.*0x4000.*address\|1/);
    } finally {
        G.ptr = original;
    }
});

test("32-bit ARM: even learned/locator addresses are never hooked either", async () => {
    const mod = { ...fakeModule("libthumb2.so"), base: numericPtr(0x10000) };
    const evenLearned = { rvas: { SSL_read: 0x100, SSL_write: 0x201 }, prologueSha256: { SSL_read: "aa".repeat(32), SSL_write: "aa".repeat(32) } };
    const api = await resolveBoringSslPlaintext(mod, deps({
        arch: () => "arm", hashPrologue: () => "aa".repeat(32), learned: { lookup: () => evenLearned },
        locate: async () => ({ sslRead: numericPtr(0x10400), sslWrite: null }), warn: () => {},
    }));
    assert.equal(api?.sslRead, null);
    assert.equal(api?.sslWrite.value, 0x10201);
    assert.equal(api?.source, "learned");
});

test("isHookableAddress only constrains 32-bit ARM", () => {
    assert.equal(isHookableAddress(numericPtr(0x1000), "arm64"), true);
    assert.equal(isHookableAddress(numericPtr(0x1000), "arm"), false);
    assert.equal(isHookableAddress(numericPtr(0x1001), "arm"), true);
});
