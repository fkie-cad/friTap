// Run: npm run test:agent
//
// Learned plaintext-RVA cache, agent side: host entries are looked up by
// `build_id|size|arch` in the installed LearnedModuleCache; locator hits on a
// module with a build id are reported back as `plaintext_api_learned`, accepted
// entries as that cache's (once per module) cache hit.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import { readFileSync } from "node:fs";
import {
    createLearnedPlaintextSource, createLocatorReporter, installLearnedPlaintextCache,
    learnedKey, learnedMessage, toLearnedEntry, ModuleIdentity,
} from "./learned_plaintext_cache.js";
import { ModuleOffsetsLearnedPayload, PlaintextApiLearnedPayload } from "../../shared/shared_structures.js";
import { LearnedModuleCacheDeps, installLearnedModuleCache, learnedFunction } from "../../shared/learned_module_cache.js";
import {
    resolveBoringSslPlaintext, setLearnedPlaintextSource, setLocatorResolvedListener, PlaintextResolverDeps,
} from "./boringssl_plaintext_resolver.js";

const G = globalThis as any;
const IDENTITY: ModuleIdentity = { buildId: "deadbeef0011", size: 0x100000, arch: "arm64" };
const KEY = "deadbeef0011|1048576|arm64";
const HOST_ENTRY = { module: "libcronet.so", rvas: { SSL_read: 0x100, SSL_write: 0x200 },
    prologue_sha256: { SSL_read: "aa".repeat(32), SSL_write: "bb".repeat(32) } };

/** Minimal NativePointer over a numeric address; reads come from `memory`. */
class FakePtr {
    constructor(readonly value: number, readonly memory: Uint8Array | null = null) {}
    add(n: any): FakePtr { return new FakePtr(this.value + Number(n?.value ?? n), this.memory); }
    sub(other: any): FakePtr { return new FakePtr(this.value - Number(other?.value ?? other), this.memory); }
    isNull(): boolean { return this.value === 0; }
    toString(): string { return "0x" + this.value.toString(16); }
    readByteArray(length: number): ArrayBuffer | null {
        if (this.memory === null) throw new Error("access violation");
        const offset = this.value - 0x7000_0000;
        if (offset < 0 || offset + length > this.memory.length) throw new Error("access violation");
        return this.memory.slice(offset, offset + length).buffer;
    }
}

function fakeModule(memory: Uint8Array | null = null, size = IDENTITY.size): any {
    return { name: "/data/app/lib/arm64/libcronet.so", base: new FakePtr(0x7000_0000, memory), size,
        findExportByName: () => null };
}

const HASHES = (address: any) => (address.value === 0x7000_0100 ? "AA".repeat(32) : "BB".repeat(32));
const LOCATED = (mod: any) => ({ sslRead: mod.base.add(0x100), sslWrite: mod.base.add(0x200) });

/** ELF64 LE image with one PT_NOTE carrying NT_GNU_BUILD_ID deadbeef0011. */
function elfWithBuildId(): Uint8Array {
    const image = new Uint8Array(0x300);
    const dv = new DataView(image.buffer);
    image.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
    dv.setBigUint64(0x20, 0x40n, true);
    dv.setUint16(0x36, 0x38, true);
    dv.setUint16(0x38, 1, true);
    dv.setUint32(0x40, 4, true);
    dv.setBigUint64(0x50, 0x200n, true);
    dv.setBigUint64(0x60, 24n, true);
    dv.setUint32(0x200, 4, true);
    dv.setUint32(0x204, 6, true);
    dv.setUint32(0x208, 3, true);
    image.set([0x47, 0x4e, 0x55, 0, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11], 0x20c);
    return image;
}

/** Install the shared module cache over `entries`; returns the payloads it emits. */
function installHostEntries(entries: unknown, over: Partial<LearnedModuleCacheDeps> = {}): ModuleOffsetsLearnedPayload[] {
    const sent: ModuleOffsetsLearnedPayload[] = [];
    installLearnedModuleCache(entries, { identify: () => IDENTITY, hashPrologue: HASHES, emit: (p) => sent.push(p),
        schedule: (flush) => flush(), ...over });
    return sent;
}

function resolverDeps(over: Partial<PlaintextResolverDeps> = {}): Partial<PlaintextResolverDeps> {
    return { readOffsets: () => "{OFFSETS}", hashPrologue: HASHES, locate: async (m) => LOCATED(m),
        warn: () => {}, now: () => 0, ...over };
}

test("learnedKey matches the host's make_key format", () => {
    assert.equal(learnedKey(IDENTITY), KEY);
});

// Shared with the host's make_key test, so both sides must agree on every case.
const KEY_CASES_PATH = new URL("../../../tests/fixtures/learned_offsets_key_cases.json", import.meta.url);

test("learnedKey reproduces every case of the shared cross-language key fixture", () => {
    const cases: { build_id: string; size: number; arch: string; key: string }[] =
        JSON.parse(readFileSync(KEY_CASES_PATH, "utf8"));
    assert.deepEqual([...new Set(cases.map((c) => c.arch))].sort(), ["arm", "arm64", "ia32", "x64"]);
    for (const c of cases) {
        assert.equal(learnedKey({ buildId: c.build_id, size: c.size, arch: c.arch }), c.key);
    }
});

test("lookup returns the entry for the module's build_id|size|arch key", () => {
    installHostEntries({ [KEY]: HOST_ENTRY });
    assert.deepEqual(createLearnedPlaintextSource().lookup(fakeModule()), {
        rvas: { SSL_read: 0x100, SSL_write: 0x200 },
        prologueSha256: { SSL_read: "aa".repeat(32), SSL_write: "bb".repeat(32) },
    });
});

test("lookup misses on another size/arch, an unknown build id, or no entries", () => {
    const entries = { [KEY]: HOST_ENTRY };
    const lookupWith = (identify: LearnedModuleCacheDeps["identify"]) => {
        installHostEntries(entries, { identify });
        return createLearnedPlaintextSource().lookup(fakeModule());
    };
    assert.equal(lookupWith(() => ({ ...IDENTITY, size: 1 })), null);
    assert.equal(lookupWith(() => ({ ...IDENTITY, arch: "x64" })), null);
    assert.equal(lookupWith(() => null), null);
    let identified = false;
    installHostEntries({}, { identify: () => { identified = true; return IDENTITY; } });
    createLearnedPlaintextSource().lookup(fakeModule());
    assert.equal(identified, false, "an empty cache must not parse the module's ELF headers");
});

test("lookup skips modules no entry was learned for, before parsing their build id", () => {
    let identified = false;
    installHostEntries({ [KEY]: HOST_ENTRY }, { identify: () => { identified = true; return IDENTITY; } });
    assert.equal(createLearnedPlaintextSource().lookup({ ...fakeModule(), name: "/system/lib64/libflutter.so" }), null);
    assert.equal(identified, false, "an unrelated module must not have its ELF headers parsed");
});

test("malformed or partial host entries are rejected", () => {
    const size = IDENTITY.size;
    assert.notEqual(toLearnedEntry(HOST_ENTRY, size), null);
    assert.equal(toLearnedEntry(null, size), null);
    assert.equal(toLearnedEntry({ rvas: { SSL_read: -1, SSL_write: "0x200" } }, size), null);
    assert.equal(toLearnedEntry({ rvas: { SSL_read: 0x100 }, prologue_sha256: { SSL_read: "aa" } }, size), null);
    assert.equal(toLearnedEntry({ ...HOST_ENTRY, prologue_sha256: { SSL_read: "aa".repeat(32), SSL_write: 7 } }, size), null);
    assert.equal(toLearnedEntry({ ...HOST_ENTRY, prologue_sha256: { SSL_read: "aa", SSL_write: "bb" } }, size), null,
        "hashes must be SHA-256 hex digests, as the host validates them");
    assert.equal(toLearnedEntry({ ...HOST_ENTRY, rvas: { SSL_read: 0x100, SSL_write: size } }, size), null,
        "rvas must lie inside the module");
});

test("a non-object host config means no entries", async () => {
    try {
        installLearnedPlaintextCache();
        for (const raw of [undefined, "{}", [1]]) {
            installHostEntries(raw);
            const api = await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ onLocatorResolved: () => {} }));
            assert.equal(api?.source, "locator");
        }
    } finally {
        setLearnedPlaintextSource(null);
        setLocatorResolvedListener(null);
    }
});

test("learnedMessage carries module-relative RVAs and lowercase prologue hashes", () => {
    const mod = fakeModule();
    assert.deepEqual(learnedMessage(mod, LOCATED(mod), IDENTITY, HASHES), {
        module: "libcronet.so", build_id: "deadbeef0011", size: 0x100000, arch: "arm64",
        rvas: { SSL_read: 0x100, SSL_write: 0x200 },
        prologue_sha256: { SSL_read: "aa".repeat(32), SSL_write: "bb".repeat(32) },
    });
});

test("learnedMessage is null for a partial API, an out-of-module RVA or an unhashable prologue", () => {
    const mod = fakeModule();
    assert.equal(learnedMessage(mod, { sslRead: mod.base.add(0x100), sslWrite: null }, IDENTITY, HASHES), null);
    assert.equal(learnedMessage(mod, { sslRead: mod.base.add(0x100), sslWrite: mod.base.add(0x200000) }, IDENTITY, HASHES), null);
    assert.equal(learnedMessage(mod, LOCATED(mod), IDENTITY, () => null), null);
});

test("the reporter emits on a locator hit only when the module has a build id", async () => {
    const sent: PlaintextApiLearnedPayload[] = [];
    const withId = createLocatorReporter(() => IDENTITY, (m) => sent.push(m), HASHES);
    const api = await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ learned: { lookup: () => null }, onLocatorResolved: withId }));
    assert.equal(api?.source, "locator");
    assert.equal(sent.length, 1);
    assert.equal(sent[0].build_id, "deadbeef0011");

    const withoutId = createLocatorReporter(() => null, (m) => sent.push(m), HASHES);
    await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ learned: { lookup: () => null }, onLocatorResolved: withoutId }));
    assert.equal(sent.length, 1);
});

test("--offsets hits are never reported; learned hits only as cache_hit", async () => {
    const sent: PlaintextApiLearnedPayload[] = [];
    const reporter = createLocatorReporter(() => IDENTITY, (m) => sent.push(m), HASHES);
    const cacheSent = installHostEntries({ [KEY]: HOST_ENTRY });
    const learned = createLearnedPlaintextSource();
    assert.equal((await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ learned, onLocatorResolved: reporter })))?.source, "learned");
    assert.deepEqual(sent, []);
    assert.deepEqual(cacheSent, [{ module: "libcronet.so", build_id: "deadbeef0011", size: 0x100000, arch: "arm64", cache_hit: true }]);
    const offsets = { "libcronet.so": { SSL_read: { address: "0x100" }, SSL_write: { address: "0x200" } } };
    const originalPtr = G.ptr;
    G.ptr = (v: any) => new FakePtr(Number(v));
    try {
        assert.equal((await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ readOffsets: () => offsets, learned: { lookup: () => null }, onLocatorResolved: reporter })))?.source, "offsets");
    } finally {
        G.ptr = originalPtr;
    }
    assert.equal(sent.length, 0);
});

test("installLearnedPlaintextCache wires the config entries and the reporter into the resolver", async () => {
    const sent: any[] = [];
    const originalSend = G.send;
    const originalArch = G.Process.arch;
    // Debug logging also goes through send(); keep only the cache reports.
    G.send = (message: any) => {
        if (message?.contentType === "plaintext_api_learned" || message?.contentType === "module_offsets_learned") sent.push(message);
    };
    G.Process.arch = "arm64";
    // The installed reporter hashes with the real sha256Prologue (Frida's Checksum).
    G.Checksum = { compute: (_algorithm: string, _bytes: ArrayBuffer) => "CC".repeat(32) };
    try {
        installLearnedModuleCache({ [KEY]: HOST_ENTRY });
        installLearnedPlaintextCache();
        const elf = elfWithBuildId();
        const learnedHit = await resolveBoringSslPlaintext(fakeModule(elf), { hashPrologue: HASHES, warn: () => {} });
        assert.equal(learnedHit?.source, "learned");
        assert.equal(sent.length, 1);
        assert.equal(sent[0].contentType, "module_offsets_learned");
        assert.equal(sent[0].cache_hit, true);
        assert.equal(sent[0].build_id, "deadbeef0011");
        sent.length = 0;

        installLearnedModuleCache({});
        const located = await resolveBoringSslPlaintext(fakeModule(elf), { hashPrologue: HASHES, warn: () => {},
            locate: async (m) => LOCATED(m) });
        assert.equal(located?.source, "locator");
        assert.equal(sent.length, 1);
        assert.equal(sent[0].contentType, "plaintext_api_learned");
        assert.equal(sent[0].protocol, "tls");
        assert.equal(sent[0].cache_hit, undefined);
        assert.equal(sent[0].build_id, "deadbeef0011");
        assert.equal(sent[0].arch, "arm64");
        assert.deepEqual(sent[0].rvas, { SSL_read: 0x100, SSL_write: 0x200 });
        assert.deepEqual(sent[0].prologue_sha256, { SSL_read: "cc".repeat(32), SSL_write: "cc".repeat(32) });
    } finally {
        G.send = originalSend;
        G.Process.arch = originalArch;
        delete G.Checksum;
        installLearnedModuleCache({});
        setLearnedPlaintextSource(null);
        setLocatorResolvedListener(null);
    }
});

test("a learned entry that fails prologue verification is not reported as a cache hit", async () => {
    const sent = installHostEntries({ [KEY]: HOST_ENTRY });
    const api = await resolveBoringSslPlaintext(fakeModule(), resolverDeps({
        learned: createLearnedPlaintextSource(), hashPrologue: () => "ff".repeat(32), onLocatorResolved: () => {} }));
    assert.equal(api?.source, "locator");
    assert.equal(sent.length, 0);
});

test("a cache-hit listener that throws does not turn the learned entry into a miss", async () => {
    installHostEntries({ [KEY]: HOST_ENTRY }, { emit: () => { throw new Error("send failed"); } });
    const api = await resolveBoringSslPlaintext(fakeModule(), resolverDeps({ learned: createLearnedPlaintextSource() }));
    assert.equal(api?.source, "learned");
});

test("one cache hit per module per session across the plaintext and the generic cache", async () => {
    const entry = { ...HOST_ENTRY, functions: { "boringssl.ssl_log_secret": { rva: 0x300, prologue_sha256: "bb".repeat(32) } } };
    const sent = installHostEntries({ [KEY]: entry });
    const mod = fakeModule();
    const api = await resolveBoringSslPlaintext(mod, resolverDeps({ learned: createLearnedPlaintextSource() }));
    assert.equal(api?.source, "learned");
    assert.notEqual(learnedFunction(mod, "boringssl.ssl_log_secret"), null);
    await resolveBoringSslPlaintext(mod, resolverDeps({ learned: createLearnedPlaintextSource() }));
    assert.deepEqual(sent.filter((p) => p.cache_hit), [
        { module: "libcronet.so", build_id: "deadbeef0011", size: 0x100000, arch: "arm64", cache_hit: true }]);
});
