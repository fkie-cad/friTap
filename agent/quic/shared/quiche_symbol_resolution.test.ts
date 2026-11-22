// Run: npm run test:agent
//
// resolveQuicheSymbolsWith() consults the learned-offsets cache after the exports:
// keys verified from the cache skip the symtab walk and the pattern scan, only
// still-missing keys are scanned, scan hits are reported under quiche.<key>,
// clean scan misses under quiche.miss.<key>, and a user --offsets entry is never
// shadowed by the cache.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";

import {
    QuicheSymbolSources, learnedQuicheMissName, learnedQuicheName, resolveQuicheSymbolsWith,
} from "./quiche_symbol_resolution.js";
import { installLearnedModuleCache, isLearnedItemName } from "../../shared/learned_module_cache.js";
import { MANGLED_SYMBOLS } from "./google_quiche_offsets.js";

class FakePtr {
    constructor(readonly value: number) {}
    add(n: any): FakePtr { return new FakePtr(this.value + Number(n?.value ?? n)); }
    sub(other: any): FakePtr { return new FakePtr(this.value - Number(other?.value ?? other)); }
    and(n: number): FakePtr { return new FakePtr(this.value & n); }
    isNull(): boolean { return this.value === 0; }
    toString(): string { return "0x" + this.value.toString(16); }
}

type Key = "readv" | "writeHeaders" | "onDataFramePayload";
const KEYS: Key[] = ["readv", "writeHeaders", "onDataFramePayload"];
const IDENTITY = { buildId: "c0ffee", size: 0x1000000, arch: "arm64" };
const HASH = "ab".repeat(32);
const MOD: any = { name: "/apex/lib64/libmainlinecronet.so", base: new FakePtr(0x7000_0000), size: IDENTITY.size };

interface Recorder {
    symtabKeys: Key[][];
    scannedKeys: Key[][];
    hashed: number[];
    reported: { functions?: Record<string, any>; layout?: Record<string, number> }[];
}

/**
 * Install a host cache holding `rvas` (key -> rva) and miss markers for `misses`;
 * `hash` is what every prologue reads now.
 */
function installCache(rvas: Partial<Record<Key, number>>, hash: string = HASH, misses: Key[] = [],
                      missMarker = 1): Recorder {
    const rec: Recorder = { symtabKeys: [], scannedKeys: [], hashed: [], reported: [] };
    const functions: Record<string, any> = {};
    for (const [key, rva] of Object.entries(rvas)) functions[learnedQuicheName(key)] = { rva, prologue_sha256: HASH };
    const layout = Object.fromEntries(misses.map((key) => [learnedQuicheMissName(key), missMarker]));
    installLearnedModuleCache({ "c0ffee|16777216|arm64": { module: "libmainlinecronet.so", functions, layout } }, {
        identify: () => IDENTITY,
        hashPrologue: (address: any) => { rec.hashed.push(address.value - MOD.base.value); return hash; },
        emit: (payload) => { if (payload.cache_hit !== true) rec.reported.push(payload); },
        schedule: (flush) => flush(),
    });
    return rec;
}

function sources(rec: Recorder, over: Partial<QuicheSymbolSources<Key>> = {},
                 scanHits: Partial<Record<Key, number>> = {}): QuicheSymbolSources<Key> {
    const userOffset = over.userOffset ?? (() => null);
    return {
        hasUserOffset: (k) => userOffset(k) !== null,
        exported: () => null,
        symtab: (keys) => { rec.symtabKeys.push(keys); return { found: new Map(), complete: true }; },
        patterns: async (keys) => {
            rec.scannedKeys.push(keys);
            return { found: new Map(keys.filter((k) => scanHits[k] !== undefined)
                .map((k) => [k, MOD.base.add(scanHits[k]!)] as [Key, any])), complete: true };
        },
        userOffset: () => null,
        missFingerprint: () => 1,
        ...over,
    };
}

const valueOf = (m: Map<Key, any>, k: Key) => m.get(k)?.value;
const reportedFunctions = (rec: Recorder) => rec.reported.flatMap((p) => Object.keys(p.functions ?? {})).sort();
const reportedMisses = (rec: Recorder) => rec.reported.flatMap((p) => Object.keys(p.layout ?? {})).sort();

test("every MANGLED_SYMBOLS key maps to valid learned-cache item and miss-marker names", () => {
    for (const key of Object.keys(MANGLED_SYMBOLS)) {
        assert.ok(isLearnedItemName(learnedQuicheName(key)), key);
        assert.ok(isLearnedItemName(learnedQuicheMissName(key)), key);
    }
    assert.equal(learnedQuicheName("writeOrBufferBody"), "quiche.writeOrBufferBody");
    assert.equal(learnedQuicheMissName("writeOrBufferBody"), "quiche.miss.writeOrBufferBody");
    assert.ok(isLearnedItemName(learnedQuicheName("weird-key.x")));
});

test("all keys from the cache: no symtab walk, no pattern scan, nothing reported", async () => {
    const rec = installCache({ readv: 0x100, writeHeaders: 0x200, onDataFramePayload: 0x300 });
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec));
    assert.equal(fromCache, 3);
    assert.equal(valueOf(resolved, "writeHeaders"), MOD.base.value + 0x200);
    assert.deepEqual(rec.symtabKeys, []);
    assert.deepEqual(rec.scannedKeys, []);
    assert.deepEqual(rec.reported, []);
});

test("partial cache: only the missing keys are scanned, and only scan hits are reported", async () => {
    const rec = installCache({ readv: 0x100 });
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(MOD, KEYS,
        sources(rec, {}, { writeHeaders: 0x2220, onDataFramePayload: 0x3330 }));
    assert.equal(fromCache, 1);
    assert.deepEqual(rec.symtabKeys, [["writeHeaders", "onDataFramePayload"]]);
    assert.deepEqual(rec.scannedKeys, [["writeHeaders", "onDataFramePayload"]]);
    assert.deepEqual(reportedFunctions(rec), ["quiche.onDataFramePayload", "quiche.writeHeaders"]);
    assert.deepEqual(reportedMisses(rec), []);
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x100);
    assert.equal(valueOf(resolved, "onDataFramePayload"), MOD.base.value + 0x3330);
});

test("a prologue-hash mismatch falls back to the scan", async () => {
    const rec = installCache({ readv: 0x100 }, "ff".repeat(32));
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {}, { readv: 0x4440 }));
    assert.equal(fromCache, 0);
    assert.deepEqual(rec.scannedKeys, [KEYS]);
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x4440);
    assert.equal(rec.reported.find((p) => p.functions)?.functions?.["quiche.readv"]?.rva, 0x4440);
});

test("symtab hits fill keys before the pattern scan and are reported too", async () => {
    const rec = installCache({});
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        symtab: (keys) => ({ found: new Map(keys.filter((k) => k === "readv").map((k) => [k, MOD.base.add(0x10)] as [Key, any])), complete: true }),
    }, { writeHeaders: 0x20, onDataFramePayload: 0x30 }));
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x10);
    assert.deepEqual(rec.scannedKeys, [["writeHeaders", "onDataFramePayload"]]);
    assert.deepEqual(reportedFunctions(rec), ["quiche.onDataFramePayload", "quiche.readv", "quiche.writeHeaders"]);
});

test("exports win and are neither looked up in the cache nor reported", async () => {
    const rec = installCache({ readv: 0x100, writeHeaders: 0x200, onDataFramePayload: 0x300 });
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(MOD, KEYS,
        sources(rec, { exported: (k) => (k === "readv" ? MOD.base.add(0x8) : null) }));
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x8);
    assert.equal(fromCache, 2);
    assert.ok(!rec.hashed.includes(0x100), "the exported key's cache entry is never verified");
    assert.deepEqual(rec.reported, []);
});

test("a user --offsets key skips the cache; patterns still win over it, else it applies", async () => {
    const userAt = MOD.base.add(0x9990);
    const rec = installCache({ readv: 0x100, writeHeaders: 0x200 });
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        userOffset: (k) => (k === "readv" || k === "writeHeaders" ? userAt : null),
    }, { writeHeaders: 0x2220, onDataFramePayload: 0x3330 }));
    assert.equal(fromCache, 0, "the cache never shadows a user offset");
    assert.ok(!rec.hashed.includes(0x100) && !rec.hashed.includes(0x200), "user-offset keys skip the cache");
    assert.equal(valueOf(resolved, "readv"), userAt.value, "no pattern hit: the user offset applies");
    assert.equal(valueOf(resolved, "writeHeaders"), MOD.base.value + 0x2220, "pattern hit keeps winning as before");
    assert.deepEqual(reportedFunctions(rec), ["quiche.onDataFramePayload", "quiche.writeHeaders"],
        "user offsets are not reported");
});

test("keys both scans missed are recorded as miss markers", async () => {
    const rec = installCache({ readv: 0x100 });
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {}, { writeHeaders: 0x2220 }));
    assert.equal(resolved.has("onDataFramePayload"), false);
    assert.deepEqual(reportedMisses(rec), ["quiche.miss.onDataFramePayload"]);
    assert.equal(rec.reported.find((p) => p.layout)?.layout?.["quiche.miss.onDataFramePayload"], 1);
});

test("a key with a miss marker is not scanned again; exports and user offsets still apply", async () => {
    const userAt = MOD.base.add(0x9990);
    const rec = installCache({}, HASH, ["readv", "writeHeaders", "onDataFramePayload"]);
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        exported: (k) => (k === "readv" ? MOD.base.add(0x8) : null),
        userOffset: (k) => (k === "writeHeaders" ? userAt : null),
    }, { writeHeaders: 0x2220, onDataFramePayload: 0x3330 }));
    assert.deepEqual(rec.symtabKeys, [["writeHeaders"]], "only the user-offset key ignores its marker");
    assert.deepEqual(rec.scannedKeys, [["writeHeaders"]]);
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x8);
    assert.equal(valueOf(resolved, "writeHeaders"), MOD.base.value + 0x2220);
    assert.equal(resolved.has("onDataFramePayload"), false, "a recorded miss is not rescanned");
    assert.deepEqual(reportedMisses(rec), [], "known misses are not reported again");
});

test("a miss marker matching the current pattern fingerprint skips the scan", async () => {
    const rec = installCache({}, HASH, KEYS, 0x1234);
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS,
        sources(rec, { missFingerprint: () => 0x1234 }, { readv: 0x4440 }));
    assert.deepEqual(rec.symtabKeys, []);
    assert.deepEqual(rec.scannedKeys, []);
    assert.equal(resolved.size, 0);
    assert.deepEqual(rec.reported, []);
});

test("changed patterns: a marker with another fingerprint is rescanned and its new marker reported", async () => {
    const rec = installCache({}, HASH, KEYS, 0x1234);
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        missFingerprint: (k) => (k === "readv" ? 0x1234 : 0x5678),
    }, { writeHeaders: 0x2220 }));
    assert.deepEqual(rec.symtabKeys, [["writeHeaders", "onDataFramePayload"]]);
    assert.deepEqual(rec.scannedKeys, [["writeHeaders", "onDataFramePayload"]]);
    assert.equal(valueOf(resolved, "writeHeaders"), MOD.base.value + 0x2220);
    assert.deepEqual(reportedFunctions(rec), ["quiche.writeHeaders"]);
    assert.deepEqual(rec.reported.filter((p) => p.layout).map((p) => p.layout),
        [{ "quiche.miss.onDataFramePayload": 0x5678 }]);
});

test("an aborted pattern scan records no miss markers", async () => {
    const rec = installCache({});
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        patterns: async () => { throw new Error("scan aborted"); },
    }));
    assert.equal(resolved.size, 0);
    assert.deepEqual(rec.reported, []);
});

test("a pattern scan that reported an error records no miss markers but keeps its hits", async () => {
    const rec = installCache({});
    const { resolved } = await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        patterns: async () => ({ found: new Map([["readv", MOD.base.add(0x40)]]), complete: false }),
    }));
    assert.equal(valueOf(resolved, "readv"), MOD.base.value + 0x40);
    assert.deepEqual(reportedFunctions(rec), ["quiche.readv"]);
    assert.deepEqual(reportedMisses(rec), []);
});

test("a failed symtab walk records no miss markers even when the pattern scan completed", async () => {
    const rec = installCache({});
    await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        symtab: () => ({ found: new Map(), complete: false }),
    }));
    assert.deepEqual(rec.scannedKeys, [KEYS], "the pattern scan still runs");
    assert.deepEqual(reportedMisses(rec), []);
});

test("each key's miss fingerprint is computed at most once per resolve", async () => {
    const rec = installCache({}, HASH, ["readv"], 0x1234);
    const calls: Key[] = [];
    await resolveQuicheSymbolsWith(MOD, KEYS, sources(rec, {
        missFingerprint: (k) => { calls.push(k); return 0x5678; },
    }));
    assert.deepEqual([...calls].sort(), [...KEYS].sort(), "read (stale marker) and report share one computation");
});

test("without a module the cache is neither read nor written", async () => {
    const rec = installCache({ readv: 0x100 });
    const { resolved, fromCache } = await resolveQuicheSymbolsWith(null, KEYS, sources(rec, {}, { writeHeaders: 0x20 }));
    assert.equal(fromCache, 0);
    assert.equal(valueOf(resolved, "writeHeaders"), MOD.base.value + 0x20);
    assert.deepEqual(rec.scannedKeys, [KEYS]);
    assert.deepEqual(rec.reported, []);
});
