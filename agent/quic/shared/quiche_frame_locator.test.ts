// Unit tests for the Google QUICHE STREAM-frame locator (quiche_frame_locator.ts).
//
// Run: npm run test:agent
//
// WHY: Chrome's libmonochrome is stripped and its byte patterns drift per build.
// QuicConnection::OnStreamFrame / QuicSession::WriteStreamData are located by
// the QUIC error-detail literals they reference; a hook must only be placed
// when every load site of every anchor lies in ONE function. Fixtures are the
// real function bounds measured in Chrome 133.0.6943.137 libmonochrome_64.so.

import { test } from "node:test";
import assert from "node:assert/strict";
import "../../shared/frida-test-stubs.js";
import {
    CRYPTO_CONNECT_ANCHORS, MAX_FUNCTION_BYTES, MIN_CRYPTO_CONNECT_ANCHORS, agreeOnFunction, agreeOnFunctionPartial,
} from "./quiche_frame_locator.js";

const ON_STREAM_FRAME = { start: 0x54e74b4, size: 0x1c4 };
const WRITE_STREAM_DATA = { start: 0x551c06c, size: 0xe8 };

test("both OnStreamFrame anchors resolving to one function pick it", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], [ON_STREAM_FRAME]]), 0x54e74b4);
    assert.equal(agreeOnFunction([[WRITE_STREAM_DATA]]), 0x551c06c);
});

test("anchors that disagree, or one anchor used in two functions, pick nothing", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], [WRITE_STREAM_DATA]]), null);
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME, WRITE_STREAM_DATA]]), null);
});

test("a missing anchor, an unbounded site or an oversized function picks nothing", () => {
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME], []]), null);
    assert.equal(agreeOnFunction([[ON_STREAM_FRAME, null]]), null);
    assert.equal(agreeOnFunction([[{ start: 0x1000, size: MAX_FUNCTION_BYTES + 4 }]]), null);
    assert.equal(agreeOnFunction([]), null);
});

test("a function whose FDE size is unknown is still accepted when all sites agree", () => {
    assert.equal(agreeOnFunction([[{ start: 0x2000, size: null }, { start: 0x2000, size: null }]]), 0x2000);
});

// TlsClientHandshaker::CryptoConnect bounds measured in Cronet 148.0.7778.120
// (landing-pad bounds: its FDE is missing) and libmonochrome_64.so (FDE).
const CRYPTO_CONNECT_CRONET148 = { start: 0x5f58c0, size: 0x574 };
const CRYPTO_CONNECT_MONOCHROME = { start: 0x4b50fb8, size: 0xa14 };

test("all four CryptoConnect anchors agreeing pick the function", () => {
    assert.equal(CRYPTO_CONNECT_ANCHORS.length, 4);
    const all = CRYPTO_CONNECT_ANCHORS.map(() => [CRYPTO_CONNECT_CRONET148]);
    assert.equal(agreeOnFunctionPartial(all, MIN_CRYPTO_CONNECT_ANCHORS), 0x5f58c0);
    assert.equal(agreeOnFunctionPartial(CRYPTO_CONNECT_ANCHORS.map(() => [CRYPTO_CONNECT_MONOCHROME]),
                                        MIN_CRYPTO_CONNECT_ANCHORS), 0x4b50fb8);
});

test("CryptoConnect anchors that disagree pick nothing", () => {
    const sites = [[CRYPTO_CONNECT_CRONET148], [CRYPTO_CONNECT_CRONET148], [CRYPTO_CONNECT_MONOCHROME], []];
    assert.equal(agreeOnFunctionPartial(sites, MIN_CRYPTO_CONNECT_ANCHORS), null);
    assert.equal(agreeOnFunctionPartial([[CRYPTO_CONNECT_CRONET148], [CRYPTO_CONNECT_CRONET148, null]], 2), null);
});

test("dropped CryptoConnect literals are tolerated down to two agreeing anchors", () => {
    const two = [[CRYPTO_CONNECT_CRONET148], [], [CRYPTO_CONNECT_CRONET148], []];
    assert.equal(agreeOnFunctionPartial(two, MIN_CRYPTO_CONNECT_ANCHORS), 0x5f58c0);
    const one = [[CRYPTO_CONNECT_CRONET148], [], [], []];
    assert.equal(agreeOnFunctionPartial(one, MIN_CRYPTO_CONNECT_ANCHORS), null);
    assert.equal(agreeOnFunctionPartial([[], [], [], []], MIN_CRYPTO_CONNECT_ANCHORS), null);
});

// ---- locateQuicheFrameApi(): learned cache before the anchor scan, memoized ----

import {
    FrameApiSources, LEARNED_FRAME_API_NAMES, LocatedFrameApi, frameApiMissFingerprint,
    locateQuicheFrameApi,
} from "./quiche_frame_locator.js";
import { installLearnedModuleCache, learnedMissName } from "../../shared/learned_module_cache.js";

class FakeAddr {
    constructor(readonly value: number) {}
    add(n: any): FakeAddr { return new FakeAddr(this.value + Number(n?.value ?? n)); }
    sub(other: any): FakeAddr { return new FakeAddr(this.value - Number(other?.value ?? other)); }
    and(n: number): FakeAddr { return new FakeAddr(this.value & n); }
    isNull(): boolean { return this.value === 0; }
    toString(): string { return "0x" + this.value.toString(16); }
}

const FRAME_IDENTITY = { buildId: "feed01", size: 0x8000000, arch: "arm64" };
const FRAME_HASH = "cd".repeat(32);
let nextFrameBase = 0x1_0000_0000;

/** A fresh mapping per test: the locator memoizes per name@base. */
function frameModule(): any {
    nextFrameBase += 0x1000_0000;
    return { name: "/data/app/lib/arm64/libmonochrome_64.so", base: new FakeAddr(nextFrameBase), size: FRAME_IDENTITY.size };
}

interface FrameRecorder { scans: number; reported: Record<string, any>[]; misses: Record<string, number>[] }

/**
 * Install a host cache holding `rvas` and `layout` (miss markers); `hash` is what every
 * prologue reads now. Scan results land in `reported`, miss markers in `misses`.
 */
function installFrameCache(rvas: Partial<Record<keyof LocatedFrameApi, number>>, hash = FRAME_HASH,
                           layout: Record<string, number> = {}): FrameRecorder {
    const rec: FrameRecorder = { scans: 0, reported: [], misses: [] };
    const functions: Record<string, any> = {};
    for (const [field, rva] of Object.entries(rvas)) {
        functions[LEARNED_FRAME_API_NAMES[field as keyof LocatedFrameApi]] = { rva, prologue_sha256: FRAME_HASH };
    }
    installLearnedModuleCache({ "feed01|134217728|arm64": { module: "libmonochrome_64.so", functions, layout } }, {
        identify: () => FRAME_IDENTITY, hashPrologue: () => hash, schedule: (flush) => flush(),
        emit: (payload) => {
            if (payload.functions) rec.reported.push(payload.functions);
            if (payload.layout) rec.misses.push(payload.layout);
        },
    });
    return rec;
}

const SCANNED = { onStreamFrame: 0x54e74b4, writeStreamData: 0x551c06c, onCryptoFrame: 0x54e0000, cryptoConnect: null };

function frameSources(rec: FrameRecorder, scanned: Record<string, number | null> = SCANNED,
                      complete = true): FrameApiSources {
    return {
        scan: async (m: any) => {
            rec.scans++;
            const at = (rva: number | null) => (rva === null ? null : m.base.add(rva));
            return { api: { onStreamFrame: at(scanned.onStreamFrame), writeStreamData: at(scanned.writeStreamData),
                            onCryptoFrame: at(scanned.onCryptoFrame), cryptoConnect: at(scanned.cryptoConnect) } as any,
                     complete };
        },
    };
}

const CRYPTO_CONNECT_MISS = { [learnedMissName(LEARNED_FRAME_API_NAMES.cryptoConnect)]: frameApiMissFingerprint("cryptoConnect") };

async function withArm64<T>(fn: () => Promise<T>): Promise<T> {
    const G = globalThis as any;
    const saved = G.Process.arch;
    G.Process.arch = "arm64";
    try { return await fn(); } finally { G.Process.arch = saved; }
}

test("frame API fully cached (CryptoConnect recorded as a miss): no anchor scan, nothing reported", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({ onStreamFrame: 0x100, writeStreamData: 0x200, onCryptoFrame: 0x300 },
        FRAME_HASH, CRYPTO_CONNECT_MISS);
    const api: any = await locateQuicheFrameApi(mod, frameSources(rec));
    assert.equal(rec.scans, 0);
    assert.equal(api.onStreamFrame.value, mod.base.value + 0x100);
    assert.equal(api.writeStreamData.value, mod.base.value + 0x200);
    assert.equal(api.onCryptoFrame.value, mod.base.value + 0x300);
    assert.equal(api.cryptoConnect, null);
    assert.deepEqual(rec.reported, []);
    assert.deepEqual(rec.misses, []);
}));

test("an optional function absent from the cache without a miss marker triggers the anchor scan", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({ onStreamFrame: 0x100, writeStreamData: 0x200 });
    const api: any = await locateQuicheFrameApi(mod, frameSources(rec));
    assert.equal(rec.scans, 1);
    assert.equal(api.onStreamFrame.value, mod.base.value + 0x100, "cached mandatory values are kept");
    assert.equal(api.writeStreamData.value, mod.base.value + 0x200);
    assert.equal(api.onCryptoFrame.value, mod.base.value + SCANNED.onCryptoFrame);
    assert.deepEqual(rec.reported.map((f) => Object.keys(f)), [["quiche.frame.OnCryptoFrame"]]);
    assert.deepEqual(rec.misses, [CRYPTO_CONNECT_MISS]);
}));

test("a miss marker from other anchors is stale: the optional function is scanned for again", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({ onStreamFrame: 0x100, writeStreamData: 0x200, onCryptoFrame: 0x300 },
        FRAME_HASH, { [learnedMissName(LEARNED_FRAME_API_NAMES.cryptoConnect)]: 7 });
    await locateQuicheFrameApi(mod, frameSources(rec));
    assert.equal(rec.scans, 1);
    assert.deepEqual(rec.misses, [CRYPTO_CONNECT_MISS]);
}));

test("an incomplete scan records no optional miss markers", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({});
    await locateQuicheFrameApi(mod, frameSources(rec, SCANNED, false));
    assert.equal(rec.reported.length, 1, "its hits are still reported");
    assert.deepEqual(rec.misses, []);
}));

test("frame API with a mandatory function missing from the cache is rescanned and reported", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({ onStreamFrame: 0x100 });
    const api: any = await locateQuicheFrameApi(mod, frameSources(rec));
    assert.equal(rec.scans, 1);
    assert.equal(api.writeStreamData.value, mod.base.value + SCANNED.writeStreamData);
    assert.deepEqual(Object.keys(rec.reported[0]).sort(), ["quiche.frame.OnCryptoFrame", "quiche.frame.WriteStreamData"],
        "the function verified from the cache is not reported back");
    assert.equal(rec.reported[0]["quiche.frame.WriteStreamData"].rva, SCANNED.writeStreamData);
    assert.deepEqual(rec.misses, [CRYPTO_CONNECT_MISS], "the optional function the clean scan missed is marked");
}));

test("frame API prologue-hash mismatch falls back to the anchor scan", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({ onStreamFrame: 0x100, writeStreamData: 0x200 }, "ee".repeat(32));
    const api: any = await locateQuicheFrameApi(mod, frameSources(rec));
    assert.equal(rec.scans, 1);
    assert.equal(api.onStreamFrame.value, mod.base.value + SCANNED.onStreamFrame);
    assert.equal(rec.reported.length, 1);
}));

test("an unsuccessful scan (no WriteStreamData) is not reported", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({});
    await locateQuicheFrameApi(mod, frameSources(rec, { ...SCANNED, writeStreamData: null }));
    assert.equal(rec.scans, 1);
    assert.deepEqual(rec.reported, []);
}));

test("frame API lookup is memoized per mapping: concurrent callers share one scan", () => withArm64(async () => {
    const mod = frameModule();
    const rec = installFrameCache({});
    const src = frameSources(rec);
    const [a, b]: any[] = await Promise.all([locateQuicheFrameApi(mod, src), locateQuicheFrameApi(mod, src)]);
    assert.equal(a, b);
    assert.equal(rec.scans, 1);
}));
