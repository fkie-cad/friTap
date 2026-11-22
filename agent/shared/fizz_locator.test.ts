// Unit tests for fizz_locator.ts against REAL bytes of Facebook 588 libcoldstart.so and
// Instagram 456 libstartup.so (sparse fixture, see __fixtures__/fizz_meta_arm64.ts):
// label vote, RTTI relative-vtable resolution, deriveSecret body validation, the whole
// pure locate pipeline, learned-location re-validation and the relative-ref needles.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import "./frida-test-stubs.js";
import {
    addressPointMatchesRtti, APPEND_TO_TRANSCRIPT_SLOT, backwardVtableCallSlot, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME,
    FIZZ_KDF_RTTI_NAME, FIZZ_LOCATOR_MISS_FINGERPRINT, FIZZ_VOTING_LABELS, isAlignedCodeEntry, labelCallSlot,
    LEARNED_FIZZ_APPEND_TRANSCRIPT, LEARNED_FIZZ_DERIVE_SECRET, LEARNED_FIZZ_DERIVE_SECRET_MISS,
    LEARNED_FIZZ_DERIVE_SECRET_SLOT, LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE, LEARNED_FIZZ_KDF_VTABLE,
    locateFizzInImage, referencesCString, relativeRefNeedles, relativeVtablesFor, revalidateFizzLocation,
    uniqueSlotTarget, validateDeriveSecretBody, voteDeriveSecretSlot, voteSlot, vtableSlotTarget,
    moduleDataRanges, moduleRodataRanges, rangeHoldsArtefact, rangesHolding,
    type FizzArtefactRegion, type FizzImage, type FizzImageSearch,
} from "./fizz_locator.js";
import { isLearnedItemName, isValidLayoutValue, missFingerprint } from "./learned_module_cache.js";
import { isADDimm64, isADR, isADRP, decodeADDImm12, decodeADRImm, decodeADRPImm, regRd, regRn } from "./arm64.js";
import { FIZZ_FB, FIZZ_IG, type FixtureSegment, type FizzFixtureImage } from "./__fixtures__/fizz_meta_arm64.js";

// ---- sparse image over the fixture (brute-force searches) ------------------------

interface Region { off: number; bytes: Uint8Array; }

/** A whole image already decoded to bytes (the ELF harness below), with its mapped segments. */
interface DecodedImage { segments: FixtureSegment[]; regions: Region[]; }

/**
 * FizzImage + FizzImageSearch over sparse fixture bytes or a whole decoded ELF. Every
 * search honours the segment protections exactly as the Frida search does: pointer slots
 * in the "relocated" ranges, relative references in the "rodata" ranges (both via the
 * locator's own rangesHolding), strings data first then code (findLiteralOccurrences),
 * load sites and isCode in the executable ranges.
 */
class SparseImage implements FizzImage, FizzImageSearch {
    readonly regions: Region[];
    readonly segments: FixtureSegment[];

    constructor(source: FizzFixtureImage | DecodedImage, patches: Record<number, number> = {}) {
        this.segments = source.segments;
        this.regions = source.regions.map((r) => ("bytes" in r ? r as Region
            : { off: r.off, bytes: Uint8Array.from(Buffer.from(r.hex, "hex")) }));
        for (const [off, word] of Object.entries(patches)) this.writeU32(Number(off), word);
    }

    /** The parts of the regions inside `segments`: [region, first byte index, end byte index). */
    private *spans(segments: FixtureSegment[]): Generator<[Region, number, number]> {
        for (const seg of segments) {
            for (const r of this.regions) {
                const lo = Math.max(seg.off, r.off), hi = Math.min(seg.off + seg.size, r.off + r.bytes.length);
                if (lo < hi) yield [r, lo - r.off, hi - r.off];
            }
        }
    }

    private executable(): FixtureSegment[] { return this.segments.filter((g) => g.protection.includes("x")); }

    private view(off: number, size: number): DataView | null {
        const r = this.regions.find((x) => off >= x.off && off + size <= x.off + x.bytes.length);
        return r === undefined ? null : new DataView(r.bytes.buffer, r.bytes.byteOffset + off - r.off, size);
    }

    private writeU32(off: number, word: number): void {
        this.view(off, 4)!.setUint32(0, word >>> 0, true);
    }

    readU32(off: number): number | null { return this.view(off, 4)?.getUint32(0, true) ?? null; }
    readS32(off: number): number | null { return this.view(off, 4)?.getInt32(0, true) ?? null; }

    readWords(off: number, count: number): number[] {
        const words: number[] = [];
        for (let w = this.readU32(off); w !== null && words.length < count; w = this.readU32(off + 4 * words.length)) words.push(w);
        return words;
    }

    readPointerOffset(off: number): number | null {
        const v = this.view(off, 8);
        return v === null ? null : Number(v.getBigUint64(0, true));
    }

    readCString(off: number, maxLen: number): string | null {
        let text = "";
        for (let i = 0; i < maxLen; i++) {
            const v = this.view(off + i, 1);
            if (v === null) return null;
            const c = v.getUint8(0);
            if (c === 0) return text;
            text += String.fromCharCode(c);
        }
        return null;
    }

    isCode(off: number): boolean { return this.executable().some((g) => off >= g.off && off < g.off + g.size); }

    private findBytes(needle: Uint8Array, align: number, segments: FixtureSegment[]): number[] {
        const out: number[] = [];
        for (const [r, lo, hi] of this.spans(segments)) {
            const hay = Buffer.from(r.bytes.buffer, r.bytes.byteOffset + lo, hi - lo);
            for (let i = hay.indexOf(needle); i >= 0; i = hay.indexOf(needle, i + 1)) {
                if ((r.off + lo + i) % align === 0) out.push(r.off + lo + i);
            }
        }
        return out;
    }

    /** Like findLiteralOccurrences: non-executable ranges first, executable ones only for texts not found there. */
    async cStrings(texts: readonly string[]): Promise<number[][]> {
        const data = this.segments.filter((g) => !g.protection.includes("x"));
        return texts.map((t) => {
            const needle = Uint8Array.from(Buffer.from(`${t}\0`, "latin1"));
            const inData = this.findBytes(needle, 1, data);
            return inData.length > 0 ? inData : this.findBytes(needle, 1, this.executable());
        });
    }

    async pointerSlots(target: number): Promise<number[]> {
        const le = new Uint8Array(8);
        new DataView(le.buffer).setBigUint64(0, BigInt(target), true);
        return this.findBytes(le, 8, this.holding("relocated"));
    }

    async relativeRefs(target: number): Promise<number[]> {
        const out: number[] = [];
        for (const [r, lo, hi] of this.spans(this.holding("rodata"))) {
            const dv = new DataView(r.bytes.buffer, r.bytes.byteOffset);
            for (let i = lo + ((4 - ((r.off + lo) % 4)) % 4); i + 4 <= hi; i += 4) {
                if (dv.getInt32(i, true) === target - (r.off + i + 4)) out.push(r.off + i);
            }
        }
        return out;
    }

    async loadSites(targets: number[]): Promise<number[][]> {
        const sites: number[][] = targets.map(() => []);
        for (const [r, lo, hi] of this.spans(this.executable())) {
            const dv = new DataView(r.bytes.buffer, r.bytes.byteOffset);
            for (let i = lo + ((4 - ((r.off + lo) % 4)) % 4); i + 4 <= hi; i += 4) {
                const w = dv.getUint32(i, true);
                if (!isADR(w) && !isADRP(w)) continue;
                for (const addr of this.materialised(r.off + i, w)) {
                    targets.forEach((t, k) => { if (t === addr) sites[k].push(r.off + i); });
                }
            }
        }
        return sites;
    }

    private holding(region: FizzArtefactRegion): FixtureSegment[] { return rangesHolding(this.segments, region); }

    private materialised(pc: number, w: number): number[] {
        if (isADR(w)) return [pc + decodeADRImm(w)];
        if (!isADRP(w)) return [];
        const page = Math.floor(pc / 0x1000) * 0x1000 + decodeADRPImm(w);
        for (let j = 1; j <= 8; j++) {
            const next = this.readU32(pc + 4 * j);
            if (next === null) return [];
            if (isADDimm64(next) && regRd(next) === regRd(w) && regRn(next) === regRd(w)) return [page + decodeADDImm12(next)];
        }
        return [];
    }
}

const FIXTURES = [FIZZ_FB, FIZZ_IG];
const NOP = 0xd503201f;

// ---- L1: label sites -> slot -----------------------------------------------------

for (const fx of FIXTURES) {
    test(`${fx.name}: every Fizz label site's consuming call is the slot-0x14 vtable call`, () => {
        const img = new SparseImage(fx);
        assert.deepEqual(Object.keys(fx.labelSites).sort(), [...FIZZ_VOTING_LABELS].sort());
        for (const [label, sites] of Object.entries(fx.labelSites)) {
            for (const site of sites) assert.equal(labelCallSlot(img, site), 0x14, `${label} @0x${site.toString(16)}`);
        }
    });

    test(`${fx.name}: label sites of the other (non-deriveSecret) code do not vote`, () => {
        const img = new SparseImage(fx);
        for (const site of fx.otherLabelSites) assert.equal(labelCallSlot(img, site), null, `0x${site.toString(16)}`);
    });

    test(`${fx.name}: the vote over all label sites picks slot 0x14 with all six labels`, async () => {
        const img = new SparseImage(fx);
        assert.deepEqual(await voteDeriveSecretSlot(img, img), { slot: 0x14, labels: 6 });
    });
}

test("hoisted chain: 'c ap traffic' (FB) resolves its blr by the backward walk", () => {
    const img = new SparseImage(FIZZ_FB);
    // ldr x8,[x23] @0xc7bfd8; ldrsw x9,[x8,#0x14]; add x8,x8,x9; adrp x5 @0xc7bfe4 ...; blr x8 @0xc7c00c
    assert.equal(backwardVtableCallSlot(img, 0xc7c00c), 0x14);
    assert.equal(backwardVtableCallSlot(img, 0xc7c008), null); // not a blr (stp)
});

test("'exp master' steps over the hashLength() vtable call (slot 8) to the x5 call", () => {
    // FB: label in x24, `blr x8` via slot 8 first (x5 not yet the label), then `mov x5, x24`.
    assert.equal(labelCallSlot(new SparseImage(FIZZ_FB), FIZZ_FB.labelSites["exp master"][0]), 0x14);
    assert.equal(labelCallSlot(new SparseImage(FIZZ_IG), FIZZ_IG.labelSites["exp master"][0]), 0x14);
});

test("a site whose label is never in x5 at a call does not vote", () => {
    const fx = FIZZ_FB;
    const site = fx.labelSites["s ap traffic"][0];           // adrp x5 @0xc7c044, add x5 @0xc7c048
    const img = new SparseImage(fx, { [site + 4]: NOP, [site]: 0x90000018 }); // adrp x24 instead of x5, no completion
    assert.equal(labelCallSlot(img, site), null);
});

test("unreadable memory ends the walk", () => {
    assert.equal(labelCallSlot(new SparseImage(FIZZ_FB), 0x10), null);
});

// ---- voteSlot -----------------------------------------------------------------------

test("voteSlot: one agreeing label is not enough", () => {
    assert.equal(voteSlot([[0x14], [null], []]), null);
});

test("voteSlot: no slots at all", () => {
    assert.equal(voteSlot([]), null);
    assert.equal(voteSlot([[null, null], [null]]), null);
});

test("voteSlot: two slots with equally many labels disagree -> null", () => {
    assert.equal(voteSlot([[0x14], [0x14], [0x1c], [0x1c]]), null);
});

test("voteSlot: majority wins; repeats within one label count once", () => {
    assert.deepEqual(voteSlot([[0x14, 0x14, 0x14], [0x14], [0x1c]]), { slot: 0x14, labels: 2 });
    assert.equal(voteSlot([[0x14, 0x14, 0x14], [0x1c]]), null);
});

// ---- L2/L3: RTTI -> relative vtable ---------------------------------------------

for (const fx of FIXTURES) {
    test(`${fx.name}: RTTI chain resolves KeyDerivationImpl slot 0x14 to deriveSecret`, async () => {
        const img = new SparseImage(fx);
        const aps = await relativeVtablesFor(img, img, FIZZ_KDF_RTTI_NAME);
        assert.deepEqual(aps, [fx.kdfVtable]);
        assert.deepEqual(uniqueSlotTarget(img, aps, 0x14), { ap: fx.kdfVtable, target: fx.deriveSecret });
        assert.equal(vtableSlotTarget(img, fx.kdfVtable, 0x10), fx.expandLabel);
    });

    test(`${fx.name}: RTTI chain resolves HandshakeContextImpl slot +0x8 to appendToTranscript`, async () => {
        const img = new SparseImage(fx);
        const aps = await relativeVtablesFor(img, img, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME);
        assert.deepEqual(aps, [fx.handshakeContextVtable]);
        assert.equal(uniqueSlotTarget(img, aps, APPEND_TO_TRANSCRIPT_SLOT)?.target, fx.appendToTranscript);
        assert.equal(isAlignedCodeEntry(img, fx.appendToTranscript), true);
    });

    test(`${fx.name}: an address point is accepted only for its own class name`, () => {
        const img = new SparseImage(fx);
        assert.equal(addressPointMatchesRtti(img, fx.kdfVtable, FIZZ_KDF_RTTI_NAME), true);
        assert.equal(addressPointMatchesRtti(img, fx.kdfVtable, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME), false);
        assert.equal(addressPointMatchesRtti(img, fx.kdfVtable + 4, FIZZ_KDF_RTTI_NAME), false);
    });
}

test("the proxy slot's zero upper half (A = proxy - 4 trivially satisfies the equation) is rejected", async () => {
    const img = new SparseImage(FIZZ_FB);
    const proxy = 0x28fc100;
    assert.ok((await img.relativeRefs(proxy)).includes(proxy - 4));
    assert.equal(addressPointMatchesRtti(img, proxy, FIZZ_KDF_RTTI_NAME), false);
});

test("uniqueSlotTarget: address points with different targets are ambiguous", () => {
    const img = new SparseImage(FIZZ_FB);
    assert.equal(uniqueSlotTarget(img, [FIZZ_FB.kdfVtable, FIZZ_FB.handshakeContextVtable], 0x14), null);
    assert.equal(uniqueSlotTarget(img, [], 0x14), null);
});

// ---- body validation -----------------------------------------------------------

for (const fx of FIXTURES) {
    test(`${fx.name}: deriveSecret body validates (x5/x6 saved, sub x?,x4,x3, "tls13 " via its vtable)`, () => {
        const img = new SparseImage(fx);
        assert.equal(validateDeriveSecretBody(img, fx.deriveSecret, fx.kdfVtable), true);
        assert.equal(referencesCString(img, fx.expandLabel, "tls13 "), true);
    });

    test(`${fx.name}: other functions and an unresolved vtable do not validate as deriveSecret`, () => {
        const img = new SparseImage(fx);
        assert.equal(validateDeriveSecretBody(img, fx.expandLabel, fx.kdfVtable), false);
        assert.equal(validateDeriveSecretBody(img, fx.appendToTranscript, fx.kdfVtable), false);
        // "tls13 " is reached only through the vtable call in both builds.
        assert.equal(validateDeriveSecretBody(img, fx.deriveSecret, null), false);
    });
}

test("deriveSecret without the x5 save does not validate", () => {
    // FB: mov x21, x5 @0xbfa164.
    const img = new SparseImage(FIZZ_FB, { 0xbfa164: NOP });
    assert.equal(validateDeriveSecretBody(img, FIZZ_FB.deriveSecret, FIZZ_FB.kdfVtable), false);
});

test("deriveSecret without `sub x8, x4, x3` does not validate", () => {
    // IG: sub x8, x4, x3 @0x356dec.
    const img = new SparseImage(FIZZ_IG, { 0x356dec: NOP });
    assert.equal(validateDeriveSecretBody(img, FIZZ_IG.deriveSecret, FIZZ_IG.kdfVtable), false);
});

test("isAlignedCodeEntry rejects misaligned, non-code and unreadable offsets", () => {
    const img = new SparseImage(FIZZ_FB);
    assert.equal(isAlignedCodeEntry(img, FIZZ_FB.appendToTranscript + 2), false);
    assert.equal(isAlignedCodeEntry(img, FIZZ_FB.codeEnd + 0x100), false);
    assert.equal(isAlignedCodeEntry(img, 0x1000), false);
});

// ---- whole pipeline + learned re-validation --------------------------------------

for (const fx of FIXTURES) {
    test(`${fx.name}: locateFizzInImage finds deriveSecret, appendToTranscript and slot 0x14`, async () => {
        const img = new SparseImage(fx);
        assert.deepEqual(await locateFizzInImage(img, img), {
            ok: true,
            location: {
                deriveSecret: fx.deriveSecret, appendToTranscript: fx.appendToTranscript, slot: 0x14,
                kdfVtable: fx.kdfVtable, handshakeContextVtable: fx.handshakeContextVtable, agreeingLabels: 6,
            },
        });
    });

    test(`${fx.name}: a learned location re-validates; a wrong slot or address does not`, () => {
        const img = new SparseImage(fx);
        const loc = {
            deriveSecret: fx.deriveSecret, appendToTranscript: fx.appendToTranscript, slot: 0x14,
            kdfVtable: fx.kdfVtable, handshakeContextVtable: fx.handshakeContextVtable,
        };
        assert.equal(revalidateFizzLocation(img, loc), true);
        assert.equal(revalidateFizzLocation(img, { ...loc, slot: 0x10 }), false);
        assert.equal(revalidateFizzLocation(img, { ...loc, appendToTranscript: fx.appendToTranscript + 4 }), false);
        assert.equal(revalidateFizzLocation(img, { ...loc, kdfVtable: fx.handshakeContextVtable }), false);
    });
}

test("locateFizzInImage fails closed without label strings", async () => {
    const img = new SparseImage(FIZZ_FB);
    const noLabels: FizzImageSearch = { ...bindSearch(img), cStrings: async (t) => t.map(() => []) };
    const result = await locateFizzInImage(img, noLabels);
    assert.equal(result.ok, false);
});

test("locateFizzInImage fails closed when the RTTI name is absent", async () => {
    const img = new SparseImage(FIZZ_IG);
    const base = bindSearch(img);
    const noRtti: FizzImageSearch = {
        ...base,
        cStrings: async (t) => (t[0] === FIZZ_KDF_RTTI_NAME ? [[]] : base.cStrings(t)),
    };
    assert.deepEqual(await locateFizzInImage(img, noRtti),
        { ok: false, why: "no unique KeyDerivationImpl vtable target for slot 0x14" });
});

function bindSearch(img: SparseImage): FizzImageSearch {
    return {
        cStrings: (t) => img.cStrings(t), pointerSlots: (t) => img.pointerSlots(t),
        relativeRefs: (t) => img.relativeRefs(t), loadSites: (t) => img.loadSites(t),
    };
}

// ---- relative-ref needles + cache names --------------------------------------------

function matchesNeedle(int32: number, needle: string): boolean {
    const [pat, mask] = needle.split(" : ").map((h) => h.split(" ").map((b) => parseInt(b, 16)));
    const bytes = [(int32 >>> 16) & 0xff, (int32 >>> 24) & 0xff];
    return bytes.every((b, i) => (b & mask[i]) === (pat[i] & mask[i]));
}

test("relativeRefNeedles cover the real RTTI components (FB KDF/HC, IG KDF) in their 1 MB chunk", () => {
    const cases = [
        { component: FIZZ_FB.kdfVtable - 4, proxy: 0x28fc100 },
        { component: FIZZ_FB.handshakeContextVtable - 4, proxy: 0x28fc0f8 },
        { component: FIZZ_IG.kdfVtable - 4, proxy: 0xeb6468 },
    ];
    for (const { component, proxy } of cases) {
        const chunk = Math.floor(component / 0x100000) * 0x100000;
        const value = proxy - (component + 4);
        const needles = relativeRefNeedles(proxy, chunk, 0x100000);
        assert.ok(needles.length >= 1 && needles.length <= 2);
        assert.ok(needles.some((n) => matchesNeedle(value, n)), `0x${component.toString(16)}`);
    }
});

test("relativeRefNeedles: negative values (target below the chunk) are covered too", () => {
    const target = 0x1000, chunk = 0x500000, a = chunk + 0x1234;
    assert.ok(relativeRefNeedles(target, chunk, 0x100000).some((n) => matchesNeedle(target - (a + 4), n)));
});

test("learned item names pass the host validator; miss marker carries a fingerprint", () => {
    for (const name of [LEARNED_FIZZ_DERIVE_SECRET, LEARNED_FIZZ_APPEND_TRANSCRIPT, LEARNED_FIZZ_KDF_VTABLE,
        LEARNED_FIZZ_HANDSHAKE_CONTEXT_VTABLE, LEARNED_FIZZ_DERIVE_SECRET_SLOT, LEARNED_FIZZ_DERIVE_SECRET_MISS]) {
        assert.equal(isLearnedItemName(name), true, name);
    }
    assert.equal(LEARNED_FIZZ_DERIVE_SECRET_MISS, "fizz.miss.derive_secret");
    assert.equal(isValidLayoutValue(LEARNED_FIZZ_KDF_VTABLE, FIZZ_FB.kdfVtable), true);
    assert.equal(isValidLayoutValue(LEARNED_FIZZ_DERIVE_SECRET_SLOT, 0x14), true);
    assert.equal(FIZZ_LOCATOR_MISS_FINGERPRINT, missFingerprint([...FIZZ_VOTING_LABELS, FIZZ_KDF_RTTI_NAME,
        FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME, "revision", "2"]));
});

test("miss markers written by the revision-1 locator (r-x .rodata skipped) no longer match", () => {
    const revision1 = missFingerprint([...FIZZ_VOTING_LABELS, FIZZ_KDF_RTTI_NAME, FIZZ_HANDSHAKE_CONTEXT_RTTI_NAME,
        "revision", "1"]);
    assert.notEqual(FIZZ_LOCATOR_MISS_FINGERPRINT, revision1);
});

// ---- where each artefact is mapped (segment protections) ---------------------------

test("rangeHoldsArtefact: .rodata artefacts in r-- or r-x, relocated ones in r-- or rw-", () => {
    const cases: [string, FizzArtefactRegion, boolean][] = [
        ["r--", "rodata", true], ["r-x", "rodata", true], ["rw-", "rodata", false], ["rwx", "rodata", false],
        ["r--", "relocated", true], ["rw-", "relocated", true], ["r-x", "relocated", false], ["rwx", "relocated", false],
        ["---", "rodata", false], ["---", "relocated", false], ["--x", "rodata", false],
    ];
    for (const [protection, region, held] of cases) assert.equal(rangeHoldsArtefact(protection, region), held, `${protection} ${region}`);
});

test("rangesHolding lists non-executable ranges before executable ones", () => {
    const ranges = [{ protection: "r-x", id: 1 }, { protection: "rw-", id: 2 }, { protection: "r--", id: 3 }];
    assert.deepEqual(rangesHolding(ranges, "rodata").map((r) => r.id), [3, 1]);
    assert.deepEqual(rangesHolding(ranges, "relocated").map((r) => r.id), [2, 3]);
});

/** The fixture segment holding `off`. */
function segmentAt(fx: FizzFixtureImage, off: number): FixtureSegment | undefined {
    return fx.segments.find((g) => off >= g.off && off < g.off + g.size);
}

for (const fx of FIXTURES) {
    test(`${fx.name}: names and relative vtables sit in the r-x segment, typeinfos and proxies in RELRO r--`, async () => {
        // The real layout (no -z separate-code): what the on-device regression got wrong.
        const img = new SparseImage(fx);
        const [kdfName] = await img.cStrings([FIZZ_KDF_RTTI_NAME]);
        for (const off of [kdfName[0], fx.kdfVtable, fx.handshakeContextVtable]) {
            assert.equal(segmentAt(fx, off)?.protection, "r-x", `0x${off.toString(16)}`);
        }
        const [nameField] = await img.pointerSlots(kdfName[0]);
        const [proxy] = await img.pointerSlots(nameField - 8);
        for (const off of [nameField, proxy]) assert.equal(segmentAt(fx, off)?.protection, "r--", `0x${off.toString(16)}`);
        assert.ok((await img.relativeRefs(proxy)).includes(fx.kdfVtable - 4));
    });

    test(`${fx.name}: the Frida range lists cover each artefact (moduleRodataRanges / moduleDataRanges)`, () => {
        const base = 0x7000000000;
        const mod = {
            base: { add: (o: number) => base + o }, size: 0,
            enumerateRanges: () => fx.segments.map((g) => ({ base: { v: base + g.off }, size: g.size, protection: g.protection })),
        } as unknown as Module;
        const offs = (ranges: { base: unknown; size: number }[]) =>
            ranges.map((r) => [(r.base as { v: number }).v - base, r.size] as [number, number]);
        const covers = (ranges: [number, number][], off: number) => ranges.some(([lo, n]) => off >= lo && off < lo + n);
        const rodata = offs(moduleRodataRanges(mod)), data = offs(moduleDataRanges(mod));
        assert.ok(covers(rodata, fx.kdfVtable - 4) && covers(rodata, fx.handshakeContextVtable - 4));
        assert.ok(!covers(data, fx.kdfVtable - 4), "relocated ranges exclude the r-x segment");
        assert.ok(rodata.every(([lo]) => segmentAt(fx, lo)?.protection !== "rw-"), "writable ranges are never rodata");
    });
}

// ---- whole-ELF harness: the real libraries mapped with their real protections -------
//
// Skips unless the pulled libraries are present (they are NOT committed; dev/fizz/bins is
// gitignored; FRITAP_FIZZ_BINS overrides the directory). Maps every PT_LOAD at its vaddr
// with PT_GNU_RELRO remapped r-- (page-rounded, as /proc/<pid>/maps shows them), applies
// the RELA R_AARCH64_RELATIVE addends (RELR slots already hold the vaddr in the file), and
// runs the full locate pipeline over the whole image.

const FIZZ_BINS = process.env.FRITAP_FIZZ_BINS
    ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..", "dev", "fizz", "bins");
const PAGE = 0x1000;
const PT_LOAD = 1, PT_NOTE = 4, PT_GNU_RELRO = 0x6474e552, SHT_RELA = 4, R_AARCH64_RELATIVE = 1027;

function protectionOf(flags: number): string {
    return (flags & 4 ? "r" : "-") + (flags & 2 ? "w" : "-") + (flags & 1 ? "x" : "-");
}

interface ElfImage extends DecodedImage { buildId: string; }

/** Decodes an ELF64 little-endian shared object into a vaddr-addressed image (pure, test-only). */
function decodeElf(file: Buffer): ElfImage {
    const phoff = Number(file.readBigUInt64LE(0x20)), phentsize = file.readUInt16LE(0x36), phnum = file.readUInt16LE(0x38);
    const phdrs = Array.from({ length: phnum }, (_v, i) => {
        const at = phoff + i * phentsize;
        return {
            type: file.readUInt32LE(at), flags: file.readUInt32LE(at + 4), offset: Number(file.readBigUInt64LE(at + 8)),
            vaddr: Number(file.readBigUInt64LE(at + 16)), filesz: Number(file.readBigUInt64LE(at + 32)),
            memsz: Number(file.readBigUInt64LE(at + 40)),
        };
    });
    const loads = phdrs.filter((p) => p.type === PT_LOAD);
    const bytes = new Uint8Array(Math.max(...loads.map((p) => p.vaddr + p.memsz)));
    for (const p of loads) bytes.set(file.subarray(p.offset, p.offset + p.filesz), p.vaddr);
    applyRelativeRelas(file, bytes);
    const relro = phdrs.filter((p) => p.type === PT_GNU_RELRO);
    const segments: FixtureSegment[] = [];
    for (const p of loads) {
        let lo = Math.floor(p.vaddr / PAGE) * PAGE;
        const hi = Math.ceil((p.vaddr + p.memsz) / PAGE) * PAGE;
        for (const r of relro) {
            const rlo = Math.floor(r.vaddr / PAGE) * PAGE, rhi = Math.min(hi, Math.floor((r.vaddr + r.memsz) / PAGE) * PAGE);
            if (rlo < lo || rlo >= hi || rhi <= rlo) continue;
            if (lo < rlo) segments.push({ off: lo, size: rlo - lo, protection: protectionOf(p.flags) });
            segments.push({ off: rlo, size: rhi - rlo, protection: "r--" });
            lo = rhi;
        }
        if (lo < hi) segments.push({ off: lo, size: hi - lo, protection: protectionOf(p.flags) });
    }
    return { segments, regions: [{ off: 0, bytes }], buildId: gnuBuildId(file, phdrs.filter((p) => p.type === PT_NOTE)) };
}

/** Writes every RELA R_AARCH64_RELATIVE addend into its slot (load base 0). */
function applyRelativeRelas(file: Buffer, bytes: Uint8Array): void {
    const shoff = Number(file.readBigUInt64LE(0x28)), shentsize = file.readUInt16LE(0x3a), shnum = file.readUInt16LE(0x3c);
    const view = new DataView(bytes.buffer);
    for (let i = 0; i < shnum; i++) {
        const sh = shoff + i * shentsize;
        if (file.readUInt32LE(sh + 4) !== SHT_RELA) continue;
        const off = Number(file.readBigUInt64LE(sh + 24)), size = Number(file.readBigUInt64LE(sh + 32));
        for (let r = off; r + 24 <= off + size; r += 24) {
            if (Number(file.readBigUInt64LE(r + 8) & 0xffffffffn) !== R_AARCH64_RELATIVE) continue;
            const slot = Number(file.readBigUInt64LE(r));
            if (slot + 8 <= bytes.length) view.setBigInt64(slot, file.readBigInt64LE(r + 16), true);
        }
    }
}

/** Hex GNU build-id from the PT_NOTE segments ("" when absent). */
function gnuBuildId(file: Buffer, notes: { offset: number; filesz: number }[]): string {
    for (const n of notes) {
        for (let at = n.offset; at + 12 <= n.offset + n.filesz;) {
            const namesz = file.readUInt32LE(at), descsz = file.readUInt32LE(at + 4), type = file.readUInt32LE(at + 8);
            const desc = at + 12 + Math.ceil(namesz / 4) * 4;
            if (type === 3 && file.toString("latin1", at + 12, at + 12 + namesz).startsWith("GNU")) {
                return file.subarray(desc, desc + descsz).toString("hex");
            }
            at = desc + Math.ceil(descsz / 4) * 4;
        }
    }
    return "";
}

const ELF_CASES = [
    { fx: FIZZ_FB, file: join(FIZZ_BINS, "fb", "libcoldstart.so") },
    { fx: FIZZ_IG, file: join(FIZZ_BINS, "ig", "libstartup.so") },
];

for (const { fx, file } of ELF_CASES) {
    const skip = existsSync(file) ? false : `pulled library absent: ${file}`;
    test(`${fx.name} (whole ELF, real segment protections): full locate`, { skip }, async () => {
        const elf = decodeElf(readFileSync(file));
        assert.equal(elf.buildId, fx.buildId, "a different build than the fixture's");
        assert.deepEqual(elf.segments, fx.segments, "the committed fixture encodes this file's protections");
        const img = new SparseImage(elf);
        assert.deepEqual(await locateFizzInImage(img, img), {
            ok: true,
            location: {
                deriveSecret: fx.deriveSecret, appendToTranscript: fx.appendToTranscript, slot: 0x14,
                kdfVtable: fx.kdfVtable, handshakeContextVtable: fx.handshakeContextVtable, agreeingLabels: 6,
            },
        });
    });
}
