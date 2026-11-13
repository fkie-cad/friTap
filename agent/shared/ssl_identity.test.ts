// Unit tests for the per-SSL* identity cache (client_random as the join key).
// Frida memory access is replaced by an injected fake reader.
//
// Run: npm run test:agent

import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import "./frida-test-stubs.js";

import {
    LAYOUT_USABLE_AFTER_DISTINCT_SSL,
    MAX_FAILED_OVERLAP_ATTEMPTS_PER_MODULE,
    SSL_IDENTITY_MAX,
    SslMemoryReader,
    clearSslLayout,
    forgetSslIdentity,
    isSslLayoutUsable,
    learnLayoutByOverlap,
    noteSslClientRandom,
    readSslClientRandom,
    resetSslIdentityState,
    setSslLayout,
    setSslMemoryReader,
    sslGeneration,
    sslIdentity,
    sslIdentityCacheSize,
    sslLayoutFor,
} from "./ssl_identity.js";

// ---------------------------------------------------------------------------
// Fake memory
// ---------------------------------------------------------------------------

function fakePtr(address: number): any {
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

/** Sparse fake address space: pointer slots and byte cells; anything unwritten faults. */
class FakeMemory implements SslMemoryReader {
    pointers = new Map<number, number>();
    bytes = new Map<number, number>();
    reads = 0;

    writePointer(address: number, value: number): void { this.pointers.set(address, value); }
    writeBytes(address: number, data: Uint8Array): void {
        data.forEach((b, i) => this.bytes.set(address + i, b));
    }
    readPointer(base: any, offset: number): any {
        this.reads++;
        const value = this.pointers.get(base.address + offset);
        return value === undefined || value < 0x1000 ? null : fakePtr(value);
    }
    readBytes(base: any, offset: number, length: number): Uint8Array | null {
        this.reads++;
        const out = new Uint8Array(length);
        for (let i = 0; i < length; i++) {
            const b = this.bytes.get(base.address + offset + i);
            if (b === undefined) return null;
            out[i] = b;
        }
        return out;
    }
    readU64(base: any, offset: number): any {
        const bytes = this.readBytes(base, offset, 8);  // counts as the one read
        return bytes === null ? null : fakeU64(bytes);
    }
}

function randomBytes(seed: number): Uint8Array {
    const out = new Uint8Array(32);
    let x = seed * 2654435761 >>> 0;
    for (let i = 0; i < 32; i++) {
        x = (x * 1103515245 + 12345) >>> 0;
        out[i] = (x >>> 16) & 0xff || 1;
    }
    return out;
}

function hex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Lay out an SSL* whose s3 pointer is at sslAddr+s3Off and cr at s3+crOff; s3 is zero-filled. */
function placeSsl(mem: FakeMemory, sslAddr: number, s3Addr: number, cr: Uint8Array, s3Off = 0x30, crOff = 0x30): void {
    mem.writePointer(sslAddr + s3Off, s3Addr);
    mem.writeBytes(s3Addr, new Uint8Array(0x140));
    mem.writeBytes(s3Addr + crOff, cr);
}

const MOD = "libmonochrome.so";
let mem: FakeMemory;

beforeEach(() => {
    resetSslIdentityState();
    mem = new FakeMemory();
    setSslMemoryReader(mem);
});

// ---------------------------------------------------------------------------
// Cache + generations
// ---------------------------------------------------------------------------

test("cache is bounded by SSL_IDENTITY_MAX", () => {
    for (let i = 0; i < SSL_IDENTITY_MAX + 50; i++) {
        noteSslClientRandom(fakePtr(0x100000 + i * 0x10), hex(randomBytes(i + 1)));
    }
    assert.equal(sslIdentityCacheSize(), SSL_IDENTITY_MAX);
});

test("note caches lower-cased cr; invalid or mostly-zero cr is ignored", () => {
    const ssl = fakePtr(0x5000);
    const cr = hex(randomBytes(7));
    noteSslClientRandom(ssl, cr.toUpperCase());
    assert.equal(sslIdentity(ssl)?.cr, cr);

    const other = fakePtr(0x6000);
    noteSslClientRandom(other, "00".repeat(32));
    noteSslClientRandom(other, "abc");
    assert.equal(sslIdentity(other), null);
});

test("generation is stable before and after the cr is learned", () => {
    const ssl = fakePtr(0x5000);
    const before = sslGeneration(ssl);
    noteSslClientRandom(ssl, hex(randomBytes(1)));
    assert.equal(sslIdentity(ssl)?.generation, before);
    noteSslClientRandom(ssl, hex(randomBytes(1)));
    assert.equal(sslGeneration(ssl), before);
});

test("forget starts a new generation on next sight", () => {
    const ssl = fakePtr(0x5000);
    noteSslClientRandom(ssl, hex(randomBytes(1)));
    const first = sslGeneration(ssl);
    forgetSslIdentity(ssl);
    assert.equal(sslIdentity(ssl), null);
    assert.notEqual(sslGeneration(ssl), first);
});

test("a different cr on the same SSL* (reuse without SSL_free) starts a new generation", () => {
    const ssl = fakePtr(0x5000);
    noteSslClientRandom(ssl, hex(randomBytes(1)));
    const first = sslGeneration(ssl);
    noteSslClientRandom(ssl, hex(randomBytes(2)));
    assert.equal(sslIdentity(ssl)?.cr, hex(randomBytes(2)));
    assert.notEqual(sslGeneration(ssl), first);
});

test("anchor mismatch on reused SSL* re-reads and bumps the generation", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
    const ssl = fakePtr(0x5000);
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    assert.equal(readSslClientRandom(ssl, MOD), hex(randomBytes(1)));
    const first = sslGeneration(ssl);

    placeSsl(mem, 0x5000, 0xa000, randomBytes(2));      // new s3 -> new connection
    assert.equal(readSslClientRandom(ssl, MOD), hex(randomBytes(2)));
    assert.notEqual(sslGeneration(ssl), first);
});

test("anchor hit costs two reads", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
    const ssl = fakePtr(0x5000);
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    readSslClientRandom(ssl, MOD);
    mem.reads = 0;
    assert.equal(readSslClientRandom(ssl, MOD), hex(randomBytes(1)));
    assert.equal(mem.reads, 2);
});

test("no negative caching: unknown before ClientHello, known after", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
    const ssl = fakePtr(0x5000);
    placeSsl(mem, 0x5000, 0x9000, new Uint8Array(32));   // zeros: before ClientHello
    assert.equal(readSslClientRandom(ssl, MOD), "");
    assert.equal(sslIdentity(ssl), null);
    mem.writeBytes(0x9000 + 0x30, randomBytes(3));
    assert.equal(readSslClientRandom(ssl, MOD), hex(randomBytes(3)));
});

test("faulting reads return unknown", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
    assert.equal(readSslClientRandom(fakePtr(0x7777), MOD), "");
    assert.equal(readSslClientRandom(fakePtr(0), MOD), "");
});

test("export fallback is used when no layout exists, and exceptions are swallowed", () => {
    const ssl = fakePtr(0x5000);
    const cr = hex(randomBytes(4));
    assert.equal(readSslClientRandom(ssl, MOD, () => cr.toUpperCase()), cr);
    assert.equal(sslIdentity(ssl), null, "an anchorless export cr is never served from the cache");
    assert.equal(readSslClientRandom(fakePtr(0x6000), MOD, () => { throw new Error("x"); }), "");
});

// ---------------------------------------------------------------------------
// Layouts: module isolation + validation state
// ---------------------------------------------------------------------------

test("layout of module A is not used for module B", () => {
    setSslLayout("A.so", { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    assert.equal(readSslClientRandom(fakePtr(0x5000), "B.so"), "");
    assert.equal(sslLayoutFor("B.so"), null);
    assert.equal(readSslClientRandom(fakePtr(0x5000), "A.so"), hex(randomBytes(1)));
});

test("stock layout becomes usable after 3 distinct plausible SSL*", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
    for (let i = 0; i < LAYOUT_USABLE_AFTER_DISTINCT_SSL; i++) {
        placeSsl(mem, 0x5000 + i * 0x100, 0x9000 + i * 0x200, randomBytes(i + 1));
    }
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), "");
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), "", "same SSL* twice counts once");
    assert.equal(readSslClientRandom(fakePtr(0x5100), MOD), "");
    assert.equal(isSslLayoutUsable(MOD), false);
    assert.equal(readSslClientRandom(fakePtr(0x5200), MOD), hex(randomBytes(3)));
    assert.equal(isSslLayoutUsable(MOD), true);
    assert.equal(sslLayoutFor(MOD)?.validated, false);
});

test("keylog note matching the layout read validates it", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(1)), MOD);
    assert.equal(sslLayoutFor(MOD)?.validated, true);
    assert.equal(isSslLayoutUsable(MOD), true);
});

test("keylog mismatch drops the layout and re-learns by overlap", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1), 0x38, 0x48);
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(1)), MOD);
    assert.deepEqual(sslLayoutFor(MOD), { s3Off: 0x38, crOff: 0x48, source: "learned", validated: true });
    assert.equal(sslIdentity(fakePtr(0x5000))?.cr, hex(randomBytes(1)));
});

test("keylog mismatch with nothing learnable leaves no layout", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(9)), MOD);
    assert.equal(sslLayoutFor(MOD), null);
    assert.equal(sslIdentity(fakePtr(0x5000))?.cr, hex(randomBytes(9)));
});

test("a validated layout is not replaced by an unvalidated one", () => {
    setSslLayout(MOD, { s3Off: 0x38, crOff: 0x48, source: "learned", validated: true });
    assert.equal(setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false }), false);
    assert.equal(sslLayoutFor(MOD)?.s3Off, 0x38);
    clearSslLayout(MOD);
    assert.equal(sslLayoutFor(MOD), null);
});

// ---------------------------------------------------------------------------
// Overlap learning
// ---------------------------------------------------------------------------

test("overlap learning finds s3Off and crOff", () => {
    placeSsl(mem, 0x5000, 0x9000, randomBytes(5), 0x2c, 0x88);
    const learned = learnLayoutByOverlap(fakePtr(0x5000), hex(randomBytes(5)), mem);
    assert.deepEqual(learned, { s3Off: 0x2c, crOff: 0x88, source: "learned", validated: true });
});

test("overlap learning rejects ambiguous matches", () => {
    placeSsl(mem, 0x5000, 0x9000, randomBytes(5), 0x30, 0x30);
    mem.writeBytes(0x9000 + 0x70, randomBytes(5));          // second copy of the same cr
    assert.equal(learnLayoutByOverlap(fakePtr(0x5000), hex(randomBytes(5)), mem), null);
});

test("overlap learning returns null when no slot matches", () => {
    placeSsl(mem, 0x5000, 0x9000, randomBytes(5));
    assert.equal(learnLayoutByOverlap(fakePtr(0x5000), hex(randomBytes(6)), mem), null);
});

test("note without layout learns one for that module only", () => {
    placeSsl(mem, 0x5000, 0x9000, randomBytes(5), 0x30, 0x30);
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(5)), MOD);
    assert.equal(sslLayoutFor(MOD)?.source, "learned");
    assert.equal(sslLayoutFor("other.so"), null);
});

test("overlap learning stops after repeated failures for a module", () => {
    for (let i = 0; i < MAX_FAILED_OVERLAP_ATTEMPTS_PER_MODULE; i++) {
        noteSslClientRandom(fakePtr(0x5000 + i * 0x10), hex(randomBytes(i + 1)), MOD);
    }
    placeSsl(mem, 0x8000, 0x9000, randomBytes(99));
    mem.reads = 0;
    noteSslClientRandom(fakePtr(0x8000), hex(randomBytes(99)), MOD);
    assert.equal(mem.reads, 0);
    assert.equal(sslLayoutFor(MOD), null);
});

// ---------------------------------------------------------------------------
// Layout-locator settle tracking (consumed by the caller_stack send policy, B5)
// ---------------------------------------------------------------------------

import { markLayoutLocatorStarted, markLayoutLocatorSettled, isLayoutLocatorSettled } from "./ssl_identity.js";

test("a module whose layout locator never started is settled", () => {
    assert.equal(isLayoutLocatorSettled("libnever.so"), true);
});

test("a started layout locator is pending until settled; reset clears it", () => {
    markLayoutLocatorStarted("libchrome.so");
    assert.equal(isLayoutLocatorSettled("libchrome.so"), false);
    markLayoutLocatorSettled("libchrome.so");
    assert.equal(isLayoutLocatorSettled("libchrome.so"), true);
    markLayoutLocatorStarted("libchrome.so");
    resetSslIdentityState();
    assert.equal(isLayoutLocatorSettled("libchrome.so"), true);
});

// ---------------------------------------------------------------------------
// Trust model (on-device P1 gap: one-connection apps never reached 3 SSL*)
// ---------------------------------------------------------------------------

import {
    MIN_DISTINCT_CR_BYTE_VALUES, distinctByteValues, looksLikeRandomBytes, setClientRandomMissObserver,
} from "./ssl_identity.js";

/** 32 bytes cycling through `distinct` non-zero values (low entropy, not mostly zero). */
function lowEntropyBytes(distinct: number): Uint8Array {
    return Uint8Array.from({ length: 32 }, (_, i) => 0x41 + (i % distinct));
}

test("test fixture: randomBytes passes the low-entropy guard", () => {
    for (let seed = 1; seed < 200; seed++) assert.equal(looksLikeRandomBytes(randomBytes(seed)), true, `seed ${seed}`);
});

test("distinctByteValues counts distinct values; guard threshold is 16", () => {
    assert.equal(MIN_DISTINCT_CR_BYTE_VALUES, 16);
    assert.equal(distinctByteValues(lowEntropyBytes(5)), 5);
    assert.equal(looksLikeRandomBytes(lowEntropyBytes(MIN_DISTINCT_CR_BYTE_VALUES - 1)), false);
    assert.equal(looksLikeRandomBytes(lowEntropyBytes(MIN_DISTINCT_CR_BYTE_VALUES)), true);
});

test("decoded layout is usable immediately on a single SSL* (still unvalidated)", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    assert.equal(isSslLayoutUsable(MOD), true);
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), hex(randomBytes(1)));
    assert.equal(sslLayoutFor(MOD)?.validated, false);
});

test("decoded layout: low-entropy bytes behind it are rejected per read", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    placeSsl(mem, 0x5000, 0x9000, lowEntropyBytes(8));
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), "");
    assert.equal(sslIdentity(fakePtr(0x5000)), null);
});

test("decoded layout: unreadable s3 or mostly-zero bytes give unknown", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), "", "s3 slot unreadable");
    placeSsl(mem, 0x6000, 0xa000, new Uint8Array(32));
    assert.equal(readSslClientRandom(fakePtr(0x6000), MOD), "", "mostly zero");
});

test("stock layout is upgraded to usable by a decoded layout with the same offsets", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), "");
    assert.equal(isSslLayoutUsable(MOD), false);
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    assert.equal(isSslLayoutUsable(MOD), true);
    assert.equal(readSslClientRandom(fakePtr(0x5000), MOD), hex(randomBytes(1)));
});

test("a keylog-validated stock layout stays validated when the same decoded layout arrives", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "stock", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(1)), MOD);
    assert.equal(setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false }), true);
    assert.deepEqual(sslLayoutFor(MOD), { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: true });
});

test("keylog mismatch drops a (usable) decoded layout", () => {
    setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "decoded", validated: false });
    placeSsl(mem, 0x5000, 0x9000, randomBytes(1));
    noteSslClientRandom(fakePtr(0x5000), hex(randomBytes(9)), MOD);
    assert.equal(sslLayoutFor(MOD), null);
    assert.equal(isSslLayoutUsable(MOD), false);
});

// ---------------------------------------------------------------------------
// client_random miss observer (drives ssl_layout_autolocate.ts)
// ---------------------------------------------------------------------------

function observeMisses(): string[] {
    const misses: string[] = [];
    setClientRandomMissObserver((module) => { misses.push(module); });
    return misses;
}

test("a miss on a module without a started locator is reported; a hit is not", () => {
    const misses = observeMisses();
    try {
        assert.equal(readSslClientRandom(fakePtr(0x5000), "libhttpengine.so"), "");
        assert.deepEqual(misses, ["libhttpengine.so"]);
        setSslLayout(MOD, { s3Off: 0x30, crOff: 0x30, source: "learned", validated: true });
        placeSsl(mem, 0x6000, 0x9000, randomBytes(2));
        readSslClientRandom(fakePtr(0x6000), MOD);
        assert.deepEqual(misses, ["libhttpengine.so"]);
    } finally {
        setClientRandomMissObserver(null);
    }
});

test("no miss is reported once a locator was started (even after it settled), nor for an empty module", () => {
    const misses = observeMisses();
    try {
        markLayoutLocatorStarted("libchrome.so");
        markLayoutLocatorSettled("libchrome.so");
        readSslClientRandom(fakePtr(0x5000), "libchrome.so");
        readSslClientRandom(fakePtr(0x5000), "");
        assert.deepEqual(misses, []);
    } finally {
        setClientRandomMissObserver(null);
    }
});

test("a throwing miss observer never breaks the read", () => {
    setClientRandomMissObserver(() => { throw new Error("boom"); });
    try {
        assert.equal(readSslClientRandom(fakePtr(0x5000), "libx.so"), "");
    } finally {
        setClientRandomMissObserver(null);
    }
});

// ---------------------------------------------------------------------------
// peekSslGeneration: non-creating, survives forgetSslIdentity (SSL_free hook order)
// ---------------------------------------------------------------------------

import { peekSslGeneration } from "./ssl_identity.js";

test("peekSslGeneration never creates a generation for an unseen SSL*", () => {
    assert.equal(peekSslGeneration(fakePtr(0x5100)), null);
    assert.equal(sslIdentityCacheSize(), 0);
});

test("peekSslGeneration returns the live generation, and the retired one right after forget", () => {
    const ssl = fakePtr(0x5200);
    const generation = sslGeneration(ssl);
    assert.equal(peekSslGeneration(ssl), generation);
    forgetSslIdentity(ssl);
    assert.equal(peekSslGeneration(ssl), generation, "the freed connection's generation, not a new one");
    assert.equal(sslIdentityCacheSize(), 0, "peeking re-created nothing");
    const next = sslGeneration(ssl);
    assert.notEqual(next, generation);
    assert.equal(peekSslGeneration(ssl), next, "a live entry wins over the retired record");
});

// ---------------------------------------------------------------------------
// Anchorless identities: an export-derived cr is never served from the cache
// (a reused SSL* address would keep the previous connection's cr forever)
// ---------------------------------------------------------------------------

test("export-derived cr is re-read through the export, so a reused SSL* gets the new cr", () => {
    const ssl = fakePtr(0x5300);
    const first = hex(randomBytes(31));
    const second = hex(randomBytes(32));
    assert.equal(readSslClientRandom(ssl, MOD, () => first), first);
    const generation = sslGeneration(ssl);
    let exportCalls = 0;
    assert.equal(readSslClientRandom(ssl, MOD, () => { exportCalls++; return second; }), second);
    assert.equal(exportCalls, 1, "the export is called again, not the anchorless cache");
    assert.notEqual(sslGeneration(ssl), generation, "the new cr starts a new generation");
});

test("export-derived cr is not served to export-less lookups either", () => {
    const ssl = fakePtr(0x5400);
    readSslClientRandom(ssl, MOD, () => hex(randomBytes(33)));
    assert.equal(sslIdentity(ssl), null);
    assert.equal(readSslClientRandom(ssl, MOD), "");
});

test("keylog-noted cr without a layout: served to export-less lookups, the export path asks the export first", () => {
    const ssl = fakePtr(0x5500);
    const noted = hex(randomBytes(34));
    const exported = hex(randomBytes(35));
    noteSslClientRandom(ssl, noted);
    assert.equal(sslIdentity(ssl)?.cr, noted);
    assert.equal(readSslClientRandom(ssl, MOD), noted);
    assert.equal(readSslClientRandom(ssl, MOD, () => exported), exported, "a fresh export wins over an anchorless note");
});

test("keylog-noted cr without a layout is the fallback when the export yields nothing", () => {
    const ssl = fakePtr(0x5600);
    const noted = hex(randomBytes(36));
    noteSslClientRandom(ssl, noted);
    assert.equal(readSslClientRandom(ssl, MOD, () => ""), noted);
});

test("a new handshake note on the same SSL* replaces an anchorless noted cr", () => {
    const ssl = fakePtr(0x5700);
    noteSslClientRandom(ssl, hex(randomBytes(37)));
    const next = hex(randomBytes(38));
    noteSslClientRandom(ssl, next);
    assert.equal(sslIdentity(ssl)?.cr, next);
});
