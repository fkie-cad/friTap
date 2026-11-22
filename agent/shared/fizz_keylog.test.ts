// Unit tests for the pure Fizz binding core (fizz_keylog.ts FizzHandshakeBinder) and
// the label self-check, with synthetic TLS 1.3 handshake messages hashed by node:crypto:
// CH||SH transcript-hash binding, SHA-384, PSK ClientHello appended in two parts, HRR,
// carried binding, unbound queue, dedupe (F2/F2, F1/F2, F1 KeyUpdate) and caps.
//
// Run: npm run test:agent

import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import "./frida-test-stubs.js";
import {
    FizzHandshakeBinder, newFizzLabelSelfCheck, FIZZ_LABEL_MISMATCH_LIMIT, FIZZ_NSS_LABELS, FIZZ_PROBE_LABELS,
    HANDSHAKE_HEADER_LEN, isKnownFizzLabel, MAX_APPEND_BYTES, MAX_CHUNKS_PER_CONTEXT, MAX_CONTEXTS, MAX_PENDING_SECRETS,
    TLS_MESSAGE_HASH, readIOBufChain, type FizzHashAlg, type FizzSecretEvent,
} from "./fizz_keylog.js";
import { resetReadableCache } from "../util/safe_memory.js";

// ---- synthetic TLS messages --------------------------------------------------------

function handshake(type: number, body: Uint8Array): Uint8Array {
    const out = new Uint8Array(4 + body.length);
    out.set([type, (body.length >>> 16) & 0xff, (body.length >>> 8) & 0xff, body.length & 0xff]);
    out.set(body, 4);
    return out;
}

function filled(length: number, seed: number): Uint8Array {
    return Uint8Array.from({ length }, (_v, i) => (seed * 31 + i * 7) & 0xff);
}

/** ClientHello: legacy_version 0x0303, random, then `rest` filler bytes. */
function clientHello(random: Uint8Array, rest = 200): Uint8Array {
    const body = new Uint8Array(2 + 32 + rest);
    body.set([0x03, 0x03]);
    body.set(random, 2);
    body.set(filled(rest, random[0]), 34);
    return handshake(1, body);
}

const serverHello = (seed: number) => handshake(2, filled(90, seed));
const encryptedExtensions = handshake(8, filled(30, 8));
const certificate = handshake(11, filled(1500, 11));
const certificateVerify = handshake(15, filled(260, 15));
const finished = handshake(20, filled(32, 20));

function concat(...parts: Uint8Array[]): Uint8Array {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
}

const nodeHash = (alg: FizzHashAlg, chunks: Uint8Array[]) => {
    const h = createHash(alg);
    for (const c of chunks) h.update(c);
    return h.digest("hex");
};

function digest(alg: FizzHashAlg, ...parts: Uint8Array[]): Uint8Array {
    return Uint8Array.from(createHash(alg).update(concat(...parts)).digest());
}

const hexOf = (b: Uint8Array) => Buffer.from(b).toString("hex");

function newBinder(): { binder: FizzHandshakeBinder; lines: string[]; hashCalls: () => number } {
    const lines: string[] = [];
    let calls = 0;
    const binder = new FizzHandshakeBinder((alg, chunks) => { calls++; return nodeHash(alg, chunks); }, (l) => lines.push(l));
    return { binder, lines, hashCalls: () => calls };
}

function secretEvent(label: string, messageHash: Uint8Array | null, secret: Uint8Array,
                     deriver = "0xd1", threadId = 7): FizzSecretEvent {
    return { deriver, threadId, label, messageHash, secret };
}

const RANDOM_A = filled(32, 0xa1);
const RANDOM_B = filled(32, 0xb2);
const SECRET_1 = filled(32, 1);
const SECRET_2 = filled(32, 2);

// ---- exact transcript-hash binding ----------------------------------------------------

test("c hs traffic binds by Hash(CH||SH) to the ClientHello random", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(1);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    const out = binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1));
    assert.deepEqual(out, [`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(SECRET_1)}`]);
    assert.deepEqual(lines, out);
});

test("the right handshake is picked among several concurrent ones", () => {
    const { binder } = newBinder();
    const chA = clientHello(RANDOM_A), chB = clientHello(RANDOM_B), shA = serverHello(1), shB = serverHello(2);
    binder.onTranscriptAppend("0xa", chA);
    binder.onTranscriptAppend("0xb", chB);
    binder.onTranscriptAppend("0xb", shB);
    binder.onTranscriptAppend("0xa", shA);
    const out = binder.onSecret(secretEvent("s hs traffic", digest("sha256", chB, shB), SECRET_2));
    assert.deepEqual(out, [`SERVER_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_B)} ${hexOf(SECRET_2)}`]);
});

test("a 48-byte messageHash binds with SHA-384", () => {
    const { binder } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(3);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    const secret = filled(48, 9);
    const out = binder.onSecret(secretEvent("c hs traffic", digest("sha384", ch, sh), secret));
    assert.deepEqual(out, [`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(secret)}`]);
});

test("full handshake: early, handshake, application and exporter secrets all bind exactly", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(4);
    for (const m of [ch, sh, encryptedExtensions, certificate, certificateVerify, finished]) binder.onTranscriptAppend("0xc1", m);
    const hCh = digest("sha256", ch);
    const hHs = digest("sha256", ch, sh);
    const hAp = digest("sha256", ch, sh, encryptedExtensions, certificate, certificateVerify, finished);
    const events: [string, Uint8Array][] = [
        ["c e traffic", hCh], ["e exp master", hCh], ["c hs traffic", hHs], ["s hs traffic", hHs],
        ["c ap traffic", hAp], ["s ap traffic", hAp], ["exp master", hAp],
    ];
    events.forEach(([label, h], i) => binder.onSecret(secretEvent(label, h, filled(32, 40 + i), `0xd${i}`)));
    assert.deepEqual(lines, events.map(([label], i) => `${FIZZ_NSS_LABELS[label]} ${hexOf(RANDOM_A)} ${hexOf(filled(32, 40 + i))}`));
    assert.equal(binder.summary().bound, 7);
    assert.equal(binder.summary().carried, 0);
});

test("skipped labels (derived, binders, res master, traffic upd) never produce lines", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A);
    binder.onTranscriptAppend("0xc1", ch);
    for (const label of ["derived", "res binder", "ext binder", "res master", "traffic upd"]) {
        binder.onSecret(secretEvent(label, digest("sha256", ch), SECRET_1));
    }
    assert.deepEqual(lines, []);
    assert.equal(binder.summary().unbound, 0);
});

// ---- PSK two-part ClientHello and HRR ------------------------------------------------

test("PSK ClientHello appended in two parts (truncated CH + binders) binds c e traffic = Hash(CH)", () => {
    const { binder } = newBinder();
    const ch = clientHello(RANDOM_A, 600);
    // Binders chunk starting with 0x01: must be taken as the CH's continuation, not a new ClientHello.
    const cut = ch.length - 291;
    const part1 = ch.subarray(0, cut), part2 = Uint8Array.from(ch.subarray(cut));
    part2[0] = 0x01;
    const fullCh = concat(part1, part2);
    binder.onTranscriptAppend("0xbinder", part1);
    binder.onTranscriptAppend("0xbinder", part2);
    const out = binder.onSecret(secretEvent("c e traffic", digest("sha256", fullCh), SECRET_1));
    assert.deepEqual(out, [`CLIENT_EARLY_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(SECRET_1)}`]);
    assert.equal(binder.summary().contexts, 1);
});

test("the main context re-appending the full CH binds the same random (no ambiguity)", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A, 300), sh = serverHello(5);
    binder.onTranscriptAppend("0xbinder", ch.subarray(0, 250));
    binder.onTranscriptAppend("0xbinder", ch.subarray(250));
    binder.onTranscriptAppend("0xmain", ch);
    binder.onTranscriptAppend("0xmain", sh);
    binder.onSecret(secretEvent("c e traffic", digest("sha256", ch), SECRET_1));
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_2));
    assert.equal(lines.length, 2);
    assert.ok(lines.every((l) => l.includes(hexOf(RANDOM_A))));
});

test("HRR: message_hash(254) starts a new context; CH2 sets its random; c hs binds over the whole transcript", () => {
    const { binder } = newBinder();
    const ch1 = clientHello(RANDOM_A, 120), ch2 = clientHello(RANDOM_A, 160);
    const messageHash = handshake(TLS_MESSAGE_HASH, digest("sha256", ch1));
    const hrr = serverHello(6), sh = serverHello(7);
    binder.onTranscriptAppend("0xc1", ch1);
    binder.onTranscriptAppend("0xc2", messageHash);
    binder.onTranscriptAppend("0xc2", hrr);
    binder.onTranscriptAppend("0xc2", ch2);
    binder.onTranscriptAppend("0xc2", sh);
    const out = binder.onSecret(secretEvent("c hs traffic", digest("sha256", messageHash, hrr, ch2, sh), SECRET_1));
    assert.deepEqual(out, [`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(SECRET_1)}`]);
    assert.equal(binder.summary().contexts, 1); // CH2 joins the HRR context, it is not a new one
});

test("messages of an unknown context (no ClientHello seen) are ignored", () => {
    const { binder, lines } = newBinder();
    const sh = serverHello(8);
    binder.onTranscriptAppend("0xorphan", sh);
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", sh), SECRET_1));
    assert.deepEqual(lines, []);
});

// ---- carried binding and the unbound queue ----------------------------------------------

test("a non-matching hash is carried only from the same deriver+thread after an exact match", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(9);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1, "0xd1", 7));
    const unknownHash = filled(32, 99);
    binder.onSecret(secretEvent("c ap traffic", unknownHash, SECRET_2, "0xd1", 7));    // carried
    binder.onSecret(secretEvent("s ap traffic", unknownHash, filled(32, 3), "0xd2", 7)); // other deriver
    binder.onSecret(secretEvent("exp master", unknownHash, filled(32, 4), "0xd1", 8));   // other thread
    assert.deepEqual(lines.slice(1), [`CLIENT_TRAFFIC_SECRET_0 ${hexOf(RANDOM_A)} ${hexOf(SECRET_2)}`]);
    assert.equal(binder.summary().carried, 1);
    assert.equal(binder.summary().unbound, 2);
});

test("an unmatched c hs traffic resets the carried binding (no stale random from an earlier handshake)", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(10);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1));
    binder.onSecret(secretEvent("c hs traffic", filled(32, 77), SECRET_2));   // new handshake, transcript unseen
    binder.onSecret(secretEvent("c ap traffic", filled(32, 78), filled(32, 5)));
    assert.equal(lines.length, 1);
    assert.equal(binder.summary().unbound, 2);
});

test("unbound secrets wait in the pending queue and bind once their transcript is recorded", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_B), sh = serverHello(11);
    assert.deepEqual(binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1)), []);
    assert.equal(binder.pendingCount, 1);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    const out = binder.onSecret(secretEvent("derived", null, SECRET_2)); // any later secret retries the queue
    assert.deepEqual(out, [`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_B)} ${hexOf(SECRET_1)}`]);
    assert.deepEqual(lines, out);
    assert.equal(binder.pendingCount, 0);
});

test("the pending queue is capped; dropped secrets still count as unbound", () => {
    const { binder } = newBinder();
    for (let i = 0; i < MAX_PENDING_SECRETS + 3; i++) {
        binder.onSecret(secretEvent("c hs traffic", filled(32, 100 + i), filled(32, i)));
    }
    assert.equal(binder.pendingCount, MAX_PENDING_SECRETS);
    assert.equal(binder.summary().unbound, MAX_PENDING_SECRETS + 3);
});

test("a secret without a usable messageHash is never guessed", () => {
    const { binder, lines } = newBinder();
    binder.onTranscriptAppend("0xc1", clientHello(RANDOM_A));
    binder.onSecret(secretEvent("c hs traffic", null, SECRET_1));
    binder.onSecret(secretEvent("c hs traffic", filled(20, 1), SECRET_1)); // not 32/48 bytes
    assert.deepEqual(lines, []);
});

// ---- dedupe and F1 -----------------------------------------------------------------

test("the same F2 secret twice yields one line", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(12);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    const ev = secretEvent("s hs traffic", digest("sha256", ch, sh), SECRET_1);
    binder.onSecret(ev);
    assert.deepEqual(binder.onSecret(ev), []);
    assert.equal(lines.length, 1);
});

test("F1 probe lines map the label enum and dedupe against identical F2 lines", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(13);
    assert.deepEqual(binder.onProbeSecret(3, RANDOM_A, SECRET_1),
        [`CLIENT_HANDSHAKE_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(SECRET_1)}`]);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    assert.deepEqual(binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1)), []);
    assert.equal(lines.length, 1);
    assert.equal(binder.summary().f1, 1);
});

test("F1: only the first secret per (random, label) — KeyUpdate re-uses *_TRAFFIC_SECRET_0", () => {
    const { binder } = newBinder();
    assert.equal(binder.onProbeSecret(5, RANDOM_A, SECRET_1).length, 1);
    assert.deepEqual(binder.onProbeSecret(5, RANDOM_A, SECRET_2), []);
    assert.equal(binder.onProbeSecret(5, RANDOM_B, SECRET_2).length, 1);
});

test("F1: unknown label enums (0 res master, UINT64_MAX skip) and bad randoms are dropped", () => {
    const { binder } = newBinder();
    assert.deepEqual(binder.onProbeSecret(0, RANDOM_A, SECRET_1), []);
    assert.deepEqual(binder.onProbeSecret(0xffffffff, RANDOM_A, SECRET_1), []);
    assert.deepEqual(binder.onProbeSecret(4, filled(16, 1), SECRET_1), []);
    assert.deepEqual(Object.keys(FIZZ_PROBE_LABELS).map(Number), [2, 3, 4, 5, 6, 7, 8]);
});

// ---- caps and hashing cost ---------------------------------------------------------------

test("contexts beyond MAX_CONTEXTS evict the oldest", () => {
    const { binder, lines } = newBinder();
    const first = clientHello(filled(32, 1));
    binder.onTranscriptAppend("0xctx0", first);
    for (let i = 1; i <= MAX_CONTEXTS; i++) binder.onTranscriptAppend(`0xctx${i}`, clientHello(filled(32, i + 1)));
    binder.onSecret(secretEvent("c e traffic", digest("sha256", first), SECRET_1));
    assert.deepEqual(lines, []);
    assert.equal(binder.summary().contexts, MAX_CONTEXTS + 1);
    assert.equal(binder.summary().handshakes, 0);
});

test("prefix hashes are memoized per context", () => {
    const { binder, hashCalls } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(14);
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1));
    const after = hashCalls();
    binder.onSecret(secretEvent("s hs traffic", digest("sha256", ch, sh), SECRET_2));
    assert.equal(hashCalls(), after);
});

test("only prefixes ending at a complete message are hashed (the first half of a split CH is not)", () => {
    const { binder, hashCalls } = newBinder();
    const ch = clientHello(RANDOM_A, 300), sh = serverHello(15);
    binder.onTranscriptAppend("0xc1", ch.subarray(0, 100));
    binder.onTranscriptAppend("0xc1", ch.subarray(100));
    binder.onTranscriptAppend("0xc1", sh);
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1));
    assert.equal(hashCalls(), 2); // CH (both parts) and CH||SH
});

test("the pending queue is retried only after new transcript bytes arrived", () => {
    const { binder, hashCalls } = newBinder();
    binder.onTranscriptAppend("0xc1", clientHello(RANDOM_A));
    binder.onSecret(secretEvent("c hs traffic", filled(32, 120), SECRET_1)); // pending: CH hashed once
    const before = hashCalls();
    binder.onSecret(secretEvent("derived", null, SECRET_2));
    binder.onSecret(secretEvent("derived", null, SECRET_2));
    assert.equal(hashCalls(), before);
    assert.equal(binder.pendingCount, 1);
});

test("after the final secret the context stores no more chunks and asks only for headers", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(16);
    for (const m of [ch, sh, encryptedExtensions, certificate, certificateVerify, finished]) binder.onTranscriptAppend("0xc1", m);
    const hAp = digest("sha256", ch, sh, encryptedExtensions, certificate, certificateVerify, finished);
    assert.equal(binder.wantsBody("0xc1"), true);
    binder.onSecret(secretEvent("s ap traffic", hAp, SECRET_1));
    assert.equal(binder.wantsBody("0xc1"), false);
    // The later secrets of the same prefix still bind from the index.
    binder.onSecret(secretEvent("c ap traffic", hAp, SECRET_2, "0xd9"));
    binder.onSecret(secretEvent("exp master", hAp, filled(32, 6), "0xd8"));
    assert.equal(lines.length, 3);
    assert.ok(lines.every((l) => l.includes(hexOf(RANDOM_A))));
    // A header-only append of a non-starting message is accepted as is.
    assert.equal(binder.onTranscriptAppend("0xc1", finished.subarray(0, HANDSHAKE_HEADER_LEN), finished.length), true);
});

test("a header-only ClientHello is refused (the caller re-reads it whole) and a stored message needs its body", () => {
    const { binder } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(17);
    assert.equal(binder.onTranscriptAppend("0xc1", ch.subarray(0, HANDSHAKE_HEADER_LEN), ch.length), false);
    assert.equal(binder.summary().contexts, 0);
    binder.onTranscriptAppend("0xc1", ch);
    assert.equal(binder.onTranscriptAppend("0xc1", sh.subarray(0, HANDSHAKE_HEADER_LEN), sh.length), false);
    assert.equal(binder.onTranscriptAppend("0xc1", sh), true);
});

test("a context over its chunk cap only tracks message bounds from header reads", () => {
    const { binder } = newBinder();
    binder.onTranscriptAppend("0xc1", clientHello(RANDOM_A));
    for (let i = 1; i < MAX_CHUNKS_PER_CONTEXT; i++) binder.onTranscriptAppend("0xc1", serverHello(i));
    assert.equal(binder.wantsBody("0xc1"), true);
    binder.onTranscriptAppend("0xc1", serverHello(99)); // over the cap: marks the context full
    assert.equal(binder.wantsBody("0xc1"), false);
});

// ---- oversized messages (> MAX_APPEND_BYTES) ---------------------------------------

/** Fake memory: IOBuf structs (length @0, data @8, next @0x20) and data buffers, by bigint address. */
function fakeIOBufMemory() {
    const u64 = new Map<bigint, number>(), ptrs = new Map<bigint, bigint>(), buffers = new Map<bigint, Uint8Array>();
    const P = (v: bigint): any => ({
        v, isNull: () => v === 0n, and: function () { return this; },
        add: (n: any) => P(v + BigInt(typeof n === "object" ? n.v : n)),
        compare: (o: any) => (v === o.v ? 0 : v < o.v ? -1 : 1), equals: (o: any) => v === o.v,
        readU64: () => ({ toNumber: () => u64.get(v) ?? 0 }),
        readPointer: () => P(ptrs.get(v) ?? 0n),
        readByteArray: (n: number) => { const b = buffers.get(v)!; return b.slice(0, n).buffer; },
        toString: () => "0x" + v.toString(16),
    });
    /** A circular chain of segments; returns its head. */
    const chain = (segments: Uint8Array[], at: bigint): any => {
        segments.forEach((seg, i) => {
            const node = at + BigInt(i) * 0x100n, data = 0x100000n + at + BigInt(i) * 0x100000n;
            u64.set(node, seg.length);
            ptrs.set(node + 8n, data);
            ptrs.set(node + 0x20n, i + 1 < segments.length ? node + 0x100n : at);
            buffers.set(data, seg);
        });
        return P(at);
    };
    return { P, chain };
}

function withWideRanges(fn: () => void): void {
    const G = globalThis as any;
    const saved = G.Process.findRangeByAddress;
    const mem = fakeIOBufMemory();
    G.Process.findRangeByAddress = () => ({ base: mem.P(0n), size: 2 ** 40, protection: "r--" });
    resetReadableCache();
    try { fn(); } finally { G.Process.findRangeByAddress = saved; resetReadableCache(); }
}

test("readIOBufChain: a chain over MAX_APPEND_BYTES still yields its header and its total (cap on kept bytes only)", () => {
    withWideRanges(() => {
        const { chain } = fakeIOBufMemory();
        const big = handshake(11, filled(70_000 - 4, 11));        // > 64 KB Certificate in two segments
        const head = chain([big.subarray(0, 40_000), big.subarray(40_000)], 0x10000000n);
        const header = readIOBufChain(head, HANDSHAKE_HEADER_LEN)!;
        assert.equal(header.total, 70_000);
        assert.deepEqual([...header.bytes], [...big.subarray(0, HANDSHAKE_HEADER_LEN)]);
        const capped = readIOBufChain(head)!;
        assert.equal(capped.total, 70_000);
        assert.equal(capped.bytes.length, MAX_APPEND_BYTES);
    });
});

test("a > 64 KB Certificate on a storing context marks it full instead of being skipped (no corrupted later prefix)", () => {
    const { binder, lines } = newBinder();
    const ch = clientHello(RANDOM_A), sh = serverHello(21);
    const bigCert = handshake(11, filled(70_000, 11));
    binder.onTranscriptAppend("0xc1", ch);
    binder.onTranscriptAppend("0xc1", sh);
    binder.onTranscriptAppend("0xc1", encryptedExtensions);
    assert.equal(binder.wantsBody("0xc1"), true);
    // The caller reads at most MAX_APPEND_BYTES: a prefix plus the total length.
    assert.equal(binder.onTranscriptAppend("0xc1", bigCert.subarray(0, MAX_APPEND_BYTES), bigCert.length), true);
    assert.equal(binder.wantsBody("0xc1"), false);                 // header-only from now on
    binder.onTranscriptAppend("0xc1", certificateVerify.subarray(0, HANDSHAKE_HEADER_LEN), certificateVerify.length);
    binder.onTranscriptAppend("0xc1", finished.subarray(0, HANDSHAKE_HEADER_LEN), finished.length);
    // Prefixes recorded before the big message still bind ...
    binder.onSecret(secretEvent("c hs traffic", digest("sha256", ch, sh), SECRET_1));
    assert.equal(lines.length, 1);
    // ... and a transcript that silently skipped the certificate is never matchable.
    binder.onSecret(secretEvent("s ap traffic", digest("sha256", ch, sh, encryptedExtensions, certificateVerify, finished), SECRET_2, "0xd5"));
    assert.equal(lines.length, 1);
});

test("summary: handshakes counts distinct client randoms with lines, contexts counts transcripts", () => {
    const { binder } = newBinder();
    const chA = clientHello(RANDOM_A), chB = clientHello(RANDOM_B);
    binder.onTranscriptAppend("0xa", chA);
    binder.onTranscriptAppend("0xa2", chA);
    binder.onTranscriptAppend("0xb", chB);
    binder.onSecret(secretEvent("c e traffic", digest("sha256", chA), SECRET_1));
    binder.onSecret(secretEvent("e exp master", digest("sha256", chA), SECRET_2));
    binder.onSecret(secretEvent("c e traffic", digest("sha256", chB), SECRET_1, "0xd2"));
    assert.equal(binder.summary().contexts, 3);
    assert.equal(binder.summary().handshakes, 2);
    assert.equal(binder.summary().lines, 3);
});

test("two handshakes with the same transcript prefix are ambiguous until one is replaced", () => {
    const { binder, lines } = newBinder();
    // Two HRR contexts whose transcripts start with the same message_hash, then differ by random.
    const messageHash = handshake(TLS_MESSAGE_HASH, filled(32, 1));
    binder.onTranscriptAppend("0xh1", messageHash);
    binder.onTranscriptAppend("0xh2", messageHash);
    binder.onTranscriptAppend("0xh1", clientHello(RANDOM_A));
    binder.onTranscriptAppend("0xh2", clientHello(RANDOM_B));
    binder.onSecret(secretEvent("c e traffic", digest("sha256", messageHash), SECRET_1));
    assert.deepEqual(lines, []);
    assert.equal(binder.pendingCount, 1);
    // A new handshake on 0xh2 drops its prefixes: the pending secret now binds to 0xh1's random.
    binder.onTranscriptAppend("0xh2", clientHello(filled(32, 0x33)));
    binder.onSecret(secretEvent("derived", null, SECRET_2));
    assert.deepEqual(lines, [`CLIENT_EARLY_TRAFFIC_SECRET ${hexOf(RANDOM_A)} ${hexOf(SECRET_1)}`]);
});

// ---- label self-check ----------------------------------------------------------------

test("known Fizz labels include the logged and the skipped ones; unknown/null are not", () => {
    for (const l of [...Object.keys(FIZZ_NSS_LABELS), "derived", "res binder", "ext binder", "res master"]) {
        assert.equal(isKnownFizzLabel(l), true, l);
    }
    for (const l of [null, "", "tls13 c hs traffic", "c hs traffic ", "CLIENT_RANDOM"]) assert.equal(isKnownFizzLabel(l), false, String(l));
});

test("label self-check: unknown labels skip, the limit-th in a row detaches, a known label resets", () => {
    const check = newFizzLabelSelfCheck();
    for (let i = 1; i < FIZZ_LABEL_MISMATCH_LIMIT; i++) assert.equal(check.observe("garbage"), "skip");
    assert.equal(check.observe("c hs traffic"), "emit");
    for (let i = 1; i < FIZZ_LABEL_MISMATCH_LIMIT; i++) assert.equal(check.observe(null), "skip");
    assert.equal(check.observe(null), "detach");
});
