// Unit tests for the Windows managed-RC4 memory-scan recovery
// (agent/rc4/libs/rc4_memscan.ts), covering the reworked fast path:
//   F1 safe reads (guard/no-access pages skipped), F2 printable-prefix early-stop on BARE
//   ciphertext, F3 largest-first ordering that reaches the .NET heap, F4 per-length L4 memo.
//
// Run: node --import tsx --test agent/rc4/libs/rc4_memscan.test.ts
//   (registered in package.json's "test:agent" list so it runs in the suite.)
//
// recover()/analyze()/handleCiphertext() are pure apart from the Frida runtime:
// selectRanges() reads Process.enumerate{Modules,Ranges}(), readRangeGuarded() calls
// Process.findRangeByAddress() then NativePointer.readByteArray(), and emitRc4Key() calls
// send(). A Buffer-backed fake pointer + stub Process/send are all the runtime this needs.
// Process is referenced at MODULE LOAD (const P = Process), so the stubs are installed
// before a dynamic import of the module under test.

import { test, before } from "node:test";
import assert from "node:assert/strict";

// --- Frida runtime stubs (installed before the dynamic import below) -----------------

// Per-test synthetic memory: the ranges selectRanges() returns, a log of which range indices
// were actually READ (readByteArray), and the key-material messages emitRc4Key() sent. A fake
// pointer implements the NativePointer surface rc4_memscan.ts touches.
let currentRanges: any[] = [];
let reads: number[] = [];
let sentKeys: any[] = [];

const RANGE_STRIDE = 0x100000;   // one synthetic range every 1MB of address space

function fakePtr(buf: Uint8Array, off: number, idx: number): any {
    return {
        add: (n: number) => fakePtr(buf, off + n, idx),
        toString: () => "0x" + (idx * RANGE_STRIDE + off).toString(16),
        compare: (_o: any) => 0,
        readByteArray: (len: number) => {
            if (off + len > buf.length) return null;
            if (off === 0) reads.push(idx);   // count one read per range (each guarded burst)
            return buf.slice(off, off + len).buffer;
        },
    };
}

function setMemory(specs: { buf: Uint8Array; file: string | null; protection?: string }[]): void {
    reads = [];
    currentRanges = specs.map((sp, idx) => ({
        base: fakePtr(sp.buf, 0, idx), size: sp.buf.length, file: sp.file, protection: sp.protection || "rw-",
    }));
}

(globalThis as any).Process = {
    pointerSize: 8,
    enumerateModules: () => [],
    enumerateRanges: (_spec: any) => currentRanges,
    getCurrentThreadId: () => 0,
    setExceptionHandler: () => { },
    // F1 safe-read guard: decode the range index from the queried address and report that
    // range's live mapping + protection. A protection whose first char is not 'r' (a guard /
    // no-access page) makes readableScanLength() skip the range before any read.
    findRangeByAddress: (p: any) => {
        const addr = parseInt(p.toString(), 16);
        const idx = Math.floor(addr / RANGE_STRIDE);
        if (idx < 0 || idx >= currentRanges.length) return null;
        const r = currentRanges[idx];
        return { base: { toString: () => "0x" + (idx * RANGE_STRIDE).toString(16) }, size: r.size, protection: r.protection };
    },
};
// Capture emitted RC4 key material (emitRc4Key -> sendKeyMaterial -> send); ignore log noise.
(globalThis as any).send = (msg: any) => {
    if (msg && (msg.classifier === "rc4" || msg.contentType === "private_key_material")) sentKeys.push(msg);
};

// Dynamic import AFTER the stubs exist (a static import would evaluate the module — and its
// `const P = Process` — before the stubs are set). Done in a before() hook because the tsx/CJS
// transform used by the test runner disallows top-level await.
let recover: (ct: Uint8Array) => Promise<any>;
let analyze: (ct: Uint8Array | null) => Promise<any>;
let handleCiphertext: (ct: Uint8Array, dir: string) => Promise<void>;
let configureRc4Memscan: (opts: any) => void;
let resetRc4RecoveryStateForTest: () => void;
let rc4FrameBody: (ct: Uint8Array) => Uint8Array;
before(async () => {
    const mod: any = await import("./rc4_memscan.js");
    recover = mod.recover;
    analyze = mod.analyze;
    handleCiphertext = mod.handleCiphertext;
    configureRc4Memscan = mod.configureRc4Memscan;
    resetRc4RecoveryStateForTest = mod.resetRc4RecoveryStateForTest;
    rc4FrameBody = mod.rc4FrameBody;
});

// --- RC4 reference helpers (independent of the module under test) --------------------

function ksa(keyBytes: number[]): number[] {
    const s = Array.from({ length: 256 }, (_, i) => i);
    let j = 0;
    for (let i = 0; i < 256; i++) { j = (j + s[i] + keyBytes[i % keyBytes.length]) & 0xff; const t = s[i]; s[i] = s[j]; s[j] = t; }
    return s;
}
function rc4(keyBytes: number[], data: number[]): number[] {
    const s = ksa(keyBytes);
    let i = 0, j = 0; const out: number[] = [];
    for (let n = 0; n < data.length; n++) {
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff; const t = s[i]; s[i] = s[j]; s[j] = t;
        out.push(data[n] ^ s[(s[i] + s[j]) & 0xff]);
    }
    return out;
}
function ascii(str: string): number[] { return Array.from(str, c => c.charCodeAt(0)); }
function be32(n: number): number[] { return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]; }
function hexOf(bytes: number[]): string { return bytes.map(b => (b < 16 ? "0" : "") + b.toString(16)).join(""); }

const KEY = "fritap-rc4-demo-key";                 // printable ASCII key (19 bytes)
const KEY_BYTES = ascii(KEY);

// A captured SSPI frame: [BE uint32 payload-length][printable payload], RC4-encrypted.
function lenPrefixedCt(keyBytes: number[], payload: string): number[] {
    const pt = be32(payload.length).concat(ascii(payload));
    return rc4(keyBytes, pt);
}
// The server's ACTUAL inbound framing (demo/tls13_server.py: sendall(len(rc).to_bytes(4,
// "big") + rc)): [BE uint32 cipher-length][RC4 ciphertext] coalesced into one TLS record.
// The 4-byte length is PLAINTEXT, prepended OUTSIDE the RC4 stream — distinct from
// lenPrefixedCt above, whose length is encrypted INSIDE the RC4 stream.
function demoInboundFrame(keyBytes: number[], payload: string): number[] {
    const cipher = rc4(keyBytes, ascii(payload));
    return be32(cipher.length).concat(cipher);
}
// A range holding the printable key as its own run (isolated by NUL separators).
function keyRange(keyBytes: number[]): Uint8Array {
    return new Uint8Array([...ascii("noise before "), 0, ...keyBytes, 0, ...ascii(" noise after here")]);
}
// The same key core preceded by `pad` NUL bytes, making the range LARGE (so largest-first
// reads it early) while keeping its candidate count tiny (NUL padding has no printable runs).
function paddedKeyRange(keyBytes: number[], pad: number): Uint8Array {
    const core = keyRange(keyBytes);
    const out = new Uint8Array(pad + core.length);
    out.set(core, pad);
    return out;
}
// A range full of DISTINCT short printable runs — each a candidate key the fuzzy sweep must
// KSA-trial. Distinct so the FNV dedup can't collapse them.
function noisyTail(seed: number, runs: number): Uint8Array {
    const out: number[] = [];
    for (let k = 0; k < runs; k++) {
        const tag = "run" + (seed + k) + "xyz";        // distinct, all printable, len >= minKeyLen
        for (let c = 0; c < tag.length; c++) out.push(tag.charCodeAt(c));
        out.push(0);                                     // NUL separates runs
    }
    return new Uint8Array(out);
}

// The code-default option baseline (all improved-recovery knobs off), applied at the start of
// every test so option merges from a prior test never leak in.
const BASELINE = {
    minKeyLen: 5, maxKeyLen: 64, trialPrefix: 64, acceptPrintableFraction: 0.85,
    maxRangeBytes: 64 * 1024 * 1024, maxTotalBytes: 300 * 1024 * 1024,
    maxTrials: 1000000, maxWindowTrials: 300000, maxWindowsPerRun: 20000,
    maxWindowRunLen: 256, maxSboxes: 64, maxSeen: 1000000,
    yieldEveryBuffers: 8, detectSboxes: false, recoverKeys: true,
    sboxFirst: false, sboxExactValidate: false, prioritizeAnonymous: false,
    requireExactOrAccept: false, knownPlaintext: null,
    groupedRead: false, readGroupBytes: 64 * 1024 * 1024, structuralAccept: false,
    largestFirst: false, asciiOnly: false,
};
function resetOpts(extra?: any): void { configureRc4Memscan({ ...BASELINE, ...(extra || {}) }); }

// --- (a) BARE-ciphertext printable frame recovers AND early-stops --------------------

// The demo's recovering SSPI frame carries NO length prefix, so the structural accept can
// never fire — F2's printable-prefix accept is what stops the scan. Largest-first reads the
// key range first (few trials); the control reads it last (whole heap trialled first).
test("(a) bare-ciphertext printable frame recovers via printable-prefix with far fewer trials/reads", async () => {
    const ct = new Uint8Array(rc4(KEY_BYTES, ascii("hello over the rc4 tls demo channel here"))); // 40B, NO prefix
    const specs = [
        { buf: paddedKeyRange(KEY_BYTES, 8000), file: null },   // LARGEST -> read first (fast)
        { buf: noisyTail(1000, 200), file: null },
        { buf: noisyTail(9000, 200), file: null },
    ];

    // FAST look: largest-first, one range per group, ASCII only. printable-prefix early-stops.
    resetOpts({ largestFirst: true, groupedRead: true, readGroupBytes: 1, asciiOnly: true });
    setMemory(specs);
    const fast = await analyze(ct);
    assert.equal(fast.stop, true, "early-stopped");
    assert.ok(fast.exact && fast.exact.source === "printable-prefix", "accepted via printable-prefix (no length prefix)");
    assert.deepEqual(reads, [0], "only the key range (largest) was read; tail ranges skipped");
    const fastTrials = fast.trials;

    // CONTROL: smallest-first, so the key range (largest) is read LAST and the fuzzy sweep
    // KSA-trials the whole heap of tail candidates before it reaches (and stops on) the key.
    resetOpts({ largestFirst: false, groupedRead: true, readGroupBytes: 1, asciiOnly: true });
    setMemory(specs);
    const full = await analyze(ct);
    assert.deepEqual(reads.slice().sort(), [0, 1, 2], "control reads all ranges");
    assert.ok(full.trials > fastTrials * 10,
        "control KSA-trials far more (" + full.trials + ") than the fast path (" + fastTrials + ")");
    console.log("[rc4-memscan test] (a) trials fast=" + fastTrials + " full=" + full.trials +
        " (reduction " + (100 - Math.round(100 * fastTrials / full.trials)) + "%); reads fast=1 full=3");
});

// --- (b) key in a LARGE region ordered AFTER small regions is still reached ----------

test("(b) largest-first reaches a LARGE key region ordered after several small regions", async () => {
    const specs = [
        { buf: noisyTail(1, 3), file: null },       // small decoy regions, no key, listed FIRST
        { buf: noisyTail(100, 3), file: null },
        { buf: noisyTail(200, 3), file: null },
        { buf: paddedKeyRange(KEY_BYTES, 6000), file: null },   // LARGE, holds the key, listed LAST
    ];
    const ct = new Uint8Array(lenPrefixedCt(KEY_BYTES, "hello over the rc4 tls demo channel here"));
    resetOpts({ largestFirst: true, structuralAccept: true, groupedRead: true, readGroupBytes: 1, asciiOnly: true });
    setMemory(specs);
    const ctx = await analyze(ct);
    assert.equal(ctx.stop, true, "recovered");
    assert.ok(ctx.exact !== null, "accepted exactly");
    assert.equal(reads[0], 3, "the LARGE key region (index 3, last in memory) was read FIRST");
    assert.deepEqual(reads, [3], "and the small decoy regions were skipped by early-stop");
    console.log("[rc4-memscan test] (b) large region idx3 read first; small regions skipped");
});

// --- (c) a guard / no-access range is SKIPPED (never read, its key never trialed) ----

test("(c) a range whose protection is not 'r' is skipped (never read/trialed)", async () => {
    resetOpts({ largestFirst: true, groupedRead: true, readGroupBytes: 1, asciiOnly: true });
    setMemory([
        { buf: paddedKeyRange(KEY_BYTES, 4000), file: null, protection: "---" }, // ONLY copy of the key, guarded
        { buf: noisyTail(500, 50), file: null },                                  // readable, no key
    ]);
    const ct = new Uint8Array(rc4(KEY_BYTES, ascii("hello over the rc4 tls demo channel here")));
    const r = await recover(ct);
    assert.equal(r.ok, false, "not recovered: the guarded range holding the key was never read/trialed");
    assert.equal(reads.indexOf(0), -1, "the guarded range (index 0) was never read");
    assert.ok(reads.indexOf(1) >= 0, "the readable range WAS read (the scan ran; only the guard page was skipped)");
});

// --- (d) F4: a first non-RC4 frame does not block a later, DIFFERENT-length RC4 frame -

test("(d) F4: a first non-RC4 frame does not block a later real RC4 frame of a shorter length", async () => {
    resetOpts();
    resetRc4RecoveryStateForTest();
    sentKeys = [];
    setMemory([{ buf: keyRange(KEY_BYTES), file: null }]);

    // Frame 1: 40 bytes of non-RC4 ciphertext — no key in memory decrypts it to plaintext.
    const junk: number[] = [];
    for (let i = 0; i < 40; i++) junk.push((i * 37 + 13) & 0xff);
    await handleCiphertext(new Uint8Array(junk), "out");
    assert.equal(sentKeys.length, 0, "frame 1 (non-RC4) recovered nothing and emitted no key");

    // Frame 2: a REAL RC4 frame that is SHORTER (27B) than frame 1 — the old '<= longest
    // scanned' gate would have permanently blocked it. It must still recover and emit.
    const ct2 = new Uint8Array(rc4(KEY_BYTES, ascii("shorter real rc4 frame here")));  // 27 bytes
    assert.ok(ct2.length < 40 && ct2.length >= 16, "frame 2 is shorter than frame 1 and >= MIN_CT_LEN");
    await handleCiphertext(ct2, "out");
    assert.equal(sentKeys.length, 1, "frame 2 (real, shorter) still recovered and emitted the key");
    assert.equal(sentKeys[0].key, hexOf(KEY_BYTES), "emitted the exact key hex");
});

// --- (e) fuzzy fallback still recovers a short printable frame (below the F2 threshold) -

test("(e) fuzzy fallback recovers a short printable frame (below HIGH_PRINTABLE_MIN_LEN)", async () => {
    resetOpts();
    setMemory([{ buf: keyRange(KEY_BYTES), file: null }]);
    const ct = new Uint8Array(rc4(KEY_BYTES, ascii("hi short rc4 one!!")));  // 18 chars < 24
    const r = await recover(ct);
    assert.ok(r.ok, "recovered via the fuzzy fallback");
    assert.deepEqual(Array.from(r.key), KEY_BYTES, "recovered the exact key bytes");
    assert.doesNotMatch(r.source, /printable-prefix|length-prefix|exact/, "did NOT use a high-confidence early-accept");
    assert.match(r.source, /trial-key\(/, "recovered via the fuzzy trial-key path");
});

// --- (f) a binary (non-ASCII) key recovers via the S-box full-pass fallback ----------

test("(f) a binary key recovers via S-box detection in the full pass", async () => {
    // Full-pass (armed) config: S-box detection on. The key bytes are non-printable, so the
    // fast pass (no S-box detection, no printable key run) cannot find them; only the full
    // pass's S-box keystream recovery succeeds.
    resetOpts({ detectSboxes: true, sboxExactValidate: true, prioritizeAnonymous: true, groupedRead: true });
    const binaryKey = [0x00, 0x01, 0x80, 0xfe, 0x7f, 0x03, 0x90, 0xaa, 0x11, 0xc4];
    const sbox = ksa(binaryKey);                        // 256-byte post-KSA permutation, resident
    const buf = new Uint8Array([...sbox, 0, ...ascii("just filler text, no key here at all")]);
    setMemory([{ buf, file: null }]);
    const ct = new Uint8Array(rc4(binaryKey, ascii("this is the secret rc4 payload flowing over sspi record layer")));
    const r = await recover(ct);
    assert.ok(r.ok, "recovered via the S-box full-pass fallback");
    assert.equal(r.key, null, "no key bytes (S-box keystream recovery)");
    assert.ok(r.sbox !== null, "recovered the post-KSA S-box keystream");
    assert.match(r.source, /sbox-keystream/, "recovered via the S-box keystream path");
});

// --- no-regression: the length-prefixed structural early-accept still fires ----------

test("no-regression: a length-prefixed frame still recovers via the structural early-accept", async () => {
    resetOpts();
    setMemory([{ buf: keyRange(KEY_BYTES), file: null }]);
    const ct = new Uint8Array(lenPrefixedCt(KEY_BYTES, "hello over the rc4 tls demo channel here"));
    const r = await recover(ct);
    assert.ok(r.ok, "recovered");
    assert.deepEqual(Array.from(r.key), KEY_BYTES, "recovered the exact key bytes");
    assert.match(r.source, /length-prefix/, "accepted via the structural length-prefix path");
});


// --- (g) rc4FrameBody: strip a PLAINTEXT 4-byte BE length prefix only on an exact match ----

test("(g) rc4FrameBody strips a plaintext 4-byte BE length prefix only on an exact length match", () => {
    // Demo inbound frame [BE cipherlen][cipher] -> body is the ciphertext at offset 4.
    const frame = new Uint8Array(demoInboundFrame(KEY_BYTES, "hello over the rc4 tls demo channel here"));
    const body = rc4FrameBody(frame);
    assert.equal(body.length, frame.length - 4, "stripped the 4-byte length prefix");
    assert.deepEqual(Array.from(body), Array.from(frame.subarray(4)), "body is the ciphertext at offset 4");

    // Bare ciphertext (no prefix, the outbound path): returned unchanged.
    const bare = new Uint8Array(rc4(KEY_BYTES, ascii("hello over the rc4 tls demo channel here")));
    assert.deepEqual(Array.from(rc4FrameBody(bare)), Array.from(bare), "bare ciphertext returned unchanged");

    // Length-INSIDE frame (structuralAccept convention): the RC4-encrypted prefix ~never equals
    // len-4, so it is NOT stripped (the structural path decrypts it whole). Guards against the
    // realignment cannibalising the existing structural-accept path.
    const inside = new Uint8Array(lenPrefixedCt(KEY_BYTES, "hello over the rc4 tls demo channel here"));
    assert.deepEqual(Array.from(rc4FrameBody(inside)), Array.from(inside), "length-inside frame returned unchanged");

    // A <= 4-byte frame has nothing to strip.
    assert.deepEqual(Array.from(rc4FrameBody(new Uint8Array([1, 2, 3, 4]))), [1, 2, 3, 4], "4-byte frame unchanged");
});

// --- (h) the demo's coalesced inbound [len][cipher] frame recovers the key ------------------
// Regression for the 4-byte misalignment that made the real inbound frame miss AND grind the
// whole heap (no early-stop). handleCiphertext() must realign via rc4FrameBody, then recover.

test("(h) the demo's coalesced inbound [len][cipher] frame recovers and emits the key", async () => {
    resetOpts({ largestFirst: true, groupedRead: true, asciiOnly: true });
    resetRc4RecoveryStateForTest();
    sentKeys = [];
    setMemory([{ buf: keyRange(KEY_BYTES), file: null }]);
    // Like the bug report's 52-byte inbound frame: [BE len=48][48B RC4 ciphertext].
    const frame = new Uint8Array(demoInboundFrame(KEY_BYTES, "received \"hi there\" (8 bytes) over rc4-in-tls!!!"));
    assert.equal(frame.length, 52, "the fixture reproduces the bug report's 52-byte inbound frame");
    await handleCiphertext(frame, "in");
    assert.equal(sentKeys.length, 1, "recovered and emitted the key from the coalesced inbound frame");
    assert.equal(sentKeys[0].key, hexOf(KEY_BYTES), "emitted the exact key hex");
});
