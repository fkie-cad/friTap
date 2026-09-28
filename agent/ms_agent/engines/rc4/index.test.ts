// Unit tests for the RC4 heap-scan engine's improved recovery path
// (agent/ms_agent/engines/rc4/index.ts).
//
// Run: npm run test:agent
//   (node --import tsx --test agent/ms_agent/engines/rc4/index.test.ts)
//
// runTiers is pure apart from readBytes() (a NativePointer.readByteArray wrapper)
// and the global send(): a Buffer-backed fake pointer and a send() stub are all
// the Frida runtime this needs, matching endpoint.test.ts / sockaddr.test.ts.

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { state } from "../../state.js";
import { Rc4Engine } from "./index.js";

const KEY = "fritap-rc4-demo-key";

// Standard RC4 KSA -> the 256-byte post-KSA S-box (byte form).
function ksa(keyBytes: number[]): number[] {
    const s = Array.from({ length: 256 }, (_, i) => i);
    let j = 0;
    for (let i = 0; i < 256; i++) {
        j = (j + s[i] + keyBytes[i % keyBytes.length]) & 0xff;
        const t = s[i]; s[i] = s[j]; s[j] = t;
    }
    return s;
}
function ascii(str: string): number[] { return Array.from(str, c => c.charCodeAt(0)); }
function hexOf(bytes: number[]): string {
    return bytes.map(b => (b < 16 ? "0" : "") + b.toString(16)).join("");
}
// Full RC4 (KSA+PRGA from i=j=0) — to build a realistic ciphertext sample.
function rc4(keyBytes: number[], data: number[]): number[] {
    const s = ksa(keyBytes);
    let i = 0, j = 0; const out: number[] = [];
    for (let n = 0; n < data.length; n++) {
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff;
        const t = s[i]; s[i] = s[j]; s[j] = t;
        out.push(data[n] ^ s[(s[i] + s[j]) & 0xff]);
    }
    return out;
}

// Buffer-backed fake NativePointer: readByteArray returns an ArrayBuffer (what
// core/memory.ts readBytes wraps), null on a short read.
function fakePtr(buf: Uint8Array, off = 0): any {
    return {
        add: (n: number) => fakePtr(buf, off + n),
        toString: () => "0x" + off.toString(16),
        readByteArray: (len: number) =>
            off + len > buf.length ? null : buf.slice(off, off + len).buffer,
    };
}

const RC4_PARAMS = {
    min_key_len: 5, max_key_len: 64, trial_prefix: 64, accept_printable_fraction: 0.85,
    max_range_bytes: 64 * 1024 * 1024, max_total_bytes: 300 * 1024 * 1024,
    max_trials: 1000000, max_window_trials: 300000, max_windows_per_run: 20000,
    max_window_run_len: 256, max_sboxes: 64, max_seen: 1000000,
    detect_sboxes: true, recover_keys: true,
    sbox_first: true, sbox_exact_validate: true, prioritize_anonymous: true,
    require_exact_or_accept: true,
};
const RC4_KAT = { key: "4b6579", plaintext: "506c61696e74657874", ciphertext: "bbf316e8d940af0ad3" };

function runScan(buf: Uint8Array, params: any) {
    const emitted: any[] = [];
    (globalThis as any).send = (msg: any) => emitted.push(msg);
    state.rc4KatOk = null;
    state.rc4Sboxes = [];
    state.rc4Emitted = {};
    state.profile = { params, kat: RC4_KAT };
    const stats: any = {};
    const errors: string[] = [];
    const ranges = [{ base: fakePtr(buf), size: buf.length, file: null }];
    Rc4Engine.runTiers(ranges, stats, errors);
    return { emitted, stats, errors };
}

// NOTE: a CLEAN post-KSA S-box is only resident if the app retains the key schedule
// separately from the running stream (PRGA mutates the box in place, so most RC4
// leaves only the ADVANCED running permutation). This exercises the opt-in two-pass
// sbox_first path for that clean-box case; the robust path for running RC4 is the
// known-plaintext test below.
test("clean post-KSA S-box (opt-in sbox_first) exact-validates the key, no ciphertext", () => {
    const keyBytes = ascii(KEY);
    const sbox = ksa(keyBytes);
    // [256-byte S-box][0x00][ASCII key][0x00][printable noise]
    const buf = new Uint8Array([...sbox, 0, ...keyBytes, 0, ...ascii("some other printable data here")]);
    const { emitted, stats, errors } = runScan(buf, RC4_PARAMS);
    assert.equal(errors.length, 0, "no scan errors: " + errors.join("; "));
    const sboxLine = emitted.find(e => e.source === "memscan-sbox");
    assert.ok(sboxLine, "S-box artifact emitted");
    assert.equal(sboxLine.key, hexOf(sbox));
    const exact = emitted.find(e => e.source === "memscan-trial-exact");
    assert.ok(exact, "exact key emitted");
    assert.equal(exact.key, hexOf(keyBytes));
    assert.equal(exact.key_len, keyBytes.length);
    assert.ok(stats.rc4.recovered && stats.rc4.ksaExecutions > 0);
    assert.ok(typeof stats.rc4.scanMs === "number");
});

test("key-absent: S-box present but key not in memory -> only the S-box is emitted", () => {
    const sbox = ksa(ascii(KEY));
    // S-box present, but the key bytes are NOT anywhere as a printable run.
    const buf = new Uint8Array([...sbox, 0, ...ascii("no key here just filler text")]);
    const { emitted } = runScan(buf, RC4_PARAMS);
    assert.ok(emitted.find(e => e.source === "memscan-sbox"), "S-box still emitted");
    assert.ok(!emitted.find(e => e.source === "memscan-trial-exact"), "no false exact key");
    // require_exact_or_accept + no ciphertext -> no fuzzy trial key either.
    assert.ok(!emitted.find(e => e.source === "memscan-trial"), "no false fuzzy key");
});

test("known-plaintext exact-validates the key against a ciphertext sample (real running RC4)", () => {
    // The reliable path for real RC4: only the KEY is resident (no clean S-box);
    // a captured ciphertext + known plaintext prove the key exactly. Single-pass default.
    const keyBytes = ascii(KEY);
    const pt = ascii("GET /rc4 HTTP/1.1\r\nHost: demo\r\n\r\n");
    const ct = rc4(keyBytes, pt);
    const buf = new Uint8Array([...ascii("noise before"), 0, ...keyBytes, 0, ...ascii("noise after here")]);
    const params = {
        ...RC4_PARAMS, sbox_first: false,
        ciphertext_sample: hexOf(ct), known_plaintext: hexOf(pt),
    };
    const { emitted } = runScan(buf, params);
    const exact = emitted.find(e => e.source === "memscan-trial-exact");
    assert.ok(exact, "exact key recovered via known-plaintext");
    assert.equal(exact.key, hexOf(keyBytes));
});

test("legacy path (sbox_first:false) still emits the S-box (back-compat)", () => {
    const sbox = ksa(ascii(KEY));
    const buf = new Uint8Array([...sbox, 0, ...ascii(KEY), 0]);
    const { emitted } = runScan(buf, { ...RC4_PARAMS, sbox_first: false, sbox_exact_validate: false });
    assert.ok(emitted.find(e => e.source === "memscan-sbox"), "S-box emitted in legacy path");
});

// --- grouped-burst read (Part 2a): early-stop must skip the tail READS, not just CPU ---

// Multi-range harness: each range gets its own pointer that records its index whenever
// it is actually read, so a test can assert which ranges the scan read.
function instrPtr(buf: Uint8Array, off: number, idx: number, reads: number[]): any {
    return {
        add: (n: number) => instrPtr(buf, off + n, idx, reads),
        toString: () => "0x" + (idx * 0x100000 + off).toString(16),   // unique per range
        readByteArray: (len: number) => {
            if (off + len > buf.length) return null;
            reads.push(idx);
            return buf.slice(off, off + len).buffer;
        },
    };
}
function runScanRanges(specs: { buf: Uint8Array; file: string | null }[], params: any) {
    const emitted: any[] = [];
    const reads: number[] = [];
    (globalThis as any).send = (msg: any) => emitted.push(msg);
    state.rc4KatOk = null;
    state.rc4Sboxes = [];
    state.rc4Emitted = {};
    state.profile = { params, kat: RC4_KAT };
    const stats: any = {};
    const errors: string[] = [];
    const ranges = specs.map((sp, idx) => ({ base: instrPtr(sp.buf, 0, idx, reads), size: sp.buf.length, file: sp.file }));
    Rc4Engine.runTiers(ranges, stats, errors);
    return { emitted, stats, errors, reads };
}

// Range 0 (smallest, anonymous) holds the key; the known-plaintext oracle proves it and
// sets early-stop. read_group_bytes:1 forces one range per group, so the two large tail
// ranges must never be read.
function groupedFixture() {
    const keyBytes = ascii(KEY);
    const pt = ascii("GET /rc4 HTTP/1.1\r\nHost: demo\r\n\r\n");
    const ct = rc4(keyBytes, pt);
    const keyRange = new Uint8Array([...ascii("noise"), 0, ...keyBytes, 0, ...ascii("more noise here")]);
    const tail1 = new Uint8Array(4096).fill(0x41);   // larger -> ordered after the key range
    const tail2 = new Uint8Array(4096).fill(0x42);
    const specs = [
        { buf: keyRange, file: null },
        { buf: tail1, file: null },
        { buf: tail2, file: null },
    ];
    return { specs, keyBytes, ct, pt, keySize: keyRange.length };
}

test("grouped_read early-stop skips the tail READS (I/O saved, not just CPU)", () => {
    const { specs, keyBytes, ct, pt, keySize } = groupedFixture();
    const params = {
        ...RC4_PARAMS, sbox_first: false, grouped_read: true, read_group_bytes: 1,
        prioritize_anonymous: true, ciphertext_sample: hexOf(ct), known_plaintext: hexOf(pt),
    };
    const { emitted, stats, reads } = runScanRanges(specs, params);
    const exact = emitted.find(e => e.source === "memscan-trial-exact");
    assert.ok(exact, "exact key recovered from the first group");
    assert.equal(exact.key, hexOf(keyBytes));
    assert.deepEqual(reads, [0], "only the first (key) range was read; tail ranges skipped");
    assert.equal(stats.rc4.readBytes, keySize, "readBytes reflects only the first group");
});

test("grouped_read:false (code default) reads every range (back-compat, no I/O early-stop)", () => {
    const { specs, keyBytes, ct, pt } = groupedFixture();
    const params = {
        ...RC4_PARAMS, sbox_first: false, grouped_read: false,
        prioritize_anonymous: true, ciphertext_sample: hexOf(ct), known_plaintext: hexOf(pt),
    };
    const { emitted, reads } = runScanRanges(specs, params);
    const exact = emitted.find(e => e.source === "memscan-trial-exact");
    assert.ok(exact, "exact key still recovered on the single-burst path");
    assert.equal(exact.key, hexOf(keyBytes));
    assert.deepEqual(reads.slice().sort(), [0, 1, 2], "single-burst reads all ranges up front");
});

// Guard against the two hand-maintained RC4 scanner copies drifting apart.
test("parity: index.ts and rc4_memscan.ts expose the same improved-recovery options", () => {
    const here = fileURLToPath(new URL(".", import.meta.url));
    const canonical = readFileSync(here + "index.ts", "utf8");
    const twin = readFileSync(here + "../../../rc4/libs/rc4_memscan.ts", "utf8");
    const opts = ["sboxFirst", "sboxExactValidate", "prioritizeAnonymous", "requireExactOrAccept", "knownPlaintext", "groupedRead", "readGroupBytes"];
    for (const o of opts) {
        assert.ok(canonical.includes(o), "index.ts missing option " + o);
        assert.ok(twin.includes(o), "rc4_memscan.ts missing option " + o);
    }
});

// The twin's grouped branch and Windows wiring can't be unit-run here (analyze is not
// exported and its import chain needs the full frida runtime); the grouped algorithm is a
// line-by-line mirror of the behaviorally-tested index.ts branch above. These static
// guards catch the real regression risks: the branch being dropped, or the Windows arming
// path silently ceasing to enable the improved suite.
test("twin: rc4_memscan.ts keeps the grouped-burst branch with early-stop", () => {
    const twin = readFileSync(fileURLToPath(new URL(".", import.meta.url)) + "../../../rc4/libs/rc4_memscan.ts", "utf8");
    assert.ok(/state\.opts\.groupedRead\s*&&\s*!state\.opts\.sboxFirst/.test(twin), "grouped branch guard present");
    assert.ok(twin.includes("readGroupBytes") && twin.includes("orderRangesGrouped"), "grouped read helpers present");
    assert.ok(/if \(ctx\.stop\) break;/.test(twin), "early-stop between/within groups present");
});

test("twin: ensureRc4WindowsMemscanArmed enables the improved-recovery suite", () => {
    const twin = readFileSync(fileURLToPath(new URL(".", import.meta.url)) + "../../../rc4/libs/rc4_memscan.ts", "utf8");
    const armed = twin.slice(twin.indexOf("export function ensureRc4WindowsMemscanArmed"));
    const call = armed.slice(0, armed.indexOf("armSspiHooks"));
    for (const p of ["configureRc4Memscan", "detectSboxes", "sboxExactValidate", "prioritizeAnonymous", "groupedRead"]) {
        assert.ok(call.includes(p), "Windows arming must enable " + p);
    }
});
