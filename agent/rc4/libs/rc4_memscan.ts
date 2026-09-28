/**
 * agent/rc4/libs/rc4_memscan.ts — Windows live RC4 recovery for MANAGED RC4.
 *
 * WHY THIS EXISTS
 *   The API-hook RC4 unit (rc4_hooks.ts: RC4_set_key / BCryptGenerateSymmetricKey /
 *   CryptEncrypt) only fires when a program uses a *crypto library* for RC4. A program
 *   that implements RC4 itself in managed byte arrays (e.g. a .NET/PowerShell KSA/PRGA
 *   loop, the plaintext -> RC4 -> TLS 1.3 fixture) calls no crypto API, so nothing is
 *   hooked and no key is emitted. Its RC4 key lives only in the process's own memory.
 *
 *   This module recovers that key the way research/memory_scan_lsass/agent/rc4_decrypt.js
 *   does (its "Strategy B/A"), ported here and wired into friTap's RC4 keylog channel:
 *     1. Capture the RC4 CIPHERTEXT in-process: hook sspicli!EncryptMessage /
 *        DecryptMessage (the SSPI record layer .NET SslStream drives). The SECBUFFER_DATA
 *        on EncryptMessage entry is the application payload handed to TLS = the RC4
 *        ciphertext before TLS wraps it. No lsass, no pcap needed.
 *     2. Scan this process's own rw- memory for candidate keys (ASCII / UTF-16LE printable
 *        runs) and RC4 S-boxes, and trial-decrypt each against the captured ciphertext.
 *        The candidate whose output looks like plaintext IS the key.
 *     3. Emit the recovered key via emitRc4Key() -> the same RC4_KEY keylog line friTap's
 *        offline RC4 decryptor consumes.
 *
 * SAFETY
 *   All hooks + reads are on THIS (client) process, never lsass, so the lsass reboot-risk
 *   contract does not apply. Every memory read is guarded (try/catch returns null) and a
 *   process-wide exception handler turns a faulting page into a miss, never a crash.
 *   Reads happen in ONE fast burst (measured: sustained injected reads get the target
 *   killed by the OS/EDR; one tight burst + pure CPU survives). Gated behind keylog_enabled
 *   by the executor that arms it, so it runs only under -k.
 */

import { emitRc4Key, hexBytes, readBytes, rc4Prga, rc4 as rc4FromKey, resolveExport } from "./rc4_hooks.js";
import { devlog, log } from "../../util/log.js";

// Frida globals are loosely typed on the injected runtime.
const P: any = Process;

interface MemscanOpts {
    maxRangeBytes: number;
    maxTotalBytes: number;
    minKeyLen: number;
    maxKeyLen: number;
    trialPrefix: number;
    acceptPrintableFraction: number;
    maxTrials: number;
    maxWindowTrials: number;
    maxWindowsPerRun: number;
    maxWindowRunLen: number;
    maxSboxes: number;
    maxSeen: number;
    yieldEveryBuffers: number;
    detectSboxes: boolean;
    recoverKeys: boolean;
    // Improved-recovery options (parity with agent/ms_agent/engines/rc4/index.ts).
    // Code defaults keep today's behavior; the arming executor turns them on.
    sboxFirst: boolean;
    sboxExactValidate: boolean;
    prioritizeAnonymous: boolean;
    requireExactOrAccept: boolean;
    knownPlaintext: Uint8Array | null;
    // Structural early-accept (parity-safe addition, twin unaffected): when on and the
    // captured ciphertext looks length-prefixed ([BE uint32 len][payload]), a candidate
    // whose decrypted prefix begins with an in-range length followed by printable bytes is
    // accepted EXACTLY and sets ctx.stop — the common SSPI/managed case, without waiting
    // for the fuzzy scan to trial-decrypt the whole budget. Off by default (fuzzy behavior).
    structuralAccept: boolean;
    // Grouped-burst read (parity with index.ts). Code default off = today's single burst.
    groupedRead: boolean;
    readGroupBytes: number;
    // FAST-pass tuning (F3). largestFirst orders anonymous ranges LARGEST-first so the big
    // .NET managed-heap segment that holds the key is reached before the many tiny anonymous
    // regions (smallest-first never got there under a small budget). asciiOnly restricts the
    // scan to ASCII-run trials — skipping the UTF-16 pass and the long-run byte-window
    // sliding — for a quick first look. Both off by default (today's behavior); the fast pass
    // turns them on and the full fallback pass leaves them off.
    largestFirst: boolean;
    asciiOnly: boolean;
}

const state: {
    opts: MemscanOpts;
    sboxes: Array<{ addr: string; form: "byte" | "int"; S: Uint8Array; identity: boolean }>;
    armed: boolean;
    handlerInstalled: boolean;
    sspiHooked: boolean;
    keyEmitted: boolean;
    recoveredKey: Uint8Array | null;
    scanning: boolean;
    faults: number;
    // L4 guard: the set of ciphertext LENGTHS already put through a scan that COMPLETED
    // WITHOUT recovering a key. A later frame whose length is already in this set is skipped
    // (a stream of same-size non-RC4 frames can't retrigger the whole scan). A frame of a
    // DIFFERENT length — shorter OR longer — still earns its own scan, so a first non-RC4
    // frame can never permanently block the real (possibly shorter) RC4 frame. Entries are
    // added ONLY after a completed miss, never speculatively before a scan.
    scannedLengths: { [len: number]: boolean };
} = {
    opts: {
        maxRangeBytes: 64 * 1024 * 1024, maxTotalBytes: 300 * 1024 * 1024,
        minKeyLen: 5, maxKeyLen: 64, trialPrefix: 64, acceptPrintableFraction: 0.85,
        maxTrials: 1000000, maxWindowTrials: 300000,
        maxWindowsPerRun: 20000, maxWindowRunLen: 256,
        maxSboxes: 64, maxSeen: 1000000,
        // detectSboxes OFF by default: S-box detection is two extra full O(n) sweeps over
        // the whole burst-read heap (the dominant scan cost), and it CANNOT contribute to
        // the RC4_KEY keylog — an S-box has no key bytes to emit (handleCiphertext logs
        // "no key bytes to emit" for that case). Trial-decrypt (recoverKeys) alone finds
        // the actual key bytes we emit. Turning it off ~halves the scan latency with no
        // loss on the emit path. Re-enable via configureRc4Memscan({detectSboxes:true})
        // only when you specifically want S-box keystream detection for live decrypt.
        yieldEveryBuffers: 8, detectSboxes: false, recoverKeys: true,
        sboxFirst: false, sboxExactValidate: false, prioritizeAnonymous: false,
        requireExactOrAccept: false, knownPlaintext: null,
        groupedRead: false, readGroupBytes: 64 * 1024 * 1024,
        structuralAccept: false,
        largestFirst: false, asciiOnly: false,
    },
    sboxes: [],
    armed: false,
    handlerInstalled: false,
    sspiHooked: false,
    keyEmitted: false,
    recoveredKey: null,
    scanning: false,
    faults: 0,
    scannedLengths: {},
};

/** Merge caller-supplied tuning into the defaults (optional). */
export function configureRc4Memscan(opts: Partial<MemscanOpts>): void {
    if (opts) for (const k in opts) (state.opts as any)[k] = (opts as any)[k];
}

/** Test-only: clear the per-connection recovery state (recovered key, emitted flag, the L4
 *  scanned-length memo, and the reentrancy guard) so a unit test can drive handleCiphertext
 *  from a clean slate. Not used in production (the agent lives for one capture). */
export function resetRc4RecoveryStateForTest(): void {
    state.recoveredKey = null;
    state.keyEmitted = false;
    state.scannedLengths = {};
    state.scanning = false;
}

// hexBytes + readBytes (guarded read: null on a faulting/unmapped page) are shared
// with rc4_hooks.ts and imported above.

const FAULT_LOG_MAX = 3;

function installExceptionHandler(): void {
    if (state.handlerInstalled) return;
    state.handlerInstalled = true;
    try {
        P.setExceptionHandler(function (details: any) {
            state.faults = (state.faults || 0) + 1;
            // Non-readable pages (no-access / PAGE_GUARD) are SKIPPED before the read, not
            // read (see readableScanLength), so a fault here is a rare TOCTOU race (a page
            // freed/reprotected between selection and read) that the guarded read already
            // caught. Log the first few, then only count, to avoid flooding a scan's output.
            if (state.faults <= FAULT_LOG_MAX && details && details.type) {
                devlog("[rc4] native fault " + details.type + " at " + details.address +
                    " (caught; guard/no-access pages are skipped, not read)" +
                    (state.faults === FAULT_LOG_MAX ? " — further faults counted silently" : ""));
            }
            return false;   // keep the target's normal semantics; our reads are guarded
        });
    } catch (e) { /* runtime without setExceptionHandler */ }
}

// ---------------------------------------------------------------------------
// RC4 core (symmetric) + allocation-free trial path. A per-candidate subarray +
// fresh S/out arrays created millions of times exhausts the QuickJS heap (no GC
// inside one long synchronous call); these reuse _S/_out and allocate nothing per trial.
// ---------------------------------------------------------------------------

const _S = new Uint8Array(256), _out = new Uint8Array(256);

// rc4Prga(S, data) and rc4FromKey(key, data) (= rc4() in rc4_hooks.ts) are shared and
// imported above. The allocation-free ksaInto/prgaInto perf variants stay local.

/** KSA from a key given as an offset window into `src`, into the shared _S. */
function ksaInto(src: Uint8Array, off: number, len: number): void {
    const S = _S;
    let i: number, j = 0, t: number;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + src[off + (i % len)]) & 0xff;
        t = S[i]; S[i] = S[j]; S[j] = t;
    }
}

/** PRGA of the shared _S over the first `n` bytes of `data`, into shared _out. */
function prgaInto(data: Uint8Array, n: number): void {
    const s = _S;
    let i = 0, j = 0, m: number, t: number;
    for (m = 0; m < n; m++) {
        i = (i + 1) & 0xff;
        j = (j + s[i]) & 0xff;
        t = s[i]; s[i] = s[j]; s[j] = t;
        _out[m] = data[m] ^ s[(s[i] + s[j]) & 0xff];
    }
}

/** Allocation-free plaintext score over _out[0..n]: printable fraction + token bonus. */
function scoreTrial(n: number): { printableFraction: number; score: number } {
    const o = _out;
    let printable = 0, m: number, c: number;
    for (m = 0; m < n; m++) { c = o[m]; if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0x7e)) printable++; }
    const frac = printable / n;
    let bonus = 0;
    for (m = 0; m + 3 < n; m++) { if (o[m] === 0x47 && o[m + 1] === 0x45 && o[m + 2] === 0x54 && o[m + 3] === 0x20) { bonus += 0.15; break; } } // "GET "
    for (m = 0; m + 3 < n; m++) { if (o[m] === 0x48 && o[m + 1] === 0x54 && o[m + 2] === 0x54 && o[m + 3] === 0x50) { bonus += 0.15; break; } } // "HTTP"
    return { printableFraction: frac, score: frac + bonus };
}

const TOKENS = ["GET ", "POST ", "HEAD ", "PUT ", "HTTP", "Host:", "User-Agent", "{", "</", ": "];

function scorePlaintext(bytes: Uint8Array | null): { printableFraction: number; score: number; ascii: string } {
    if (bytes === null || bytes.length === 0) return { printableFraction: 0, score: 0, ascii: "" };
    let printable = 0, i: number, c: number;
    for (i = 0; i < bytes.length; i++) { c = bytes[i]; if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0x7e)) printable++; }
    const frac = printable / bytes.length;
    let str = "";
    for (i = 0; i < bytes.length; i++) { c = bytes[i]; str += (c >= 0x20 && c <= 0x7e) ? String.fromCharCode(c) : "."; }
    let bonus = 0;
    for (i = 0; i < TOKENS.length; i++) if (str.indexOf(TOKENS[i]) >= 0) bonus += 0.15;
    return { printableFraction: frac, score: frac + bonus, ascii: str };
}

// ---------------------------------------------------------------------------
// S-box permutation detection (byte form and int[256] form). A generation-stamped
// rolling distinct-value window: a 256-value run of distinct bytes IS a permutation
// of 0..255. Identity permutations (pre-KSA) are skipped as false-positive magnets.
// ---------------------------------------------------------------------------

const _pos = new Int32Array(256);

function scanByteSboxes(u8: Uint8Array, base: NativePointer): void {
    const pos = _pos; pos.fill(-1);
    let start = 0;
    for (let r = 0; r < u8.length; r++) {
        const v = u8[r];
        if (pos[v] >= start) start = pos[v] + 1;
        pos[v] = r;
        if (r - start + 1 === 256) recordSbox(base.add(start).toString(), "byte", u8, start);
    }
}

function scanIntSboxes(u8: Uint8Array, base: NativePointer): void {
    const pos = _pos; pos.fill(-1);
    let start = 0; const ndw = u8.length >> 2;
    for (let r = 0; r < ndw; r++) {
        const p = r * 4;
        if (u8[p + 1] !== 0 || u8[p + 2] !== 0 || u8[p + 3] !== 0) { start = r + 1; continue; }
        const v = u8[p];
        if (pos[v] >= start) start = pos[v] + 1;
        pos[v] = r;
        if (r - start + 1 === 256) recordSbox(base.add(start * 4).toString(), "int", u8, start * 4);
    }
}

function recordSbox(addrStr: string, form: "byte" | "int", u8: Uint8Array, off: number): void {
    if (state.sboxes.length >= state.opts.maxSboxes) return;
    const S = new Uint8Array(256);
    let k: number;
    if (form === "byte") { for (k = 0; k < 256; k++) S[k] = u8[off + k]; }
    else { for (k = 0; k < 256; k++) S[k] = u8[off + k * 4]; }
    let identity = true;
    for (k = 0; k < 256; k++) if (S[k] !== k) { identity = false; break; }
    state.sboxes.push({ addr: addrStr, form: form, S: S, identity: identity });
}

// ---------------------------------------------------------------------------
// Streaming trial-decrypt key recovery. Never stores candidates: each printable
// run is trial-decrypted against the captured ciphertext ON THE FLY and only the
// single best result is kept — O(1) memory regardless of heap size.
// ---------------------------------------------------------------------------

interface TrialCtx {
    prefix: Uint8Array | null;
    prefixLen: number;
    best: { source: string; key: Uint8Array; keyHex: string; score: number; printableFraction: number } | null;
    trials: number;
    windowTrials: number;
    candidates: number;
    seen: { [h: number]: number };
    seenCount: number;
    stop: boolean;
    exact: { source: string; key: Uint8Array; keyHex: string; sboxIdx: number } | null;
    live: { boxes: Uint8Array[]; b0: number[]; bN: number[]; n: number } | null;
    // Structural-accept hint derived per-recover from the captured ciphertext (null = off).
    // maxLen is the in-range bound for a decoded length prefix (the ciphertext length).
    struct: { maxLen: number } | null;
    ranges?: number;
    readBytes?: number;
}

function isPrintable(c: number): boolean { return c >= 0x20 && c <= 0x7e; }

// High-confidence printable-prefix accept (F2). A decrypted trial prefix at least this many
// bytes long AND at least this fraction printable proves the key without any length prefix.
// 24 bytes @ 0.97 gives a ~0.37^24 ≈ 1e-10 false-accept against wrong keys (~0.37 printable).
const HIGH_PRINTABLE_MIN_LEN = 24;
const HIGH_PRINTABLE_FRAC = 0.97;

/* Exact-validation set from the live (non-identity) S-boxes found this scan.
 * b0/bN are first/last-byte prechecks so the 256-byte compare runs only on a hit. */
function buildLiveSboxes(): { boxes: Uint8Array[]; b0: number[]; bN: number[]; n: number } {
    const boxes: Uint8Array[] = [], b0: number[] = [], bN: number[] = [];
    for (let s = 0; s < state.sboxes.length; s++) {
        const sb = state.sboxes[s];
        if (sb.identity) continue;
        boxes.push(sb.S); b0.push(sb.S[0]); bN.push(sb.S[255]);
    }
    return { boxes: boxes, b0: b0, bN: bN, n: boxes.length };
}
/* Does KSA(candidate) in _S reproduce a found S-box? Exact, plaintext-free. */
function ksaMatchesSbox(live: { boxes: Uint8Array[]; b0: number[]; bN: number[]; n: number }): number {
    const S = _S;
    for (let k = 0; k < live.n; k++) {
        if (S[0] !== live.b0[k] || S[255] !== live.bN[k]) continue;
        const box = live.boxes[k]; let ok = true;
        for (let m = 0; m < 256; m++) { if (S[m] !== box[m]) { ok = false; break; } }
        if (ok) return k;
    }
    return -1;
}

function trialKey(ctx: TrialCtx, src: Uint8Array, off: number, len: number, source: string, isWindow: boolean): void {
    ctx.candidates++;
    if (ctx.stop) return;
    // Exact S-box validation needs no ciphertext; the scored path needs a prefix.
    const canSbox = state.opts.sboxExactValidate && ctx.live !== null && ctx.live.n > 0;
    if (ctx.prefix === null && !canSbox) return;
    if (isWindow) { if (ctx.windowTrials >= state.opts.maxWindowTrials) return; }
    else if (ctx.trials >= state.opts.maxTrials) return;
    // Collision-safe 64-bit dedup: two FNV-1a lanes; on an h1 collision with a
    // different h2 we PROCEED (never silently skip a distinct candidate).
    let h1 = (2166136261 ^ len) >>> 0;
    let h2 = ((2166136261 ^ 0x9e3779b9) ^ len) >>> 0;
    for (let q = 0; q < len; q++) {
        const b = src[off + q];
        h1 = (h1 ^ b) >>> 0; h1 = Math.imul(h1, 16777619) >>> 0;
        h2 = (h2 ^ b) >>> 0; h2 = Math.imul(h2, 16777619) >>> 0;
    }
    const prev = ctx.seen[h1];
    if (prev === h2) return;
    if (prev === undefined && ctx.seenCount < state.opts.maxSeen) { ctx.seen[h1] = h2; ctx.seenCount++; }
    if (isWindow) ctx.windowTrials++; else ctx.trials++;
    ksaInto(src, off, len);
    // (1) Exact acceptance via S-box KSA match (zero false accepts, no plaintext).
    if (canSbox) {
        const mi = ksaMatchesSbox(ctx.live as any);
        if (mi >= 0) {
            const kx = new Uint8Array(len);
            for (let a = 0; a < len; a++) kx[a] = src[off + a];
            ctx.exact = { source: "sbox", key: kx, keyHex: hexBytes(kx), sboxIdx: mi };
            ctx.stop = true; return;
        }
    }
    if (ctx.prefix === null) return;
    prgaInto(ctx.prefix, ctx.prefixLen);
    // (2) Exact acceptance via known-plaintext: keystream reproduces the known prefix.
    const kp = state.opts.knownPlaintext;
    if (kp !== null && kp.length <= ctx.prefixLen) {
        let match = true;
        for (let c = 0; c < kp.length; c++) { if (_out[c] !== kp[c]) { match = false; break; } }
        if (match) {
            const ky = new Uint8Array(len);
            for (let a2 = 0; a2 < len; a2++) ky[a2] = src[off + a2];
            ctx.exact = { source: "known-plaintext", key: ky, keyHex: hexBytes(ky), sboxIdx: -1 };
            ctx.stop = true; return;
        }
    }
    // (2b) Exact acceptance via captured-frame structure: the SSPI frame is
    //      [BE uint32 length][payload]. If the decrypted prefix begins with an in-range
    //      length and the bytes after it clear the printable gate, the key is proven —
    //      accept + early-stop. Opt-in per-recover via ctx.struct (derived from the
    //      ciphertext, not hardcoded); false-accept risk is near-zero (exact in-range
    //      length AND a printable-payload confirmation). Falls through to the fuzzy
    //      ranking below when it does not fire, so non-length-prefixed captures still work.
    const st = ctx.struct;
    if (st !== null && ctx.prefixLen >= 5) {
        const L = ((_out[0] << 24) | (_out[1] << 16) | (_out[2] << 8) | _out[3]) >>> 0;
        if (L > 0 && L <= st.maxLen) {
            let checkLen = L < 64 ? L : 64;
            if (checkLen > ctx.prefixLen - 4) checkLen = ctx.prefixLen - 4;
            if (checkLen > 0) {
                let printable = 0;
                for (let c = 4; c < 4 + checkLen; c++) {
                    const ch = _out[c];
                    if (ch === 9 || ch === 10 || ch === 13 || (ch >= 0x20 && ch <= 0x7e)) printable++;
                }
                if (printable / checkLen >= state.opts.acceptPrintableFraction) {
                    const ks = new Uint8Array(len);
                    for (let a3 = 0; a3 < len; a3++) ks[a3] = src[off + a3];
                    ctx.exact = { source: "length-prefix", key: ks, keyHex: hexBytes(ks), sboxIdx: -1 };
                    ctx.stop = true; return;
                }
            }
        }
    }
    const sc = scoreTrial(ctx.prefixLen);
    // (2c) Demo-agnostic high-confidence printable accept — does NOT depend on a length
    //      prefix, so it fires on BARE ciphertext (the real target's recovering frame is bare
    //      ciphertext: the demo sends the 4-byte length in its own SSPI frame, so the payload
    //      frame carries no prefix and the structural accept above can never fire). A wrong
    //      RC4 key decrypts to ~0.37 printable; a run of >= HIGH_PRINTABLE_MIN_LEN usable
    //      bytes that is >= HIGH_PRINTABLE_FRAC printable is the real key. False-accept is
    //      ~0.37^24 ≈ 1e-10. Frames shorter than HIGH_PRINTABLE_MIN_LEN fall through to the
    //      fuzzy ranking below (no regression).
    if (ctx.prefixLen >= HIGH_PRINTABLE_MIN_LEN && sc.printableFraction >= HIGH_PRINTABLE_FRAC) {
        const kh = new Uint8Array(len);
        for (let a4 = 0; a4 < len; a4++) kh[a4] = src[off + a4];
        ctx.exact = { source: "printable-prefix", key: kh, keyHex: hexBytes(kh), sboxIdx: -1 };
        ctx.stop = true; return;
    }
    // (3) Ranking only (fuzzy): keep the single best-scoring candidate.
    if (ctx.best === null || sc.score > ctx.best.score) {
        const key = new Uint8Array(len);
        for (let i = 0; i < len; i++) key[i] = src[off + i];
        ctx.best = { source: source, key: key, keyHex: hexBytes(key), score: sc.score, printableFraction: sc.printableFraction };
    }
}

function runToTrials(ctx: TrialCtx, u8: Uint8Array, runStart: number, runEnd: number, source: string): void {
    if (ctx.stop) return;
    const minL = state.opts.minKeyLen, maxL = state.opts.maxKeyLen, runLen = runEnd - runStart;
    if (runLen < minL) return;
    if (runLen <= maxL) { trialKey(ctx, u8, runStart, runLen, source, false); return; }
    if (state.opts.asciiOnly) return;                  // fast look: no long-run window sliding
    if (runLen > state.opts.maxWindowRunLen) return;   // giant blob: skip (budget guard)
    let perRun = 0; const cap = state.opts.maxWindowsPerRun;
    for (let i = runStart; i < runEnd && perRun < cap && !ctx.stop && ctx.windowTrials < state.opts.maxWindowTrials; i++) {
        const maxHere = Math.min(maxL, runEnd - i);
        for (let L = minL; L <= maxHere && perRun < cap && !ctx.stop; L++) { trialKey(ctx, u8, i, L, source, true); perRun++; }
    }
}

const _u16 = new Uint8Array(8192);

function detectSboxesChunk(u8: Uint8Array, base: NativePointer): void {
    // sboxFirst forces detection even when detectSboxes is off (exact validation needs it).
    if (!(state.opts.detectSboxes || state.opts.sboxFirst)) return;
    if (state.sboxes.length < state.opts.maxSboxes) scanByteSboxes(u8, base);
    if (state.sboxes.length < state.opts.maxSboxes) scanIntSboxes(u8, base);
}
function recoverChunk(ctx: TrialCtx, u8: Uint8Array, base: NativePointer): void {
    if (!state.opts.recoverKeys || ctx.stop) return;

    // ASCII runs (trialled in place by offset — no per-run allocation).
    let off: number, runStart = -1;
    for (off = 0; off <= u8.length; off++) {
        const printable = off < u8.length && isPrintable(u8[off]);
        if (printable) { if (runStart < 0) runStart = off; }
        else { if (runStart >= 0) { runToTrials(ctx, u8, runStart, off, "ascii"); runStart = -1; if (ctx.stop) return; } }
    }

    // UTF-16LE runs (printable even bytes, zero odd bytes) -> decode into reused scratch.
    // Skipped on the fast look (asciiOnly): the managed RC4 key is an ASCII byte array, so
    // the UTF-16 pass only adds cost there; the full fallback pass still runs it.
    if (state.opts.asciiOnly) return;
    let u16Start = -1;
    for (off = 0; off + 1 < u8.length; off += 2) {
        if (ctx.stop) return;
        const ok = isPrintable(u8[off]) && u8[off + 1] === 0;
        if (ok) { if (u16Start < 0) u16Start = off; }
        else if (u16Start >= 0) {
            let n = (off - u16Start) >> 1; if (n > _u16.length) n = _u16.length;
            if (n >= state.opts.minKeyLen) {
                for (let d = 0; d < n; d++) _u16[d] = u8[u16Start + d * 2];
                runToTrials(ctx, _u16, 0, n, "utf16");
            }
            u16Start = -1;
        }
    }
}
/* Legacy interleaved path (sboxFirst:false): detect + recover in one pass. */
function scanChunk(ctx: TrialCtx, u8: Uint8Array, base: NativePointer): void {
    detectSboxesChunk(u8, base);
    recoverChunk(ctx, u8, base);
}

// ---------------------------------------------------------------------------
// Range selection (rw-, exclude agent/frida ranges) + one fast burst read.
// ---------------------------------------------------------------------------

const AGENT_PATTERNS = [/frida/i, /gum-js/i];

// Guarded whole-range read is done in page-aligned sub-chunks of at most this size, each
// re-checking protection, instead of one up-to-64MB readByteArray spanning mixed-protection
// pages. 1MB keeps the per-chunk protection check cheap while bounding a re-scan.
const READ_CHUNK_BYTES = 1024 * 1024;

/* Pure clamp (ported LOCALLY from agent/ms_agent/core/memory.ts — the two are separate
 * bundles and must NOT cross-import): of the requested `size` bytes starting at `base`, how
 * many stay inside the live mapping [rangeBase, rangeBase+rangeSize)? Inputs are addresses
 * as plain numbers; a base before the mapping, or at/after its end, clamps to 0. */
function clampReadableLength(base: number, size: number, rangeBase: number, rangeSize: number): number {
    if (size <= 0 || rangeSize <= 0) return 0;
    if (base < rangeBase) return 0;
    const available = rangeBase + rangeSize - base;
    if (available <= 0) return 0;
    return available < size ? available : size;
}

/* User-space bases and range sizes fit well under 2^53, so a pointer -> number is lossless. */
function ptrToNum(p: any): number { return parseInt(p.toString(), 16); }

/* How many bytes from `base` are mapped and READABLE right now, capped at `size`? Returns 0
 * to skip. Ported locally from the twin's readableScanLength: require a live mapping whose
 * FIRST protection char is 'r' — this skips no-access '---' pages AND, critically on Windows,
 * PAGE_GUARD stack pages (Frida reports their protection without the read bit). Reading a
 * guard page is DESTRUCTIVE: the OS consumes the guard to grow the stack, priming a later
 * stack overflow that cleanly terminates the target. Then clamp to the live mapping end
 * (rd.base+rd.size): a page freed/shrunk/reprotected since selectRanges() (a TOCTOU race)
 * would otherwise fault mid-read with a native access violation JS try/catch can't trap. */
function readableScanLength(base: any, size: number): number {
    try {
        const rd = P.findRangeByAddress(base);
        if (rd === null || rd === undefined || !rd.protection || rd.protection.charAt(0) !== "r") return 0;
        return clampReadableLength(ptrToNum(base), size, ptrToNum(rd.base), rd.size);
    } catch (e) { return 0; }
}

/* Read up to `size` bytes from `base` as one contiguous buffer, reading in page-aligned
 * sub-chunks and re-checking protection before EACH — so a guard/no-access page is never
 * consumed and a live mapping is never faulted. Stops at the first non-readable sub-chunk
 * (returning the readable prefix, keeping the buffer's base offsets exact) or when the live
 * mapping ends. Returns null when nothing is readable. */
function readRangeGuarded(base: NativePointer, size: number): Uint8Array | null {
    if (size <= 0) return null;
    const out = new Uint8Array(size);
    let got = 0;
    while (got < size) {
        let want = size - got;
        if (want > READ_CHUNK_BYTES) want = READ_CHUNK_BYTES;
        const sub = base.add(got);
        const readable = readableScanLength(sub, want);
        if (readable <= 0) break;                  // guard / no-access / shrunk: stop here
        const chunk = readBytes(sub, readable);
        if (chunk === null) break;
        out.set(chunk, got);
        got += chunk.length;
        if (chunk.length < want) break;            // mapping ended inside this sub-chunk
    }
    if (got === 0) return null;
    return got === size ? out : out.subarray(0, got);
}

function selectRanges(): Array<{ base: NativePointer; size: number; anonymous: boolean }> {
    const out: Array<{ base: NativePointer; size: number; anonymous: boolean }> = [];
    try {
        const owned: Array<{ base: NativePointer; end: NativePointer }> = [];
        try {
            const mods = P.enumerateModules();
            for (let m = 0; m < mods.length; m++) {
                const name = (mods[m].name || "") + " " + (mods[m].path || "");
                for (let p = 0; p < AGENT_PATTERNS.length; p++) {
                    if (AGENT_PATTERNS[p].test(name)) { owned.push({ base: mods[m].base, end: mods[m].base.add(mods[m].size) }); break; }
                }
            }
        } catch (e) { /* */ }
        const all = P.enumerateRanges({ protection: "rw-", coalesce: false });
        for (let i = 0; i < all.length; i++) {
            const r = all[i];
            let isOwned = false;
            for (let o = 0; o < owned.length; o++) {
                if (r.base.compare(owned[o].end) < 0 && owned[o].base.compare(r.base.add(r.size)) < 0) { isOwned = true; break; }
            }
            if (isOwned) continue;
            // Exclude file-backed ranges entirely: the managed RC4 key (and the .NET heap
            // that holds it) is private-commit / anonymous, so a file-backed rw- mapping
            // (a DLL data section, a memory-mapped file) can only add scan cost and, on
            // Windows, risk touching a copy-on-write or specially-protected page. `anonymous`
            // used to be only a sort hint; here it is a hard filter.
            if (r.file != null) continue;
            out.push({ base: r.base, size: r.size, anonymous: true });
        }
    } catch (e: any) { devlog("[rc4] selectRanges: " + (e && e.message ? e.message : e)); }
    return out;
}

/** Read ONE range into a buffer, honoring the per-range cap and remaining total budget.
 *  Returns {base, u8, anonymous, size} or null (unreadable / no budget left). Shared by
 *  the single-burst (readAllFast) and grouped-burst read paths so cap/budget accounting is
 *  single-sourced (parity with index.ts rc4ReadOneRange). */
function readOneRange(range: { base: NativePointer; size: number; anonymous: boolean }, totalSoFar: number): { base: NativePointer; u8: Uint8Array; anonymous: boolean; size: number } | null {
    const perCap = state.opts.maxRangeBytes, budget = state.opts.maxTotalBytes;
    if (totalSoFar >= budget) return null;
    let sz = range.size;
    if (sz > perCap) sz = perCap;
    if (totalSoFar + sz > budget) sz = budget - totalSoFar;
    // Safe read: page-aligned sub-chunks, each re-checking protection (never consumes a
    // guard page, never faults a live mapping). Returns the contiguous readable prefix.
    const u8 = readRangeGuarded(range.base, sz);
    if (u8 === null) return null;
    return { base: range.base, u8: u8, anonymous: range.anonymous, size: u8.length };
}

/** Smallest-first order (reused for the plain sort and as the anonymous-first tie-break):
 *  a heap larger than the budget still covers the small/medium ranges where a key is
 *  likeliest, not one giant mapping. */
function bySize(a: { size: number }, b: { size: number }): number { return a.size - b.size; }

/** Order ranges for the grouped-burst path: anonymous/managed-heap first when
 *  prioritize_anonymous is set (so the key lands in the first group and early-stop skips
 *  the tail READS), else smallest-first; smallest-first within each class (parity with
 *  index.ts rc4OrderRanges). */
function orderRangesGrouped(ranges: Array<{ base: NativePointer; size: number; anonymous: boolean }>): Array<{ base: NativePointer; size: number; anonymous: boolean }> {
    const ordered = ranges.slice();
    if (state.opts.largestFirst) {
        // FAST-pass order: the .NET managed-heap segment holding the key is a LARGE anonymous
        // mapping, so read it before the many tiny anonymous regions. Combined with F2's
        // early-stop this reaches the key fast without a small budget cap (which read tiny
        // regions first and never got to the heap).
        ordered.sort(function (a, b) { return b.size - a.size; });
    } else if (state.opts.prioritizeAnonymous) {
        ordered.sort(function (a, b) { return (a.anonymous === b.anonymous) ? bySize(a, b) : (a.anonymous ? -1 : 1); });
    } else {
        ordered.sort(bySize);
    }
    return ordered;
}

/** PHASE 1 — burst-read the selected ranges into JS buffers as fast as possible
 *  (one tight burst; sustained injected reads get the target killed by the OS/EDR). */
function readAllFast(): { buffers: Array<{ base: NativePointer; u8: Uint8Array; anonymous: boolean }>; ranges: number; total: number } {
    const ranges = selectRanges();
    const buffers: Array<{ base: NativePointer; u8: Uint8Array; anonymous: boolean }> = [];
    let total = 0;
    // Smallest-first: an app/managed heap is many moderate rw- allocations; a heap larger
    // than the budget still covers all small/medium ranges instead of one giant region.
    ranges.sort(bySize);
    for (let i = 0; i < ranges.length; i++) {
        if (total >= state.opts.maxTotalBytes) break;
        const r = readOneRange(ranges[i], total);
        if (r !== null) { buffers.push(r); total += r.size; }
    }
    return { buffers: buffers, ranges: ranges.length, total: total };
}

function yieldTick(): Promise<void> { return new Promise(function (res) { setTimeout(res, 0); }); }

// Structural early-accept needs at least a 4-byte length prefix plus one payload byte to
// confirm; below this a captured frame is too short to reason about structurally.
const STRUCT_MIN_CT_LEN = 8;

/** One live memory pass: burst-read, then pure-CPU detect S-boxes + stream-trial keys. */
export async function analyze(ct: Uint8Array | null): Promise<TrialCtx> {
    state.sboxes = [];
    const prefix = ct ? ct.subarray(0, Math.min(state.opts.trialPrefix, ct.length)) : null;
    // Structural-accept hint: only when opted in AND the ciphertext is long enough to
    // plausibly carry a 4-byte length prefix plus payload. maxLen (the in-range bound for a
    // decoded length) is the ciphertext length — derived here, never hardcoded in trialKey.
    const struct = (state.opts.structuralAccept && ct !== null && ct.length >= STRUCT_MIN_CT_LEN)
        ? { maxLen: ct.length } : null;
    const ctx: TrialCtx = {
        prefix: prefix, prefixLen: prefix ? prefix.length : 0, best: null,
        trials: 0, windowTrials: 0, candidates: 0, seen: {}, seenCount: 0,
        stop: false, exact: null, live: null, struct: struct,
    };
    const every = state.opts.yieldEveryBuffers || 8;
    if (state.opts.groupedRead && !state.opts.sboxFirst) {
        // Grouped-burst read (parity with index.ts): order anonymous-first, read a large
        // GROUP of ranges as one tight burst (EDR-safe — still burst + CPU), interleaved
        // detect+recover + free per buffer, then check early-stop before reading the next
        // group. Exact evidence in an early group skips the tail READS (the read-IPC
        // bottleneck), not just CPU. groupedRead=false restores the single burst below.
        const ordered = orderRangesGrouped(selectRanges());
        let total = 0, gi = 0, rangesUsed = 0, yc = 0;
        const budget = state.opts.maxTotalBytes, groupCap = state.opts.readGroupBytes;
        while (gi < ordered.length && total < budget && !ctx.stop) {
            const group: Array<{ base: NativePointer; u8: Uint8Array; anonymous: boolean; size: number }> = [];
            let gBytes = 0;
            while (gi < ordered.length && total < budget && gBytes < groupCap) {
                const rr = readOneRange(ordered[gi], total);
                gi++;
                if (rr !== null) { group.push(rr); total += rr.size; gBytes += rr.size; rangesUsed++; }
            }
            for (let gj = 0; gj < group.length; gj++) {
                if (!ctx.stop) { try { scanChunk(ctx, group[gj].u8, group[gj].base); } catch (e) { /* */ } }
                (group[gj] as any).u8 = null;   // free as we go
                if ((yc++ % every) === 0) await yieldTick();
                if (ctx.stop) break;
            }
        }
        ctx.ranges = rangesUsed; ctx.readBytes = total;
        return ctx;
    }
    const read = readAllFast();
    if (state.opts.sboxFirst) {
        // PHASE 2a: detect S-boxes across ALL buffers first (no free), so a live S-box
        // found anywhere can exactly-validate a candidate in any chunk.
        for (let d = 0; d < read.buffers.length; d++) {
            try { detectSboxesChunk(read.buffers[d].u8, read.buffers[d].base); } catch (e) { /* */ }
            if ((d % every) === 0) await yieldTick();
        }
        ctx.live = buildLiveSboxes();
        // Visit anonymous/managed-heap ranges first so early-stop fires sooner
        // (read order/budget untouched — the EDR-safe burst above is unchanged).
        if (state.opts.prioritizeAnonymous) {
            read.buffers.sort(function (a, b) { return (a.anonymous === b.anonymous) ? 0 : (a.anonymous ? -1 : 1); });
        }
        // PHASE 2b: recover, freeing as we go; can early-stop on exact evidence.
        for (let j = 0; j < read.buffers.length; j++) {
            if (!ctx.stop) { try { recoverChunk(ctx, read.buffers[j].u8, read.buffers[j].base); } catch (e) { /* */ } }
            (read.buffers[j] as any).u8 = null;   // free even if stopped
            if ((j % every) === 0) await yieldTick();
        }
    } else {
        for (let i = 0; i < read.buffers.length; i++) {
            // Honor early-stop on this path too: once ctx.stop is set (an exact/printable
            // accept), skip scanning the remaining buffers instead of grinding through them.
            if (!ctx.stop) { try { scanChunk(ctx, read.buffers[i].u8, read.buffers[i].base); } catch (e) { /* */ } }
            (read.buffers[i] as any).u8 = null;   // free even if stopped
            if ((i % every) === 0) await yieldTick();
        }
    }
    ctx.ranges = read.ranges; ctx.readBytes = read.total;
    return ctx;
}

// ---------------------------------------------------------------------------
// Orchestration — recover the key for a captured ciphertext (trial-key -> S-box).
// ---------------------------------------------------------------------------

function sboxPrefixScore(S: Uint8Array, prefix: Uint8Array, prefixLen: number): number {
    for (let k = 0; k < 256; k++) _S[k] = S[k];
    prgaInto(prefix, prefixLen);
    return scoreTrial(prefixLen).score;
}

interface Recovered { ok: boolean; key: Uint8Array | null; sbox: Uint8Array | null; source: string; plaintextAscii: string; printableFraction: number; }

// FAST PASS (F2 + F3): LARGEST-anonymous-first ordering, ASCII-run trials only, and a
// demo-agnostic printable/structural early-stop, with NO S-box detection. Handles the common
// case — a printable key in the .NET managed heap, whose recovering SSPI frame is BARE
// ciphertext — in seconds, stopping the moment a decrypted prefix reads as plaintext. When it
// fails to clear the accept gate, recover() falls back to the FULL pass (the armed config:
// full budget + UTF-16 pass + S-box detection), so nothing that recovers today is lost. Both
// passes now use the F1 safe reads and skip file-backed ranges.
const FAST_PASS_OVERRIDES: Partial<MemscanOpts> = {
    structuralAccept: true,     // length-prefix early-accept when a captured frame carries one
    detectSboxes: false,        // skip the two O(n) S-box sweeps on the fast look
    sboxExactValidate: false,   // no S-boxes detected here to validate against
    prioritizeAnonymous: true,  // (all selected ranges are anonymous now; harmless)
    largestFirst: true,         // reach the LARGE managed-heap segment before tiny regions
    asciiOnly: true,            // ASCII-run trials only (skip UTF-16 + long-run windowing)
    groupedRead: true,          // grouped burst so early-stop skips the tail READS, not just CPU
    // maxTotalBytes is NOT capped here: the old 32MB cap read tiny anonymous regions first and
    // never reached the .NET heap that holds the key. With largestFirst + F2's printable/
    // structural early-stop, the fast pass reaches the heap and stops on the first confident
    // hit, so it stays fast without a budget cap that hides the key. A genuine miss falls
    // through to the FULL pass (S-box + UTF-16 + full budget), so nothing that recovers today
    // is lost.
};

/** Run one recovery pass. `overrides` (null = the armed/full config) are applied for the
 *  whole pass — analyze() AND the accept gate read state.opts, so the swap wraps both and
 *  is always restored. Single scan-in-flight (state.scanning) keeps this reentrancy-safe. */
async function recoverPass(ct: Uint8Array, overrides: Partial<MemscanOpts> | null): Promise<Recovered> {
    const saved = state.opts;
    if (overrides) state.opts = Object.assign({}, saved, overrides);
    try {
        return await recoverOnce(ct);
    } finally {
        if (overrides) state.opts = saved;
    }
}

/** Two-attempt recover: a cheap structural/heap-first fast pass, then — only if it fails —
 *  the full armed pass (unchanged behavior) so no recovery capability is lost. */
export async function recover(ct: Uint8Array): Promise<Recovered> {
    const fast = await recoverPass(ct, FAST_PASS_OVERRIDES);
    if (fast.ok) return fast;
    return recoverPass(ct, null);
}

async function recoverOnce(ct: Uint8Array): Promise<Recovered> {
    const ctx = await analyze(ct);
    const prefix = ctx.prefix as Uint8Array, prefixLen = ctx.prefixLen;
    let best: { source: string; key: Uint8Array | null; sbox: Uint8Array | null; score: number } | null = null;
    // Exact evidence (KSA reproduces a live S-box, or known-plaintext match): the key
    // bytes are proven. Route it ahead of the scored candidates (dominating score) so
    // the existing accept gate validates it and it wins over any fuzzy trial/S-box pick.
    if (ctx.exact) {
        best = { source: "trial-key-exact(" + ctx.exact.source + ")", key: ctx.exact.key, sbox: null, score: Number.POSITIVE_INFINITY };
    } else if (ctx.best) {
        // B: the best streaming trial-key from the memory pass.
        best = { source: "trial-key(" + ctx.best.source + ")", key: ctx.best.key, sbox: null, score: ctx.best.score };
    }
    // A: detected S-boxes used as post-KSA keystream (no key bytes).
    for (let i = 0; i < state.sboxes.length; i++) {
        if (state.sboxes[i].identity) continue;
        const sc = sboxPrefixScore(state.sboxes[i].S, prefix, prefixLen);
        if (best === null || sc > best.score) {
            best = { source: "sbox-keystream(" + state.sboxes[i].form + "@" + state.sboxes[i].addr + ")", key: null, sbox: state.sboxes[i].S, score: sc };
        }
    }
    if (best === null) return { ok: false, key: null, sbox: null, source: "no-candidates", plaintextAscii: "", printableFraction: 0 };
    const full = best.sbox ? rc4Prga(best.sbox, ct) : rc4FromKey(best.key as Uint8Array, ct);
    const scored = scorePlaintext(full);
    // Accept on the COMBINED score (printable fraction + token bonus), NOT the old
    // "printable-enough OR contains any token byte" clause: TOKENS includes single-byte
    // "{", so ~random RC4 output (~0.4 printable) that happens to contain one would be
    // wrongly accepted, emitting a bogus key. Genuine plaintext clears frac ~1.0 easily;
    // random output falls well short. (Mirrors the fix in friTap/offline/rc4/decrypt.py.)
    const ok = scored.score >= state.opts.acceptPrintableFraction;
    return { ok: ok, key: best.key, sbox: best.sbox, source: best.source, plaintextAscii: scored.ascii, printableFraction: scored.printableFraction };
}

// Below this many bytes, a frame is not worth a memory scan: too short to score
// reliably (a handful of bytes decrypt to "printable" under many wrong keys), and the
// fixture's per-message 4-byte length prefix rides its own tiny SSPI frame. Recovering
// from a real message frame (>= this) avoids emitting a spurious key from the length
// frame. The key persists across frames, so any one sufficiently long frame recovers it.
const MIN_CT_LEN = 16;

/** Decrypt one captured frame with the ALREADY-recovered key and log the plaintext.
 * Cheap (no memory scan): just RC4 with the known key. Tries the frame as-is AND after
 * skipping a 4-byte length prefix (the fixture sends `[len][ciphertext]`, and the inbound
 * TLS record often coalesces the two), keeping whichever looks more like plaintext. Purely
 * observational — the RC4_KEY line was already emitted; this lets -v show the live chat
 * even when the traffic itself is not in a pcap (e.g. loopback, which the -f capture on
 * Windows does not record). */
function decryptFrameWithKey(ct: Uint8Array, dir: string): void {
    try {
        const key = state.recoveredKey as Uint8Array;
        const whole = scorePlaintext(rc4FromKey(key, ct));
        let best = whole, off = 0;
        if (ct.length > 4) {
            const skipped = scorePlaintext(rc4FromKey(key, ct.subarray(4)));
            if (skipped.score > whole.score) { best = skipped; off = 4; }
        }
        if (best.printableFraction >= state.opts.acceptPrintableFraction || best.score > best.printableFraction) {
            log("[rc4] " + dir + " plaintext" + (off ? " (after 4B len)" : "") + ": '" + best.ascii + "'");
        }
    } catch (e) { /* observational only */ }
}

/** Called from the SSPI capture with one RC4 ciphertext frame. Recovers the key once
 * (memory scan + trial-decrypt), emits it, then decrypts every later frame directly.
 * Exported for unit tests (the L4 re-scan logic); production drives it via the SSPI hooks. */
export async function handleCiphertext(ct: Uint8Array, dir: string): Promise<void> {
    if (!ct || ct.length < MIN_CT_LEN) return;
    // Fast path: key already known — decrypt this frame directly, no memory scan.
    if (state.recoveredKey !== null) { decryptFrameWithKey(ct, dir); return; }
    if (state.scanning) return;   // a scan is already in flight; skip concurrent frames
    // L4: skip a re-scan ONLY for a frame length we already scanned to completion WITHOUT
    // recovering a key. A different length — shorter OR longer — may carry the real RC4
    // frame, so it earns its own scan; a first non-RC4 frame can't permanently block the real
    // (possibly shorter) RC4 frame the way a "<= longest scanned" gate did. The length is
    // remembered only AFTER a completed miss (below), never speculatively before the scan.
    // With F2/F3 scans are fast, so an occasional re-scan of a new length is cheap.
    if (state.scannedLengths[ct.length]) return;
    state.scanning = true;
    try {
        const r = await recover(ct);
        if (!r.ok) {
            state.scannedLengths[ct.length] = true;   // remember only after a completed miss
            devlog("[rc4] memscan: could not confidently decrypt " + dir + " ciphertext (" + ct.length + "B); best='" + r.plaintextAscii + "'");
            return;
        }
        if (r.key !== null) {
            emitRc4Key(r.key, "trial-key(mem)", dir);
            state.keyEmitted = true;
            state.recoveredKey = r.key;   // enable the fast decrypt path for later frames
            log("[rc4] recovered RC4 key from process memory via " + r.source + " (dir=" + dir + "); plaintext='" + r.plaintextAscii + "'");
        } else {
            // S-box-only recovery: we can decrypt but there are no key bytes to write as an
            // RC4_KEY line, so we report the plaintext but cannot emit a keylog entry.
            log("[rc4] memscan recovered an RC4 keystream (S-box) but no key bytes to emit; plaintext='" + r.plaintextAscii + "'");
        }
    } catch (e: any) {
        devlog("[rc4] memscan handleCiphertext error: " + (e && e.message ? e.message : e));
    } finally {
        state.scanning = false;
    }
}

// ---------------------------------------------------------------------------
// SSPI record-layer ciphertext capture (sspicli!EncryptMessage/DecryptMessage).
//   SecBufferDesc { i32 ulVersion; i32 cBuffers; ptr pBuffers } (16 bytes)
//   SecBuffer     { i32 cbBuffer;  i32 BufferType; ptr pvBuffer } (16 bytes)
//   SECBUFFER_DATA = 1.
// ---------------------------------------------------------------------------

const SECBUFFER_DATA = 1;

function parseSecBuffers(pMessage: NativePointer): Array<{ cb: number; type: number; pv: NativePointer }> {
    const out: Array<{ cb: number; type: number; pv: NativePointer }> = [];
    try {
        const cBuffers = pMessage.add(4).readU32();
        const pBuffers = pMessage.add(8).readPointer();
        for (let i = 0; i < cBuffers && i < 16; i++) {
            const sb = pBuffers.add(i * 16);
            out.push({ cb: sb.readU32(), type: sb.add(4).readU32(), pv: sb.add(8).readPointer() });
        }
    } catch (e) { /* */ }
    return out;
}

function grabAppData(pMessage: NativePointer): Uint8Array | null {
    const bufs = parseSecBuffers(pMessage);
    for (let i = 0; i < bufs.length; i++) {
        if (bufs[i].type === SECBUFFER_DATA && bufs[i].cb > 0) {
            const b = readBytes(bufs[i].pv, bufs[i].cb);
            if (b !== null) return b;
        }
    }
    return null;
}

// resolveExport (Frida-version-tolerant export lookup) is shared with rc4_hooks.ts
// and imported above.

function attach(mod: string, fn: string, callbacks: InvocationListenerCallbacks): boolean {
    try {
        const addr = resolveExport(mod, fn);
        if (addr === null) return false;
        Interceptor.attach(addr, callbacks);
        devlog("[rc4] memscan hooked " + mod + "!" + fn);
        return true;
    } catch (e: any) { devlog("[rc4] memscan attach " + mod + "!" + fn + ": " + (e && e.message ? e.message : e)); return false; }
}

function installSspiHooks(): boolean {
    const mods = ["sspicli.dll", "secur32.dll"];
    let hookedEnc = false, hookedDec = false, i: number;
    for (i = 0; i < mods.length && !hookedEnc; i++) {
        hookedEnc = attach(mods[i], "EncryptMessage", {
            onEnter(args: any) {
                // EncryptMessage(phContext, fQOP, pMessage, seqNo) -> app plaintext = RC4 ciphertext
                const b = grabAppData(args[2]);
                if (b !== null && b.length > 0) {
                    handleCiphertext(b, "out").catch(function (e: any) { devlog("[rc4] memscan: " + (e && e.message ? e.message : e)); });
                }
            },
        });
    }
    for (i = 0; i < mods.length && !hookedDec; i++) {
        hookedDec = attach(mods[i], "DecryptMessage", {
            onEnter(args: any) { (this as any).pMessage = args[1]; },   // DecryptMessage(phContext, pMessage, seqNo, pfQOP)
            onLeave() {
                const b = grabAppData((this as any).pMessage);
                if (b !== null && b.length > 0) {
                    handleCiphertext(b, "in").catch(function (e: any) { devlog("[rc4] memscan: " + (e && e.message ? e.message : e)); });
                }
            },
        });
    }
    return hookedEnc || hookedDec;
}

function ensureSspiHooks(): boolean {
    if (state.sspiHooked) return true;
    state.sspiHooked = installSspiHooks();
    return state.sspiHooked;
}

/** Install the SSPI hooks, and keep trying until sspicli/secur32 is actually mapped:
 *  the TLS stack often maps those DLLs only on first SSL use, after the agent loads. */
function armSspiHooks(): void {
    if (ensureSspiHooks()) return;
    try {
        if (typeof P.attachModuleObserver === "function") {
            P.attachModuleObserver({
                onAdded: function (m: any) { try { if (/sspicli|secur32/i.test((m.name || "") + " " + (m.path || ""))) ensureSspiHooks(); } catch (e) { /* */ } },
            });
        }
    } catch (e) { /* */ }
    let tries = 0;
    try {
        const iv = setInterval(function () { tries++; if (ensureSspiHooks() || tries > 120) { try { clearInterval(iv); } catch (e) { /* */ } } }, 250);
    } catch (e) { /* */ }
}

// ---------------------------------------------------------------------------
// Public entry — arm the capture + scanner once (Windows, under -k). Idempotent.
// ---------------------------------------------------------------------------

/**
 * Arm in-process RC4 recovery: install the fault handler, then arm the SSPI record-layer
 * ciphertext capture (which drives the memory scan + trial-decrypt + key emit on the first
 * captured frame). Safe to call repeatedly; only the first call does work. Called from the
 * Windows RC4 executors (which already gate on keylog_enabled), so it runs only under -k.
 */
export function ensureRc4WindowsMemscanArmed(): void {
    if (state.armed) return;
    state.armed = true;
    // Opt the Windows/SSPI path into the improved-recovery suite (code defaults stay OFF,
    // so this arming call is the single place that turns it on — mirrors how the Android
    // patterns.json profile enables the same params on the ms_agent copy):
    //   detectSboxes + sboxExactValidate → exact, zero-false-accept acceptance whenever a
    //     clean post-KSA S-box is resident, and early-stop on it;
    //   groupedRead + prioritizeAnonymous → grouped anonymous-first reads so that
    //     early-stop skips the tail READS (the frida read-IPC cost), not just CPU.
    // The existing scored trial-decrypt (real SSPI ciphertext) is preserved as the
    // fallback; the exact path is routed ahead of it. Trade-off: detectSboxes adds two
    // O(n) detection sweeps, so the common (no clean box) case is a bit slower in
    // exchange for exact validation + S-box keystream emission.
    configureRc4Memscan({
        detectSboxes: true,
        sboxExactValidate: true,
        prioritizeAnonymous: true,
        requireExactOrAccept: true,
        groupedRead: true,
    });
    installExceptionHandler();
    armSspiHooks();
    devlog("[rc4] memscan armed (SSPI ciphertext capture + memory trial-decrypt, improved suite); recovers managed-RC4 keys");
}
