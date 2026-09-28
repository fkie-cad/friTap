import { state } from "../../state.js";
import { registerEngine } from "../../registry.js";
import { MemscanEngine } from "../../types.js";
import { log } from "../../core/log.js";
import { hexBytes, readBytes } from "../../core/memory.js";

/* Shared, reused scratch — allocating fresh 256-byte arrays per trial exhausts
 * the QuickJS heap (no GC inside one synchronous scan) and crashes the runtime. */
var _rc4S = new Uint8Array(256);
var _rc4Out = new Uint8Array(256);
var _rc4Pos = new Int32Array(256);
var _rc4U16 = new Uint8Array(8192);

function rc4Opts() {
    var pr = (state.profile && state.profile.params) || {};
    function num(v, d) { return (typeof v === 'number' && isFinite(v)) ? v : d; }
    var ctHex = pr.ciphertext_sample;
    var ct = (typeof ctHex === 'string' && ctHex) ? rc4HexToBytes(ctHex) : null;
    return {
        minKeyLen: num(pr.min_key_len, 5),
        maxKeyLen: num(pr.max_key_len, 64),
        trialPrefix: num(pr.trial_prefix, 64),
        acceptPrintableFraction: num(pr.accept_printable_fraction, 0.85),
        maxRangeBytes: num(pr.max_range_bytes, 64 * 1024 * 1024),
        maxTotalBytes: num(pr.max_total_bytes, 300 * 1024 * 1024),
        maxTrials: num(pr.max_trials, 1000000),
        maxWindowTrials: num(pr.max_window_trials, 300000),
        maxWindowsPerRun: num(pr.max_windows_per_run, 20000),
        maxWindowRunLen: num(pr.max_window_run_len, 256),
        maxSboxes: num(pr.max_sboxes, 64),
        maxSeen: num(pr.max_seen, 1000000),
        detectSboxes: pr.detect_sboxes !== false,
        recoverKeys: pr.recover_keys !== false,
        ciphertextSample: ct,
        // Improved-recovery params. Code fallback = today's behavior (all off); the
        // shipped profile turns them on. See friTap/memory_scanning/patterns.json.
        knownPlaintext: (typeof pr.known_plaintext === 'string' && pr.known_plaintext) ? rc4HexToBytes(pr.known_plaintext) : null,
        sboxFirst: pr.sbox_first === true,
        sboxExactValidate: pr.sbox_exact_validate === true,
        prioritizeAnonymous: pr.prioritize_anonymous === true,
        requireExactOrAccept: pr.require_exact_or_accept === true,
        // Grouped-burst read (code fallback = today's single whole-budget burst). When on,
        // ranges are read in large groups with an early-stop check between groups so exact
        // evidence in an early (anonymous-first) group skips the tail READS, not just CPU.
        groupedRead: pr.grouped_read === true,
        readGroupBytes: num(pr.read_group_bytes, 64 * 1024 * 1024)
    };
}

function rc4HexToBytes(h) {
    h = String(h).replace(/[^0-9a-fA-F]/g, '');
    var out = new Uint8Array(h.length >> 1);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
}

/* RC4 core (allocating; used only for the one-off KAT). */
function rc4Ksa(key) {
    var S = new Uint8Array(256), i, j = 0, t;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 0xff; t = S[i]; S[i] = S[j]; S[j] = t; }
    return S;
}
function rc4Prga(S, data) {
    var s = S.slice(), out = new Uint8Array(data.length), i = 0, j = 0, n, t;
    for (n = 0; n < data.length; n++) {
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff; t = s[i]; s[i] = s[j]; s[j] = t;
        out[n] = data[n] ^ s[(s[i] + s[j]) & 0xff];
    }
    return out;
}
function rc4(key, data) { return rc4Prga(rc4Ksa(key), data); }

/* KSA from a key window src[off..off+len] into the shared _rc4S (no allocation). */
function ksaInto(src, off, len) {
    var S = _rc4S, i, j = 0, t;
    for (i = 0; i < 256; i++) S[i] = i;
    for (i = 0; i < 256; i++) { j = (j + S[i] + src[off + (i % len)]) & 0xff; t = S[i]; S[i] = S[j]; S[j] = t; }
}
/* PRGA of _rc4S over the first n bytes of data, into shared _rc4Out. */
function prgaInto(data, n) {
    var s = _rc4S, i = 0, j = 0, m, t;
    for (m = 0; m < n; m++) {
        i = (i + 1) & 0xff; j = (j + s[i]) & 0xff; t = s[i]; s[i] = s[j]; s[j] = t;
        _rc4Out[m] = data[m] ^ s[(s[i] + s[j]) & 0xff];
    }
}
/* Allocation-free plaintext score over _rc4Out[0..n]: printable fraction plus a
 * cheap "GET "/"HTTP" token bonus (byte comparison, no string built). */
function scoreTrial(n) {
    var o = _rc4Out, printable = 0, m, c;
    for (m = 0; m < n; m++) { c = o[m]; if (c === 9 || c === 10 || c === 13 || (c >= 0x20 && c <= 0x7e)) printable++; }
    var frac = n ? printable / n : 0, bonus = 0;
    for (m = 0; m + 3 < n; m++) { if (o[m] === 0x47 && o[m + 1] === 0x45 && o[m + 2] === 0x54 && o[m + 3] === 0x20) { bonus += 0.15; break; } }
    for (m = 0; m + 3 < n; m++) { if (o[m] === 0x48 && o[m + 1] === 0x54 && o[m + 2] === 0x54 && o[m + 3] === 0x50) { bonus += 0.15; break; } }
    return { printableFraction: frac, score: frac + bonus };
}

/* KAT: run once, cache the result. A failing core must never emit. */
function rc4SelfCheck(errors) {
    if (state.rc4KatOk !== null) return state.rc4KatOk;
    var kat = (state.profile && state.profile.kat) || {};
    try {
        var got = hexBytes(rc4(rc4HexToBytes(kat.key), rc4HexToBytes(kat.plaintext)));
        var want = String(kat.ciphertext || '').toLowerCase();
        state.rc4KatOk = (got === want && want.length > 0);
        if (state.rc4KatOk) log('info', 'rc4 KAT ok (' + got + ')');
        else errors.push('rc4 KAT failed: ' + got + ' != ' + want);
    } catch (e: any) {
        state.rc4KatOk = false;
        errors.push('rc4 KAT error: ' + e.message);
    }
    return state.rc4KatOk;
}

function isPrintable(c) { return c >= 0x20 && c <= 0x7e; }

/* O(n) rolling distinct-value window: a run of 256 distinct bytes IS a byte-form
 * S-box (only 256 byte values exist). */
function scanByteSboxes(u8, base, opts) {
    var pos = _rc4Pos; pos.fill(-1);
    var start = 0;
    for (var r = 0; r < u8.length; r++) {
        var v = u8[r];
        if (pos[v] >= start) start = pos[v] + 1;
        pos[v] = r;
        if (r - start + 1 === 256) recordSbox(base.add(start).toString(), 'byte', u8, start, opts);
    }
}
/* Same over LE dwords each <=255 (high 3 bytes zero); 256 distinct = int[256] S-box. */
function scanIntSboxes(u8, base, opts) {
    var pos = _rc4Pos; pos.fill(-1);
    var start = 0, ndw = u8.length >> 2;
    for (var r = 0; r < ndw; r++) {
        var p = r * 4;
        if (u8[p + 1] !== 0 || u8[p + 2] !== 0 || u8[p + 3] !== 0) { start = r + 1; continue; }
        var v = u8[p];
        if (pos[v] >= start) start = pos[v] + 1;
        pos[v] = r;
        if (r - start + 1 === 256) recordSbox(base.add(start * 4).toString(), 'int', u8, start * 4, opts);
    }
}
function recordSbox(addrStr, form, u8, off, opts) {
    if (state.rc4Sboxes.length >= opts.maxSboxes) return;
    var S = new Uint8Array(256), k;
    if (form === 'byte') { for (k = 0; k < 256; k++) S[k] = u8[off + k]; }
    else { for (k = 0; k < 256; k++) S[k] = u8[off + k * 4]; }
    // Skip the identity permutation (S[k]==k): a freshly-initialised, pre-KSA box,
    // useless as keystream and a false-positive magnet (e.g. a jump table).
    var identity = true;
    for (k = 0; k < 256; k++) if (S[k] !== k) { identity = false; break; }
    state.rc4Sboxes.push({ addr: addrStr, form: form, S: S, identity: identity });
}

/* Build the exact-validation set from the live (non-identity) S-boxes found this
 * scan. b0/bN are cheap first/last-byte prechecks so the 256-byte compare runs only
 * on a precheck hit (astronomically rare for a wrong key). n is typically 0-2. */
function buildLiveSboxes() {
    var boxes: Uint8Array[] = [], b0: number[] = [], bN: number[] = [];
    for (var s = 0; s < state.rc4Sboxes.length; s++) {
        var sb = state.rc4Sboxes[s];
        if (sb.identity) continue;
        boxes.push(sb.S); b0.push(sb.S[0]); bN.push(sb.S[255]);
    }
    return { boxes: boxes, b0: b0, bN: bN, n: boxes.length };
}
/* Exact test: does KSA(candidate), sitting in _rc4S, reproduce a found S-box?
 * This is plaintext-free and zero-false-accept. Returns the S-box index or -1. */
function ksaMatchesSbox(live) {
    var S = _rc4S;
    for (var k = 0; k < live.n; k++) {
        if (S[0] !== live.b0[k] || S[255] !== live.bN[k]) continue;
        var box = live.boxes[k], ok = true;
        for (var m = 0; m < 256; m++) { if (S[m] !== box[m]) { ok = false; break; } }
        if (ok) return k;
    }
    return -1;
}

/* Trial the candidate key at src[off..off+len] against ctx.prefix, keeping the
 * single best in ctx.best. Allocation-free (reuses _rc4S/_rc4Out); FNV-1a dedup
 * so a managed heap's repeated strings are KSA'd at most once. */
function trialKey(ctx, src, off, len, source, isWindow) {
    ctx.candidates++;
    if (ctx.stop) return;
    // Exact S-box validation needs no ciphertext; the scored path needs a prefix.
    // With neither available there is nothing to test, so skip (old behavior).
    var canSbox = ctx.opts.sboxExactValidate && ctx.live !== null && ctx.live.n > 0;
    if (ctx.prefix === null && !canSbox) return;
    if (isWindow) { if (ctx.windowTrials >= ctx.opts.maxWindowTrials) return; }
    else if (ctx.trials >= ctx.opts.maxTrials) return;
    // Collision-safe 64-bit dedup: two independent FNV-1a lanes in one byte loop.
    // On an h1 collision with a DIFFERENT h2 we PROCEED (never silently skip a
    // distinct candidate) — the old single 32-bit lane could wrongly drop a key.
    var h1 = (2166136261 ^ len) >>> 0;
    var h2 = ((2166136261 ^ 0x9e3779b9) ^ len) >>> 0;
    for (var q = 0; q < len; q++) {
        var b = src[off + q];
        h1 = (h1 ^ b) >>> 0; h1 = Math.imul(h1, 16777619) >>> 0;
        h2 = (h2 ^ b) >>> 0; h2 = Math.imul(h2, 16777619) >>> 0;
    }
    var prev = ctx.seen[h1];
    if (prev === h2) return;
    if (prev === undefined && ctx.seenCount < ctx.opts.maxSeen) { ctx.seen[h1] = h2; ctx.seenCount++; }
    if (isWindow) ctx.windowTrials++; else ctx.trials++;
    ksaInto(src, off, len);
    // (1) Exact acceptance: KSA(candidate) reproduces a live S-box. Zero false
    //     accepts, no plaintext needed -> accept + early-stop.
    if (canSbox) {
        var mi = ksaMatchesSbox(ctx.live);
        if (mi >= 0) {
            var kx = new Uint8Array(len);
            for (var a = 0; a < len; a++) kx[a] = src[off + a];
            ctx.exact = { source: source, key: kx, keyHex: hexBytes(kx), sboxIdx: mi };
            ctx.stop = true;
            return;
        }
    }
    if (ctx.prefix === null) return;
    prgaInto(ctx.prefix, ctx.prefixLen);
    // (2) Exact acceptance via known-plaintext: the keystream reproduces the known
    //     prefix exactly -> accept + early-stop.
    var kp = ctx.opts.knownPlaintext;
    if (kp !== null && kp.length <= ctx.prefixLen) {
        var match = true;
        for (var c = 0; c < kp.length; c++) { if (_rc4Out[c] !== kp[c]) { match = false; break; } }
        if (match) {
            var ky = new Uint8Array(len);
            for (var a2 = 0; a2 < len; a2++) ky[a2] = src[off + a2];
            ctx.exact = { source: source, key: ky, keyHex: hexBytes(ky), sboxIdx: -1 };
            ctx.stop = true;
            return;
        }
    }
    // (3) Ranking only (fuzzy): keep the single best-scoring candidate.
    var sc = scoreTrial(ctx.prefixLen);
    if (ctx.best === null || sc.score > ctx.best.score) {
        var key = new Uint8Array(len);
        for (var i = 0; i < len; i++) key[i] = src[off + i];
        ctx.best = { source: source, key: key, keyHex: hexBytes(key), score: sc.score,
                     printableFraction: sc.printableFraction };
    }
}

/* Feed one printable run to the trial: whole run when <= maxKeyLen (the isolated
 * key case), else bounded sliding windows for a key embedded in a longer blob. */
function runToTrials(ctx, u8, runStart, runEnd, source) {
    if (ctx.stop) return;
    var minL = ctx.opts.minKeyLen, maxL = ctx.opts.maxKeyLen, runLen = runEnd - runStart;
    if (runLen < minL) return;
    if (runLen <= maxL) { trialKey(ctx, u8, runStart, runLen, source, false); return; }
    if (runLen > ctx.opts.maxWindowRunLen) return;   // giant blob: skip (budget guard)
    var perRun = 0, cap = ctx.opts.maxWindowsPerRun;
    for (var i = runStart; i < runEnd && perRun < cap && !ctx.stop && ctx.windowTrials < ctx.opts.maxWindowTrials; i++) {
        var maxHere = Math.min(maxL, runEnd - i);
        for (var L = minL; L <= maxHere && perRun < cap && !ctx.stop; L++) { trialKey(ctx, u8, i, L, source, true); perRun++; }
    }
}

/* Detect S-boxes within one already-read chunk. sboxFirst forces detection even
 * when detect_sboxes is off, since exact validation depends on it. */
function rc4DetectSboxesChunk(u8, base, opts) {
    if (!(opts.detectSboxes || opts.sboxFirst)) return;
    if (state.rc4Sboxes.length < opts.maxSboxes) scanByteSboxes(u8, base, opts);
    if (state.rc4Sboxes.length < opts.maxSboxes) scanIntSboxes(u8, base, opts);
}
/* Stream-trial candidate keys within one already-read chunk (no S-box detection). */
function rc4RecoverChunk(ctx, u8, base) {
    if (!ctx.opts.recoverKeys || ctx.stop) return;
    // ASCII runs (trialled in place by offset — no per-run allocation).
    var off, runStart = -1;
    for (off = 0; off <= u8.length; off++) {
        var printable = off < u8.length && isPrintable(u8[off]);
        if (printable) { if (runStart < 0) runStart = off; }
        else { if (runStart >= 0) { runToTrials(ctx, u8, runStart, off, 'ascii'); runStart = -1; if (ctx.stop) return; } }
    }
    // UTF-16LE runs (printable even bytes, zero odd bytes) -> decode into scratch.
    var u16Start = -1;
    for (off = 0; off + 1 < u8.length; off += 2) {
        if (ctx.stop) return;
        var ok = isPrintable(u8[off]) && u8[off + 1] === 0;
        if (ok) { if (u16Start < 0) u16Start = off; }
        else if (u16Start >= 0) {
            var n = (off - u16Start) >> 1; if (n > _rc4U16.length) n = _rc4U16.length;
            if (n >= ctx.opts.minKeyLen) {
                for (var d = 0; d < n; d++) _rc4U16[d] = u8[u16Start + d * 2];
                runToTrials(ctx, _rc4U16, 0, n, 'utf16');
            }
            u16Start = -1;
        }
    }
}
/* Single interleaved pass (the default): detect + recover per chunk. The live
 * S-box set is refreshed after detection so a candidate is exact-validated against
 * every S-box found so far — one read, free-as-you-go, bounded memory. (A clean
 * post-KSA box in a LATER chunk is missed here; the opt-in sbox_first two-pass
 * closes that gap at the cost of a second read.) */
function rc4ScanChunk(ctx, u8, base) {
    rc4DetectSboxesChunk(u8, base, ctx.opts);
    if (ctx.opts.sboxExactValidate && state.rc4Sboxes.length !== ctx.liveCount) {
        ctx.live = buildLiveSboxes();
        ctx.liveCount = state.rc4Sboxes.length;
    }
    rc4RecoverChunk(ctx, u8, base);
}

/* PHASE 1 — burst-read the selected ranges into JS buffers as fast as possible
 * (EDR-safe: sustained injected reading gets a process terminated; one fast burst
 * survives). Smallest-first so a heap larger than the budget still covers all the
 * small/medium ranges where a key is likeliest, not one giant mapping. */
/* Read ONE range into a buffer, honoring the per-range cap and the remaining total
 * budget. Returns {base, u8, anonymous, size} or null (unreadable / no budget left).
 * Shared by the single-burst (rc4ReadAllFast) and grouped-burst read paths so the
 * cap/budget accounting is single-sourced. anonymous (file == null) heap ranges are
 * where a key/S-box is likeliest; the flag lets the caller visit them first. */
function rc4ReadOneRange(range, totalSoFar, opts) {
    var perCap = opts.maxRangeBytes, budget = opts.maxTotalBytes;
    if (totalSoFar >= budget) return null;
    var sz = range.size;
    if (sz > perCap) sz = perCap;
    if (totalSoFar + sz > budget) sz = budget - totalSoFar;
    var u8 = readBytes(range.base, sz);
    if (u8 === null) return null;
    return { base: range.base, u8: u8, anonymous: (range.file == null), size: sz };
}

/* Smallest-first order: a heap larger than the budget still covers the small/medium
 * ranges where a key is likeliest, not one giant mapping. Reused for the plain sort and
 * as the tie-break of the anonymous-first order. */
function rc4BySize(a, b) { return a.size - b.size; }

function rc4ReadAllFast(ranges, opts) {
    var sorted = ranges.slice().sort(rc4BySize);
    var buffers = [], total = 0;
    for (var i = 0; i < sorted.length; i++) {
        if (total >= opts.maxTotalBytes) break;
        var r = rc4ReadOneRange(sorted[i], total, opts);
        if (r !== null) { buffers.push(r); total += r.size; }
    }
    return { buffers: buffers, total: total };
}

/* Order ranges for the grouped-burst path: anonymous/managed-heap first when
 * prioritize_anonymous is set (so the key lands in the first group and early-stop skips
 * the tail READS), else smallest-first (budget coverage, matching rc4ReadAllFast).
 * Within each class, smallest-first for coverage. */
function rc4OrderRanges(ranges, opts) {
    var ordered = ranges.slice();
    if (opts.prioritizeAnonymous) {
        ordered.sort(function (a, b) { var aa = (a.file == null), bb = (b.file == null); return (aa === bb) ? rc4BySize(a, b) : (aa ? -1 : 1); });
    } else {
        ordered.sort(rc4BySize);
    }
    return ordered;
}

/* Streaming per-range read+process: read ONE range, process it, free it, respect
 * the budget, and honor early-stop. Bounds memory to one range at a time and — for
 * the recover phase — lets early-stop skip reading the rest of the heap once the key
 * is found. `phase` is 'detect' (find S-boxes) or 'recover' (trial keys). */
function rc4StreamScan(ranges, opts, ctx, phase, errors) {
    var ordered = ranges.slice();
    if (phase === 'recover' && opts.prioritizeAnonymous) {
        // Anonymous/managed-heap first so early-stop fires sooner.
        ordered.sort(function (a, b) { var aa = (a.file == null), bb = (b.file == null); return (aa === bb) ? 0 : (aa ? -1 : 1); });
    } else {
        ordered.sort(rc4BySize);   // smallest-first (budget coverage)
    }
    var total = 0, budget = opts.maxTotalBytes;
    for (var i = 0; i < ordered.length; i++) {
        if (ctx.stop) break;
        if (total >= budget) break;
        // rc4ReadOneRange single-sources the per-range cap + remaining-budget clamp; the
        // budget-exhausted case is already handled by the break above, so a null here means
        // an unreadable range → skip it.
        var r = rc4ReadOneRange(ordered[i], total, opts);
        if (r === null) continue;
        total += r.size;
        try {
            if (phase === 'detect') rc4DetectSboxesChunk(r.u8, r.base, opts);
            else rc4RecoverChunk(ctx, r.u8, r.base);
        } catch (e: any) { errors.push('rc4 ' + phase + ' ' + r.base + ': ' + e.message); }
        r.u8 = null;   // free immediately — one range's worth of memory at a time
    }
    return total;
}

/* Emit one recovered RC4 key/state. `source` distinguishes a KSA key
 * ('memscan-trial', key bytes) from a post-KSA S-box state ('memscan-sbox', the
 * 256-byte permutation) so the offline RC4 decryptor treats each correctly. */
function emitRc4Key(keyHex, keyLen, source, stats) {
    var key = source + '|' + keyHex;
    if (state.rc4Emitted[key] !== undefined) return;
    state.rc4Emitted[key] = 1;
    send({ type: 'rc4_key', key: keyHex, key_len: keyLen, source: source,
           direction: 'unknown', assoc: '-' });
    stats.emitted++;
}

export const Rc4Engine: MemscanEngine = {
    name: 'rc4',
    runTiers: function (ranges: any, stats: any, errors: string[]): void {
    if (!rc4SelfCheck(errors)) return;   // a failing RC4 core must never emit
    var t0 = Date.now();
    var opts = rc4Opts();
    state.rc4Sboxes = [];
    var ct = opts.ciphertextSample;
    var prefix = ct ? ct.subarray(0, Math.min(opts.trialPrefix, ct.length)) : null;
    var ctx: any = {
        opts: opts, prefix: prefix, prefixLen: prefix ? prefix.length : 0,
        best: null, trials: 0, windowTrials: 0, candidates: 0,
        seen: {}, seenCount: 0, live: null, liveCount: 0, exact: null, stop: false
    };
    var readTotal = 0, readDoneMs;

    if (opts.sboxFirst) {
        // PHASE 2a: detect S-boxes across the heap first (streaming read+detect+free),
        // so a live S-box found anywhere can exactly-validate a candidate in any range.
        readTotal += rc4StreamScan(ranges, opts, ctx, 'detect', errors);
        ctx.live = buildLiveSboxes();
        readDoneMs = Date.now();
        // PHASE 2b: recover (streaming, anonymous-first). Early-stop on exact evidence
        // avoids reading the rest of the heap once the key is found.
        readTotal += rc4StreamScan(ranges, opts, ctx, 'recover', errors);
    } else if (opts.groupedRead) {
        // Grouped-burst read: order anonymous-first, read a large GROUP of ranges as one
        // tight burst (EDR-safe — still burst + CPU, just a few bursts instead of one),
        // interleaved detect+recover + free per buffer, then check early-stop before
        // reading the next group. So exact evidence in an early group skips the tail
        // READS (the frida read-IPC bottleneck), not just the CPU. grouped_read:false
        // (code default) restores the single whole-budget burst above, byte-identical.
        var orderedG = rc4OrderRanges(ranges, opts);
        var total = 0, gi = 0, budget = opts.maxTotalBytes, groupCap = opts.readGroupBytes;
        while (gi < orderedG.length && total < budget && !ctx.stop) {
            var group = [], gBytes = 0;
            while (gi < orderedG.length && total < budget && gBytes < groupCap) {
                var rr = rc4ReadOneRange(orderedG[gi], total, opts);
                gi++;
                if (rr !== null) { group.push(rr); total += rr.size; gBytes += rr.size; }
            }
            if (readDoneMs === undefined) readDoneMs = Date.now();   // time-to-first-burst
            for (var gj = 0; gj < group.length; gj++) {
                try { rc4ScanChunk(ctx, group[gj].u8, group[gj].base); }
                catch (e: any) { errors.push('rc4 chunk ' + group[gj].base + ': ' + e.message); }
                group[gj].u8 = null;                          // free as we go
                if (ctx.stop) break;
            }
        }
        if (readDoneMs === undefined) readDoneMs = Date.now();
        readTotal = total;
    } else {
        // Legacy single burst read then interleaved detect+recover, freeing as we go.
        var read = rc4ReadAllFast(ranges, opts);              // PHASE 1: burst read
        readDoneMs = Date.now();
        readTotal = read.total;
        for (var i = 0; i < read.buffers.length; i++) {
            try { rc4ScanChunk(ctx, read.buffers[i].u8, read.buffers[i].base); }
            catch (e: any) { errors.push('rc4 chunk ' + read.buffers[i].base + ': ' + e.message); }
            read.buffers[i].u8 = null;                        // free as we go
        }
    }

    // S-box recovery: each non-identity S-box is post-KSA keystream state.
    var live = 0;
    for (var s = 0; s < state.rc4Sboxes.length; s++) {
        if (state.rc4Sboxes[s].identity) continue;
        live++;
        emitRc4Key(hexBytes(state.rc4Sboxes[s].S), 256, 'memscan-sbox', stats);
    }
    // Key recovery. Exact evidence (S-box KSA match or known-plaintext) wins and is
    // emitted as the high-confidence 'memscan-trial-exact'. Otherwise the best-scoring
    // key is emitted only when it clears the accept threshold (requireExactOrAccept);
    // when that gate is off (code default) the old always-emit-best behavior stands.
    if (ctx.exact) {
        emitRc4Key(ctx.exact.keyHex, ctx.exact.key.length, 'memscan-trial-exact', stats);
    } else if (ctx.best) {
        if (!opts.requireExactOrAccept || ctx.best.score >= opts.acceptPrintableFraction) {
            emitRc4Key(ctx.best.keyHex, ctx.best.key.length, 'memscan-trial', stats);
        }
    }
    stats.rc4 = {
        sboxes: state.rc4Sboxes.length, liveSboxes: live,
        candidateKeys: ctx.candidates, readBytes: readTotal,
        ksaExecutions: ctx.trials + ctx.windowTrials,        // distinct KSA runs executed
        scanMs: Date.now() - t0, burstReadMs: readDoneMs - t0,
        recovered: !!(ctx.exact || ctx.best),
        bestScore: ctx.exact ? 1 : (ctx.best ? ctx.best.score : 0)
    };
    }
};
registerEngine(Rc4Engine);
