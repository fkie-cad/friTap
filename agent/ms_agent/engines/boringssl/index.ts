import { state } from "../../state.js";
import { registerEngine } from "../../registry.js";
import { MemscanEngine } from "../../types.js";

import { log } from "../../core/log.js";
import { hexBytes, hex, readHex, readBytes, readPointerOrNull, readU8OrNull, readU16OrNull, scanRange, pointerToScanPattern } from "../../core/memory.js";
import { untag, looksLikeHeapPointer } from "../../core/pointers.js";
import { isValidHashLen, looksLikeSecret, looksLikeRandom } from "../../core/heuristics.js";

function emitKeylog(label, clientRandom, secret, tier, ssl, source, stats) {
    var key = label + '|' + clientRandom;
    var previous = state.recorded[key];
    if (previous === secret) return false;              // already emitted, stay quiet
    if (previous !== undefined) {
        log('warn', 'conflict for ' + label + ' ' + clientRandom.substring(0, 16) +
                    '... (KeyUpdate rotation?) — not emitting from ' + source);
        return false;
    }
    state.recorded[key] = secret;
    send({
        type: 'keylog',
        line: label + ' ' + clientRandom + ' ' + secret,
        tier: tier, ssl: ssl.toString(), source: source
    });
    stats.emitted++;
    return true;
}

function emitUnpaired(base, secret, sessionId, sslVersion, stats) {
    send({
        type: 'unpaired', kind: 'orphan_session',
        secret: secret, session_id: sessionId,
        ssl_version: sslVersion, addr: base.toString()
    });
    stats.emitted++;
}

function readSlotLengths(hs) {
    var slots = state.profile.tiers.A_ssl_handshake.slots;
    var lengths = new Array(slots.length);
    var common = 0;
    var hasLabelled = false;
    for (var i = 0; i < slots.length; i++) {
        var len = readU8OrNull(hs.add(slots[i].len));
        if (len === null) return null;
        lengths[i] = len;
        if (len === 0) continue;
        if (!isValidHashLen(len)) return null;
        if (common === 0) common = len;
        else if (len !== common) return null;
        if (slots[i].label !== null) hasLabelled = true;
    }
    return hasLabelled ? lengths : null;
}

/* The two-way close: s3->hs must point back at the SSL_HANDSHAKE we started from.
 * Two independent pointers agreeing is what makes a byte-pattern hit a fact. */
function closesRoundTrip(hs, s3) {
    var back = readPointerOrNull(s3.add(state.profile.struct_offsets.SSL3_STATE.hs));
    return back !== null && !back.isNull() && untag(back).equals(untag(hs));
}

/* Walks hs -> ssl -> s3 -> hs. Returns {ssl, s3} only when the loop closes. */
function resolveHandshakeContext(hs) {
    var off = state.profile.struct_offsets;
    var ssl = readPointerOrNull(hs.add(off.SSL_HANDSHAKE.ssl));
    if (!looksLikeHeapPointer(ssl)) return null;
    var s3 = readPointerOrNull(ssl.add(off.SSL.s3));
    if (!looksLikeHeapPointer(s3)) return null;
    if (!closesRoundTrip(hs, s3)) return null;
    return { ssl: ssl, s3: s3 };
}

function readClientRandom(s3) {
    var c = state.profile.constants;
    var bytes = readBytes(s3.add(state.profile.struct_offsets.SSL3_STATE.client_random),
                          c.ssl3_random_size);
    return looksLikeRandom(bytes) ? hexBytes(bytes) : null;
}

/* Emits one keylog line per populated, labelled slot. Slot indices are absolute
 * because offsetof(SSL_HANDSHAKE, secret) is a compile-time constant, which is
 * exactly what lets every secret be labelled with certainty (JSON step 4).
 * `lengths` comes from readSlotLengths(), so both callers have already proved the
 * run consistent before a single secret byte is read. */
function emitHandshakeSlots(hs, ssl, clientRandom, tier, lengths, stats) {
    var slots = state.profile.tiers.A_ssl_handshake.slots;
    for (var i = 0; i < slots.length; i++) {
        var slot = slots[i];
        if (slot.label === null) continue;
        var len = lengths[i];
        if (len === 0) continue;
        var bytes = readBytes(hs.add(slot.data), len);
        if (!looksLikeSecret(bytes)) continue;
        emitKeylog(slot.label, clientRandom, hexBytes(bytes), tier, ssl, slot.name, stats);
    }
}

/* ---------------------------------------------------------------------------
 * Tier A — anchor on min_version||max_version inside SSL_HANDSHAKE.
 * Four fixed bytes cost ~0.07 expected random hits over a 300 MB heap, so this is
 * a cheap phase-1 needle and everything that follows is verified in JS.
 * ------------------------------------------------------------------------- */

function rememberNeedle(ssl) {
    var method = readPointerOrNull(ssl.add(state.profile.struct_offsets.SSL.method));
    if (!looksLikeHeapPointer(method)) return;
    if (state.needle !== null && state.needle.value.equals(method)) return;
    var mod = Process.findModuleByAddress(untag(method));
    state.needle = {
        value: method,
        module: mod === null ? null : mod.name,
        rva: mod === null ? null : '0x' + untag(method).sub(mod.base).toString(16)
    };
    log('info', 'Tier B needle derived from Tier A: ' + method +
                (mod === null ? '' : ' (' + state.needle.module + '+' + state.needle.rva + ')'));
}

function processHandshakeCandidate(hs, stats) {
    var lengths = readSlotLengths(hs);
    if (lengths === null) return;
    var ctx = resolveHandshakeContext(hs);
    if (ctx === null) return;
    stats.tierA.validated++;

    rememberNeedle(ctx.ssl);
    var clientRandom = readClientRandom(ctx.s3);
    if (clientRandom === null) return;
    emitHandshakeSlots(hs, ctx.ssl, clientRandom, 'A', lengths, stats);
}

function runTierA(ranges, stats, errors) {
    var tier = state.profile.tiers.A_ssl_handshake;
    if (!tier.enabled) return;
    for (var r = 0; r < ranges.length; r++) {
        for (var a = 0; a < tier.anchors.length; a++) {
            var hits = scanRange(ranges[r], tier.anchors[a].pattern, errors);
            for (var h = 0; h < hits.length; h++) {
                stats.tierA.candidates++;
                var hs = hits[h].address.sub(tier.anchor_offset_in_struct);
                try { processHandshakeCandidate(hs, stats); }
                catch (e: any) { errors.push('tierA ' + hs + ': ' + e.message); }
            }
        }
    }
}

/* ---------------------------------------------------------------------------
 * Tier A throttling — WHETHER Tier A runs on a given scan. What it does when it
 * runs is untouched.
 *
 * Measured on Chrome 133 (the same numbers are recorded in the profile under
 * tiers.A_ssl_handshake._rescan_every_doc): across 45 consecutive scans Tier A
 * produced 1736 candidates and validated NONE, while costing two of the three
 * Memory.scanSync passes a scan makes — ~430 ms each per ~55 MiB, i.e. two thirds
 * of a ~1.3 s scan. It is nearly redundant because Tier B enumerates every live
 * SSL and follows s3->hs into the very same handshakes, through the very same
 * slot-extraction code.
 *
 * Nearly, not entirely: deriving the Tier B needle from a real object is Tier A's
 * one irreplaceable job, and it is what makes a stale needle.rva in the profile
 * survivable. So this throttles, it never disables.
 *
 * The payoff is recall, not CPU. A handshake is live for milliseconds and we
 * sample, so scans per minute is the only lever that moves handshake-epoch
 * secrets — and dropping three passes to one roughly triples that rate.
 * ------------------------------------------------------------------------- */

/* Missing, non-numeric or < 1 all mean "every scan", i.e. exactly the behaviour
 * before this existed. A bad profile value must never be able to switch a tier
 * off; the worst it can do is make the scanner slower than intended. */
function tierARescanEvery() {
    var configured = state.profile.tiers.A_ssl_handshake.rescan_every;
    if (typeof configured !== 'number' || !isFinite(configured) || configured < 1) return 1;
    return Math.floor(configured);
}

function shouldRunTierA() {
    // 1. Tier B cannot run at all without a needle, and Tier A is the only thing
    //    that can derive one from a live object. Note this asks whether a needle
    //    is AVAILABLE, not whether Tier A produced it: the profile also ships a
    //    build-specific RVA hint, and when that hint is right Tier B works from
    //    scan 1 without Tier A ever validating anything. Keying this on
    //    state.needle instead made the throttle dead code on the real target,
    //    because in the steady state Tier A validates nothing (measured: 1736
    //    candidates, 0 validated, across 45 scans) - so state.needle stayed null
    //    forever and rule 1 fired on every scan. Rule 3 is what catches a hint
    //    that is present but WRONG.
    if (resolveNeedleValue() === null) return true;
    // 2. The periodic re-check. state.scanIndex is 0 on the first scan, so with
    //    any rescan_every the very first scan runs.
    if (state.scanIndex % tierARescanEvery() === 0) return true;
    // 3. Safety valve. If the needle goes stale — the module was reloaded, or it
    //    came from the profile's build-specific RVA hint and was wrong — Tier B
    //    matches nothing and reports it as silence, not as an error. Tier A is the
    //    only thing that can re-derive the needle, so a scan that validated
    //    nothing must be followed by one that runs it. A target with simply no TLS
    //    traffic therefore behaves exactly as it did before: Tier A every scan.
    return state.lastTierBValidated === 0;
}

/* ---------------------------------------------------------------------------
 * Tier B — the workhorse. ssl->method points at one static SSL_PROTOCOL_METHOD
 * shared by every TLS SSL object and lives at offset 0, so a single exact pointer
 * needle enumerates every LIVE SSL in the heap: pointer walking instead of byte
 * pattern archaeology.
 * ------------------------------------------------------------------------- */


/* Prefer the value Tier A derived from a real object this run; the JSON's RVA is
 * build-specific and is only a hint. */
function resolveNeedleValue() {
    if (state.needle !== null) return state.needle.value;
    var hint = state.profile.tiers.B_ssl_method_ptr.needle;
    if (!hint || !hint.module || !hint.rva) return null;
    var mod = Process.findModuleByName(hint.module);
    return mod === null ? null : mod.base.add(ptr(hint.rva));
}

/* Once the handshake is gone these three fields hold the CURRENT epoch's
 * application secrets. While a handshake is still in flight they hold the
 * HANDSHAKE epoch — verified on device — so a *_TRAFFIC_SECRET_0 label would be a
 * lie and the caller uses Tier A's unambiguous slots instead.
 *
 * Each entry names a field in struct_offsets.SSL3_STATE; its length byte is the
 * "<field>_len" key, which the Python driver checks exists before we get here. */
function emitS3TrafficSecrets(ssl, s3, clientRandom, stats) {
    var secrets = state.profile.tiers.B_ssl_method_ptr.s3_secrets;
    var off = state.profile.struct_offsets.SSL3_STATE;
    for (var i = 0; i < secrets.length; i++) {
        var entry = secrets[i];
        var len = readU8OrNull(s3.add(off[entry.field + '_len']));
        if (len === null || len === 0) continue;
        var bytes = readBytes(s3.add(off[entry.field]), len);
        /* looksLikeSecret is where the hash-length check lives, so a stale size_
         * byte cannot produce a correctly-labelled secret of the wrong length. */
        if (!looksLikeSecret(bytes)) continue;
        emitKeylog(entry.label, clientRandom, hexBytes(bytes), 'B', ssl, entry.field, stats);
    }
}

function sessionBaseFor(path, ssl, s3) {
    var off = state.profile.struct_offsets;
    if (path.from === 'SSL3_STATE') return s3.add(off.SSL3_STATE[path.field]);
    if (path.from === 'SSL') return ssl.add(off.SSL[path.field]);
    return null;
}

/* TLS 1.2 only: the master secret pairs with client_random to make an NSS keylog
 * line. The version check is mandatory because a TLS 1.3 SHA-384 resumption PSK
 * is byte-identical in shape. Label, required version and required length all
 * come from tiers.B_ssl_method_ptr.tls12_session — no NSS label and no size is
 * spelled out in this file. */
function emitSessionMasterSecret(ssl, session, clientRandom, source, stats) {
    var cfg = state.profile.tiers.B_ssl_method_ptr.tls12_session;
    var off = state.profile.struct_offsets.SSL_SESSION;
    var version = readU16OrNull(session.add(off.ssl_version));
    if (version !== cfg.require_ssl_version) return;
    var len = readU8OrNull(session.add(off.secret_len));      // ONE byte, never 4 or 8
    if (len !== cfg.require_secret_len) return;
    var bytes = readBytes(session.add(off.secret), len);
    if (!looksLikeSecret(bytes)) return;
    emitKeylog(cfg.label, clientRandom, hexBytes(bytes), 'B', ssl, source, stats);
}

/* `SSL.session` is the session OFFERED for resumption while a handshake is still in
 * flight, i.e. the PREVIOUS handshake's master secret, while s3->client_random
 * already holds the NEW ClientHello random. Pairing those two yields
 * "CLIENT_RANDOM <new_random> <old_master_secret>": a false positive whenever the
 * server declines resumption, and emitKeylog is first-write-wins, so that wrong
 * line then BLOCKS the correct one for the same handshake.
 *
 * Which paths are only sound once the handshake is over is a property of the
 * layout, not of this code, so it is spelled `when_handshake_complete_only` in the
 * profile rather than special-cased on a field name here. SSL3_STATE
 * .established_session does not carry the flag and does not need it - it is set BY
 * completion - so TLS 1.2 coverage of finished handshakes is unaffected. */
function emitSessionSecrets(ssl, s3, clientRandom, handshakeState, stats) {
    var paths = state.profile.tiers.B_ssl_method_ptr.tls12_session.paths;
    for (var i = 0; i < paths.length; i++) {
        if (paths[i].when_handshake_complete_only && handshakeState !== HS_COMPLETE) continue;
        var slot = sessionBaseFor(paths[i], ssl, s3);
        if (slot === null) continue;
        var session = readPointerOrNull(slot);
        if (!looksLikeHeapPointer(session)) continue;
        emitSessionMasterSecret(ssl, session, clientRandom, paths[i].field, stats);
    }
}

/* The state of s3->hs decides which secrets can be labelled at all, and the
 * distinction that matters is NOT "plausible pointer or not". It is three-way,
 * because two different things both look like "not a pointer":
 *
 *   - readPointerOrNull() returns null for a FAULTING read exactly as it would for
 *     a field we simply could not reach; and
 *   - looksLikeHeapPointer() consults buildMappedRangeIndex(), which takes ONE
 *     snapshot per scan while the target keeps allocating for the 1.2-1.8 s the
 *     scan runs, so a genuine hs into a range mapped AFTER that snapshot is not
 *     "plausible" either.
 *
 * Folding either case into "handshake finished" would emit s3->{write,read}
 * _traffic_secret - which at that moment hold the HANDSHAKE-epoch secrets - under a
 * *_TRAFFIC_SECRET_0 label, the exact mislabelling emitS3TrafficSecrets warns
 * about. It is also sticky: emitKeylog is first-write-wins, so the correct secret
 * found on a later scan would then be refused as a conflict and never emitted.
 * Hence a third outcome that emits nothing and is counted instead. */
var HS_COMPLETE = 'complete';            // read succeeded, hs is NULL: handshake is over
var HS_LIVE = 'live';                    // read succeeded, hs is a plausible live SSL_HANDSHAKE
var HS_INDETERMINATE = 'indeterminate';  // read faulted, or hs is non-NULL but outside the snapshot

function classifyHandshake(hs) {
    if (hs === null) return HS_INDETERMINATE;   // the read of s3->hs itself faulted
    if (hs.isNull()) return HS_COMPLETE;
    return looksLikeHeapPointer(hs) ? HS_LIVE : HS_INDETERMINATE;
}

function processSslCandidate(ssl, stats) {
    var off = state.profile.struct_offsets;
    var s3 = readPointerOrNull(ssl.add(off.SSL.s3));
    if (!looksLikeHeapPointer(s3)) return;
    stats.tierB.validated++;

    var clientRandom = readClientRandom(s3);
    if (clientRandom === null) return;

    var hs = readPointerOrNull(s3.add(off.SSL3_STATE.hs));
    var handshakeState = classifyHandshake(hs);
    if (handshakeState === HS_LIVE) {
        // Handshake still in flight: only the labelled SSL_HANDSHAKE slots are
        // unambiguous, and only once hs->ssl->s3->hs closes.
        //
        // readSlotLengths() is an INTENTIONAL tightening of this path: Tier B
        // used to emit these slots without ever checking that the seven length
        // bytes form one consistent run of a valid hash size. A run that fails
        // that check is not a live handshake we can label, so dropping it raises
        // precision; it is also what lets the lengths be read once instead of
        // twice.
        if (closesRoundTrip(hs, s3)) {
            var lengths = readSlotLengths(hs);
            if (lengths !== null) emitHandshakeSlots(hs, ssl, clientRandom, 'B', lengths, stats);
        }
    } else if (handshakeState === HS_COMPLETE) {
        emitS3TrafficSecrets(ssl, s3, clientRandom, stats);
    } else {
        // Neither set can be labelled with certainty, so emit NEITHER. Counted so
        // that a run which hits this often is visible rather than silently lossy.
        stats.indeterminateHs++;
    }
    emitSessionSecrets(ssl, s3, clientRandom, handshakeState, stats);
}

function runTierB(ranges, stats, errors) {
    var tier = state.profile.tiers.B_ssl_method_ptr;
    if (!tier.enabled) return;
    var needle = resolveNeedleValue();
    if (needle === null) {
        log('warn', 'Tier B skipped: no needle derived by Tier A and the profile hint ' +
                    'did not resolve in this process');
        return;
    }
    var pattern = pointerToScanPattern(needle);
    for (var r = 0; r < ranges.length; r++) {
        var hits = scanRange(ranges[r], pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            stats.tierB.candidates++;
            // method sits at offset 0, so the hit address IS the SSL object.
            try { processSslCandidate(hits[h].address, stats); }
            catch (e: any) { errors.push('tierB ' + hits[h].address + ': ' + e.message); }
        }
    }
}

/* ---------------------------------------------------------------------------
 * Tier C — last resort: SSL_SESSION objects with no reachable SSL. Without a
 * client_random these cannot form a usable keylog line, so they go to a separate
 * unpaired report and the tier is off unless the profile enables it.
 * ------------------------------------------------------------------------- */

function processOrphanSession(base, tier, stats) {
    var off = state.profile.struct_offsets.SSL_SESSION;
    var len = readU8OrNull(base.add(off.secret_len));
    if (len !== tier.require_secret_len) return;
    var bytes = readBytes(base.add(off.secret), len);
    if (!looksLikeSecret(bytes)) return;
    stats.tierC.validated++;
    var idLen = readU8OrNull(base.add(off.session_id_len));
    var version = readU16OrNull(base.add(off.ssl_version));
    emitUnpaired(base, hexBytes(bytes),
                 idLen ? readHex(base.add(off.session_id), idLen) : '',
                 version === null ? 0 : version, stats);
}

function runTierC(ranges, stats, errors) {
    var tier = state.profile.tiers.C_orphan_session;
    if (!tier || !tier.enabled) return;
    for (var r = 0; r < ranges.length; r++) {
        var hits = scanRange(ranges[r], tier.anchor.pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            stats.tierC.candidates++;
            var base = hits[h].address.sub(tier.anchor.offset_in_struct);
            try { processOrphanSession(base, tier, stats); }
            catch (e: any) { errors.push('tierC ' + base + ': ' + e.message); }
        }
    }
}

export const BoringsslEngine: MemscanEngine = {
    name: 'boringssl',
    runTiers: function (ranges: any, stats: any, errors: string[]): void {
        if (shouldRunTierA()) runTierA(ranges, stats, errors);
        else stats.tierA.skipped = true;
        runTierB(ranges, stats, errors);
        runTierC(ranges, stats, errors);
        state.lastTierBValidated = stats.tierB.validated;
    }
};
registerEngine(BoringsslEngine);
