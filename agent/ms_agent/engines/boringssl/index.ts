import { state } from "../../state.js";
import { registerEngine } from "../../registry.js";
import { MemscanEngine } from "../../types.js";

import { log } from "../../core/log.js";
import { hexBytes, hex, readHex, readBytes, readPointerOrNull, readU8OrNull, readU16OrNull, scanRange, pointerToScanPattern, pointerToTagAgnosticScanPattern } from "../../core/memory.js";
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

/* ---------------------------------------------------------------------------
 * Tier B needle seeding from live SSL_read / SSL_write.
 *
 * Tier A is the only path that derives the needle from a REAL object, but it can
 * only do so by catching a live SSL_HANDSHAKE (the 03 03 04 03 anchor), which is
 * ephemeral and NEVER appears for a TLS session that was already open before
 * friTap attached. SSL_read / SSL_write, by contrast, fire on every active
 * session — pre-existing ones included — and their first argument is the SSL*.
 * Reading ssl->method there yields the exact same shared SSL_PROTOCOL_METHOD
 * pointer Tier A would derive (method is field 0), so Tier B can then enumerate
 * every live SSL with no handshake required. This is an ADDITIONAL needle source;
 * Tier A and the static profile hint are untouched.
 * ------------------------------------------------------------------------- */

var needleSeedInstalled = false;     // installNeedleSeedHooks ran (once per process)
var needleSeedListeners: any[] = []; // Interceptor listeners; detached after first seed

/* Opt-out per profile via tiers.B_ssl_method_ptr.seed_from_ssl_io. Absent or any
 * non-false value means ON, so a profile has to say `false` explicitly to disable
 * it; the shipped signal/chrome profiles set it true. */
function seedFromSslIoEnabled() {
    var tier = state.profile && state.profile.tiers && state.profile.tiers.B_ssl_method_ptr;
    return !!tier && tier.seed_from_ssl_io !== false;
}

/* Read ssl->method from a candidate SSL* and, when it is a plausible pointer into
 * a mapped region and no live-derived needle exists yet, record it as the Tier B
 * needle — exactly the shape rememberNeedle() produces, plus a `source` tag for
 * diagnostics. Returns true when state.needle now holds THIS method value (whether
 * this call set it or a prior seed/Tier A already did), false otherwise.
 *
 * Never throws: a bad SSL* is ignored so a hook on the hot I/O path can never
 * crash the target. The guard is deliberately keep-first: once any live-derived
 * needle is set, a different method value does NOT overwrite it. */
export function seedNeedleFromSsl(ssl, source) {
    if (ssl === null || ssl.isNull()) return false;
    var method;
    try {
        method = readPointerOrNull(ssl.add(state.profile.struct_offsets.SSL.method));
    } catch (e: any) { return false; }
    if (!looksLikeHeapPointer(method)) return false;
    if (state.needle !== null) return state.needle.value.equals(method);  // keep the needle we have
    var mod = null;
    try { mod = Process.findModuleByAddress(untag(method)); } catch (e: any) { mod = null; }
    state.needle = {
        value: method,
        module: mod === null ? null : mod.name,
        rva: mod === null ? null : '0x' + untag(method).sub(mod.base).toString(16),
        source: source
    };
    log('info', 'Tier B needle derived (' + source + '): ' + method +
                (mod === null ? '' : ' (' + state.needle.module + '+' + state.needle.rva + ')'));
    return true;
}

/* Concrete (wildcard-free) module names from EVERY boringssl profile configure()
 * was handed. Two boringssl profiles (Chrome + Signal) can coexist in one session
 * and the seed installs once, so we probe both profiles' modules; a name with a
 * '*' cannot be passed to findExportByName and is skipped (global lookup covers
 * it). */
function candidateModules() {
    var out: string[] = [];
    var profiles = state.profiles !== null ? state.profiles : [state.profile];
    for (var i = 0; i < profiles.length; i++) {
        var p = profiles[i];
        var mods = p && p.match && p.match.modules;
        if (!mods) continue;
        for (var j = 0; j < mods.length; j++) {
            if (typeof mods[j] === 'string' && mods[j].indexOf('*') === -1) out.push(mods[j]);
        }
    }
    return out;
}

/* Resolve an SSL I/O export by name: the profiles' named modules first, then a
 * global lookup, then a scan of EVERY loaded module. The global lookup only finds
 * a statically-linked or globally-scoped BoringSSL; Signal (and any app that
 * dlopen()s libssl.so with RTLD_LOCAL) exports SSL_read/SSL_write from a module
 * that is neither profile-listed nor in the global scope, so the full enumeration
 * — the same approach friTap's main hooking pipeline uses — is the reliable path.
 * Returns null when nothing resolves. */
function resolveSslExport(name) {
    var mods = candidateModules();
    for (var i = 0; i < mods.length; i++) {
        try {
            var m = Process.findModuleByName(mods[i]);
            var a = m === null ? null : m.findExportByName(name);
            if (a !== null && !a.isNull()) return a;
        } catch (e: any) { /* module not loaded — try the next */ }
    }
    try {
        var g = Module.findGlobalExportByName(name);
        if (g !== null && !g.isNull()) return g;
    } catch (e: any) { /* not globally exported */ }
    // Last resort: enumerate all loaded modules. This catches a dynamically
    // loaded libssl.so (RTLD_LOCAL) that neither of the lookups above can reach.
    try {
        var all = Process.enumerateModules();
        for (var k = 0; k < all.length; k++) {
            try {
                var e = all[k].findExportByName(name);
                if (e !== null && !e.isNull()) return e;
            } catch (err: any) { /* keep scanning */ }
        }
    } catch (e2: any) { /* enumeration unavailable — give up */ }
    return null;
}

/* Resolve EVERY instance of an SSL I/O export, deduped by address. Multiple
 * libssl copies can coexist (e.g. a globally-exported cronet/webview libssl AND
 * the app's own dlopen()'d RTLD_LOCAL libssl.so). A pre-existing socket routes
 * through exactly one of them, and its SSL_read/SSL_write may be reachable ONLY
 * via the symbol table (RTLD_LOCAL exports are not global) — the same case
 * friTap's main pipeline handles with an enumerateSymbols() fallback. So we
 * collect exports AND symbol-table matches across all modules and hook them all;
 * onEnter seeds once and detaches, so extra hooks cost nothing. */
function resolveSslExportsAll(name) {
    var out: NativePointer[] = [];
    var seen: { [k: string]: boolean } = {};
    function add(p) {
        if (p === null || p.isNull()) return;
        var key = p.toString();
        if (seen[key]) return;
        seen[key] = true;
        out.push(p);
    }
    var single = resolveSslExport(name);
    if (single !== null) add(single);
    try {
        var all = Process.enumerateModules();
        for (var i = 0; i < all.length; i++) {
            var m = all[i];
            // Exported in this module?
            try {
                var ex = m.findExportByName(name);
                if (ex !== null && !ex.isNull()) add(ex);
            } catch (e: any) { /* next */ }
            // Symbol-table fallback — only for TLS-bearing modules (bounded cost),
            // which is what reaches an SSL_read/SSL_write that is present only in a
            // module's symbol table (RTLD_LOCAL, non-exported). Signal's active TLS
            // lives in libhttpengine.so (Cronet), whose SSL_read is symbol-only —
            // so the allowlist must include it (device-confirmed). Kept as a
            // substring list rather than "all modules" to bound enumerateSymbols()
            // cost at install time.
            // Substring allowlist of TLS-bearing module names. Deliberately small
            // and specific: enumerateSymbols() on a huge module (libmonochrome,
            // libwebviewchromium — 100+ MB) is expensive and, on a stripped module,
            // finds nothing anyway, so those are excluded. Note: modern Signal's
            // APEX Cronet (libhttpengine.so / libcrypto_httpengine.so) is stripped —
            // SSL_read/SSL_write are in neither the dynamic nor the debug symbol
            // table, so a symbol-name seed cannot reach them; recovering those needs
            // a byte-pattern needle seed (tracked separately).
            var nm = (m.name || '').toLowerCase();
            var sslBearing = ['libssl', 'boringssl', 'conscrypt',
                'httpengine', 'signal'];
            var isSslBearing = false;
            for (var s = 0; s < sslBearing.length; s++) {
                if (nm.indexOf(sslBearing[s]) !== -1) { isSslBearing = true; break; }
            }
            if (!isSslBearing) continue;
            try {
                var syms = m.enumerateSymbols();
                for (var j = 0; j < syms.length; j++) {
                    if (syms[j].name === name && syms[j].address !== null &&
                        !syms[j].address.isNull()) add(syms[j].address);
                }
            } catch (e2: any) { /* symbols unavailable — next */ }
        }
    } catch (e3: any) { /* enumeration unavailable */ }
    return out;
}

function detachNeedleSeedHooks() {
    for (var i = 0; i < needleSeedListeners.length; i++) {
        try { needleSeedListeners[i].detach(); } catch (e: any) { /* best effort */ }
    }
    needleSeedListeners = [];
}

/* How many needle-seed Interceptor listeners are still attached. Diagnostic +
 * test surface: proves the seed hooks are gone after engine stop even on a target
 * where a needle was never seeded (so onSslIoEnter never self-detached). */
export function needleSeedListenerCount(): number {
    return needleSeedListeners.length;
}

/* onEnter for SSL_read/SSL_write: arg0 is SSL*. Seed the needle, then — once ANY
 * needle exists — detach so there is zero per-call overhead on the hot I/O path.
 * Wrapped so a hook can never throw into the target. */
function onSslIoEnter(args) {
    try { seedNeedleFromSsl(args[0], 'ssl_io'); } catch (e: any) { /* never throw into target */ }
    if (state.needle !== null) detachNeedleSeedHooks();
}

function attachSslIoHook(name) {
    var addrs = resolveSslExportsAll(name);
    var n = 0;
    for (var i = 0; i < addrs.length; i++) {
        try {
            needleSeedListeners.push(Interceptor.attach(addrs[i], { onEnter: onSslIoEnter }));
            n++;
        } catch (e: any) { /* one bad address must not lose the others */ }
    }
    return n > 0;
}

/* Install the SSL_read/SSL_write (and *_ex when present) seed hooks ONCE per
 * process. Runs from the engine's runTiers regardless of whether Tier A ever
 * fires. Failing to resolve the exports is a soft failure: Tier A / the profile
 * hint remain the fallback and the engine behaves exactly as before. */
export function installNeedleSeedHooks() {
    if (needleSeedInstalled) return;
    needleSeedInstalled = true;
    if (!seedFromSslIoEnabled()) return;
    if (typeof Interceptor === 'undefined' || Interceptor === null) return;
    var names = ['SSL_read', 'SSL_write', 'SSL_read_ex', 'SSL_write_ex'];
    var attached = 0;
    for (var i = 0; i < names.length; i++) if (attachSslIoHook(names[i])) attached++;
    if (attached === 0) {
        log('warn', 'Tier B needle seed: could not resolve SSL_read/SSL_write in this ' +
                    'process; falling back to Tier A / profile hint');
    } else {
        log('info', 'Tier B needle seed hooks installed on ' + attached + ' SSL I/O export(s)');
    }
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

/* Enriched "secret bundle" for the offline mid-stream decrypter. Runs ONLY on the
 * HS_COMPLETE path, right after emitS3TrafficSecrets has emitted the ordinary NSS
 * keylog lines, and emits the same three application-epoch traffic secrets TOGETHER
 * with BOTH randoms in one leak-safe sidecar record. A flow whose ClientHello never
 * appears in the pcap has no client_random on the wire to pair the NSS line against;
 * carrying server_random alongside lets the offline decrypter recover the epoch keys
 * for exactly those mid-stream flows. The NSS line (emitS3TrafficSecrets/emitKeylog)
 * is untouched and stays the primary output for handshake-present flows.
 *
 * Opt-in per profile via tiers.B_ssl_method_ptr.emit_secret_bundle, so the extra
 * sidecar is only produced where an offline mid-stream consumer is wired up.
 *
 * Also reused by Tier B0 (idle-SSL bootstrap), which finds a post-handshake
 * SSL3_STATE directly on the heap and may have NO SSL* to go with it; hence `ssl`
 * is tolerated as null (its only use is the provenance field, emitted as '').
 *
 * The three traffic secrets are re-read and re-validated here through the SAME
 * looksLikeSecret gate the keylog path uses; if ANY of them fails, NOTHING is
 * emitted (a partial bundle cannot decrypt). server_random is DIFFERENT: it is
 * carried for provenance only — the offline TLS 1.3 decrypter recovers the epoch
 * keys from the traffic secrets and never reads server_random — so a scrubbed or
 * reused server_random (common on a long-idle post-handshake SSL3_STATE, exactly
 * Tier B0's target) must NOT drop the whole bundle. It is included when it looks
 * like a CSPRNG value and emitted as '' otherwise. No cipher_id is included - this
 * build's profile carries no verified offset for it (SSL3_STATE has no cipher_id
 * field), and inventing one would be exactly the plausible-but-wrong output the
 * profile's design notes forbid. */
export function emitSecretBundle(ssl, s3, clientRandom, stats) {
    var tier = state.profile.tiers.B_ssl_method_ptr;
    if (!tier.emit_secret_bundle) return false;
    var off = state.profile.struct_offsets.SSL3_STATE;
    var c = state.profile.constants;

    // Provenance only, never required for decryption: include it when valid, else
    // emit ''. Do NOT drop the bundle when server_random is scrubbed/reused.
    var serverRandomBytes = readBytes(s3.add(off.server_random), c.ssl3_random_size);
    var serverRandomHex = looksLikeRandom(serverRandomBytes) ? hexBytes(serverRandomBytes) : '';

    var fields = [
        { field: 'write_traffic_secret', key: 'client_traffic_secret_0' },
        { field: 'read_traffic_secret',  key: 'server_traffic_secret_0' },
        { field: 'exporter_secret',      key: 'exporter_secret' }
    ];
    var bundle: any = {};
    for (var i = 0; i < fields.length; i++) {
        var len = readU8OrNull(s3.add(off[fields[i].field + '_len']));
        if (len === null || len === 0) return false;
        var bytes = readBytes(s3.add(off[fields[i].field]), len);
        if (!looksLikeSecret(bytes)) return false;      // one bad field => no bundle
        bundle[fields[i].key] = hexBytes(bytes);
    }

    /* Cross-scan dedup — mirrors emitKeylog's state.recorded guard. Without it
     * Tier B0 re-emits the SAME idle bundle every scan, so the poll loop's
     * emitted>0 backoff never grows and the heavy full-heap scan runs continuously
     * (device-confirmed ANR). Key on client_random; VALUE is every secret that
     * makes the bundle decrypt, so a KeyUpdate (same client_random, rotated
     * secrets) is a different value and still re-emits, while a re-scan of the
     * unchanged idle SSL returns quietly without send() or stats.emitted++. */
    var bundleKey = 'BUNDLE|' + clientRandom;
    var bundleValue = bundle.client_traffic_secret_0 + '|' + bundle.server_traffic_secret_0 +
                      '|' + bundle.exporter_secret + '|' + serverRandomHex;
    if (state.recordedBundles[bundleKey] === bundleValue) return false;  // already emitted, unchanged
    state.recordedBundles[bundleKey] = bundleValue;

    send({
        type: 'tls_secret_bundle',
        client_random: clientRandom,
        server_random: serverRandomHex,
        client_traffic_secret_0: bundle.client_traffic_secret_0,
        server_traffic_secret_0: bundle.server_traffic_secret_0,
        exporter_secret: bundle.exporter_secret,
        // ssl is provenance only. Tier B0 emits a bundle straight from an idle
        // SSL3_STATE with no reachable SSL*, so a null ssl is expected there and
        // must not throw — an empty provenance string then stands for "no SSL*".
        ssl: ssl === null ? '' : ssl.toString()
    });
    stats.emitted++;
    return true;
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
        // Enriched sidecar for offline mid-stream decryption (opt-in per profile).
        // Emitted BESIDE the NSS line above, never in place of it.
        emitSecretBundle(ssl, s3, clientRandom, stats);
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

/* ---------------------------------------------------------------------------
 * Tier B0 — idle-SSL bootstrap. Recovers a PRE-EXISTING, post-handshake ("idle")
 * TLS socket whose libssl is STRIPPED (modern Signal APEX Cronet
 * libhttpengine.so: SSL_read/SSL_write have NO symbols, so the symbol-based
 * needle seed can never fire and Tier A never catches a handshake for it).
 *
 * Instead of hooking a function, scan the heap DIRECTLY for a live SSL3_STATE by
 * its three stride-49 traffic-secret length bytes, validate it, and emit the
 * secret bundle STRAIGHT FROM SSL3_STATE — no needle required. Optionally reverse
 * -link back to the SSL* to seed the Tier B needle for full enumeration.
 *
 * Runs ONLY when no needle is known yet (see runTiers): once anything has seeded a
 * needle, Tier B already enumerates every live SSL, so Tier B0 costs nothing.
 * ------------------------------------------------------------------------- */

/* One masked Memory.scanSync pattern per valid hash length. The three traffic
 * secrets are InplaceVectors at a fixed stride, so their length bytes sit at
 * write_traffic_secret_len, read_traffic_secret_len and exporter_secret_len — a
 * span from the first to the last length byte with the SAME length value L at
 * exactly those three positions and every other byte a wildcard. A hit's address
 * IS write_traffic_secret_len, so s3 = hit - write_traffic_secret_len.
 *
 * Every position is derived from struct_offsets (the gaps encode the stride-49
 * constants.inplace_vector_stride), so nothing is hardcoded here. */
export function buildIdleS3Anchors() {
    var off = state.profile.struct_offsets.SSL3_STATE;
    var lens = state.profile.constants.valid_hash_lens;
    var base = off.write_traffic_secret_len;
    var p0 = off.write_traffic_secret_len - base;   // 0
    var p1 = off.read_traffic_secret_len - base;    // one stride on
    var p2 = off.exporter_secret_len - base;        // two strides on
    var span = p2 + 1;
    var anchors: any[] = [];
    for (var i = 0; i < lens.length; i++) {
        var L = lens[i];
        var hexL = (L < 16 ? '0' : '') + L.toString(16);
        var tokens = new Array(span);
        for (var j = 0; j < span; j++) tokens[j] = '??';
        tokens[p0] = hexL; tokens[p1] = hexL; tokens[p2] = hexL;
        anchors.push({ pattern: tokens.join(' '), hashLen: L, anchorOffset: base });
    }
    return anchors;
}

/* A byte pattern of three fixed length bytes has real random-hit odds over a big
 * heap, so a hit is only a fact once the fields it implies check out. Idle means
 * the handshake object is GONE (s3->hs == NULL): that is precisely the case Tier A
 * cannot reach and the case where s3's three traffic secrets hold the current
 * application epoch. A faulting hs read or a live hs pointer is NOT idle. Then all
 * three traffic secrets must be real hash-length secrets and client_random must be
 * CSPRNG-shaped — which rejects a coincidental three-byte collision. */
export function validateIdleS3(s3) {
    var off = state.profile.struct_offsets.SSL3_STATE;
    var c = state.profile.constants;
    var hs = readPointerOrNull(s3.add(off.hs));
    if (hs === null || !hs.isNull()) return false;              // faulted or live => not idle
    var cr = readBytes(s3.add(off.client_random), c.ssl3_random_size);
    if (!looksLikeRandom(cr)) return false;
    var fields = ['write_traffic_secret', 'read_traffic_secret', 'exporter_secret'];
    for (var i = 0; i < fields.length; i++) {
        var len = readU8OrNull(s3.add(off[fields[i] + '_len']));
        if (len === null || len === 0) return false;
        var bytes = readBytes(s3.add(off[fields[i]]), len);
        if (!looksLikeSecret(bytes)) return false;             // one bad field => reject
    }
    return true;
}

/* Accept `ssl` as the real SSL that owns `s3`. Two structural checks, keyed on
 * offsets fixed in BoringSSL and verified for every profiled build:
 *   1. ssl->s3 (offset SSL.s3) points back at s3 — the two-way close.
 *   2. ssl->method (field 0, the Tier B needle) is a plausible pointer that
 *      resolves to a LOADED MODULE — the shared static SSL_PROTOCOL_METHOD lives in
 *      a module's rodata, never on the heap, so this both proves method is a usable
 *      needle AND rejects the coincidental pointer-to-s3 slots the tag-agnostic scan
 *      also turns up (their "method" is 0x0/0x2/a heap address, not a module).
 * Then an OPTIONAL, PROFILE-DRIVEN extra confirmation: each SSL field named in
 * tiers.B_ssl_method_ptr.reverse_link_require_heap_fields must itself be a plausible
 * heap pointer. The default is ['session','ctx'] — the historical behavior, so
 * Chrome/Cronet and every profile that does not override it are UNCHANGED. The
 * signal profile sets it to [] because those field offsets are only verified for
 * the Chrome layout and on libsignal's in-tree BoringSSL ssl->session at that offset
 * is null/unset for a mid-stream TLS 1.3 socket — requiring it silently rejected the
 * real SSL and left the Tier B needle unseeded, forcing the fragile Tier B0 anchor.
 * Round-trip + method-in-module alone uniquely identifies the owning SSL (measured
 * on-device), and Tier B re-validates every candidate it then enumerates, so nothing
 * downstream trusts a needle blindly. */
function acceptsAsSsl(ssl, s3) {
    var off = state.profile.struct_offsets;
    var back = readPointerOrNull(ssl.add(off.SSL.s3));
    if (back === null || !untag(back).equals(untag(s3))) return false;
    var method = readPointerOrNull(ssl.add(off.SSL.method));
    if (!looksLikeHeapPointer(method)) return false;
    var mod = null;
    try { mod = Process.findModuleByAddress(untag(method)); } catch (e: any) { mod = null; }
    if (mod === null) return false;
    var extra = state.profile.tiers.B_ssl_method_ptr.reverse_link_require_heap_fields;
    if (extra === undefined) extra = ['session', 'ctx'];
    for (var i = 0; i < extra.length; i++) {
        if (!looksLikeHeapPointer(readPointerOrNull(ssl.add(off.SSL[extra[i]])))) return false;
    }
    return true;
}

/* Reverse-link an idle SSL3_STATE to its SSL* by scanning the heap for a pointer
 * whose value is s3, then treating that slot as ssl->s3 (candidate ssl = slot -
 * SSL.s3). Bounded: returns the FIRST candidate that acceptsAsSsl, else null. The
 * SSL* is optional — the bundle is emitted from s3 either way — so a null result
 * simply means Tier B cannot be seeded from this object. */
export function sslFromS3(s3, ranges, errors) {
    var off = state.profile.struct_offsets;
    // The stored ssl->s3 carries its scudo/MTE allocation tag while `s3` (from a
    // range scan) is untagged, so match tag-agnostically or the reverse-link never
    // fires on an MTE target (libsignal on Android) — the exact bug that left the
    // Tier B needle unseeded mid-stream and forced the fragile Tier B0 anchor.
    var pattern = pointerToTagAgnosticScanPattern(s3, state.validators.tagMask);
    for (var r = 0; r < ranges.length; r++) {
        var hits = scanRange(ranges[r], pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            var ssl = hits[h].address.sub(off.SSL.s3);
            if (acceptsAsSsl(ssl, s3)) return ssl;
        }
    }
    return null;
}

/* Present when the driver pre-initialised stats (the normal path); created here so
 * the engine's own tests can call runTierB0 with a bare stats object. */
function ensureTierB0Stats(stats) {
    if (!stats.tierB0) stats.tierB0 = { candidates: 0, validated: 0, emitted: 0 };
    return stats.tierB0;
}

/* Absent or any non-false value means ON, so a profile disables Tier B0 only by
 * saying enabled:false explicitly; the shipped boringssl profiles ship it on. */
function tierB0Enabled() {
    var t = state.profile.tiers.B0_idle_ssl;
    return !t || t.enabled !== false;
}

/* How often Tier B0 runs while no needle exists — mirrors tierARescanEvery().
 * Missing, non-numeric or < 1 fall back to a sane default (8), so a bad profile
 * value can only change the cadence, never switch the tier off. Tier B0 is a heavy
 * full-heap masked scan; running it every cycle on stripped Cronet (where the
 * needle never seeds) pins CPU and starved Signal's UI thread into an ANR. */
function tierB0RescanEvery() {
    var t = state.profile.tiers.B0_idle_ssl;
    var configured = t && t.rescan_every;
    if (typeof configured !== 'number' || !isFinite(configured) || configured < 1) return 8;
    return Math.floor(configured);
}

/* The stable per-profile key for the Tier B0 throttle counter. Profiles carry an
 * `id` (see driver.ts / patterns.json); '?' guards a scaffold profile that has none
 * so the counter never keys on `undefined`. */
function tierB0ProfileKey(): string {
    var p = state.profile;
    return (p && p.id) ? p.id : 'default';
}

/* PER-PROFILE Tier B0 scan counter: reads the active profile's eligible-scan count,
 * increments it, and returns the PRE-increment value (0 on that profile's FIRST
 * eligible scan). It must NOT use the global state.scanIndex: under the default
 * `--protocol signal` command two boringssl profiles run each scan and share
 * state.scanIndex (incremented once per profile-scan in driver.ts), so one profile
 * only ever sees ODD indices and a `scanIndex % N === 0` gate never fires for it —
 * starving its Tier B0 (device-confirmed). Counting per profile makes each profile's
 * Tier B0 run on ITS OWN scans 0, N, 2N, … regardless of ordering or parity.
 *
 * The caller gates this behind `resolveNeedleValue() === null`, so the counter only
 * advances on scans where Tier B0 is actually eligible — intended. */
export function nextTierB0ProfileScan(): number {
    var key = tierB0ProfileKey();
    var count = state.b0ProfileScans[key] || 0;
    state.b0ProfileScans[key] = count + 1;
    return count;
}

/* WHETHER Tier B0 runs given THIS profile's eligible-scan count (its caller in
 * runTiers still also gates on resolveNeedleValue() === null). The count is 0 on the
 * profile's FIRST eligible scan, so that scan always runs — it emits the idle bundle
 * once — and then only every Nth of that profile's scans, so the emitted bundle can
 * go quiet (via emitSecretBundle's dedup) and the poll loop's backoff can grow
 * instead of the heap scan running on every cycle. Pure: the counter advances in
 * nextTierB0ProfileScan(), keeping this predicate side-effect-free and testable. */
export function shouldRunTierB0(profileScanCount: number): boolean {
    return profileScanCount % tierB0RescanEvery() === 0;
}

/* One validated idle SSL3_STATE: emit its secret bundle DIRECTLY (no SSL* / needle
 * required), then — only if the SSL* was recovered — seed the Tier B needle so the
 * rest of the scan can enumerate every other live SSL. */
function processIdleS3(s3, ranges, b0, stats, errors) {
    if (!validateIdleS3(s3)) return;
    b0.validated++;
    var clientRandom = readClientRandom(s3);
    if (clientRandom === null) return;                         // re-checked; defensive
    // Reverse-link to the owning SSL* only while the needle is still unseeded: the
    // first success seeds it and Tier B takes over, so later idle-S3 hits in the
    // same scan skip the (full-heap) reverse-link. The bundle is emitted from s3
    // either way, so a null ssl costs nothing.
    var ssl = state.needle === null ? sslFromS3(s3, ranges, errors) : null;
    if (emitSecretBundle(ssl, s3, clientRandom, stats)) b0.emitted++;
    if (ssl !== null) seedNeedleFromSsl(ssl, 'heap_idle_s3');
}

export function runTierB0(ranges, stats, errors) {
    if (!tierB0Enabled()) return;
    var b0 = ensureTierB0Stats(stats);
    var anchors = buildIdleS3Anchors();
    var seen: { [k: string]: boolean } = {};                  // dedup s3 within this scan
    for (var a = 0; a < anchors.length; a++) {
        for (var r = 0; r < ranges.length; r++) {
            var hits = scanRange(ranges[r], anchors[a].pattern, errors);
            for (var h = 0; h < hits.length; h++) {
                var s3 = hits[h].address.sub(anchors[a].anchorOffset);
                var key = s3.toString();
                if (seen[key]) continue;
                seen[key] = true;
                b0.candidates++;
                try { processIdleS3(s3, ranges, b0, stats, errors); }
                catch (e: any) { errors.push('tierB0 ' + s3 + ': ' + e.message); }
            }
        }
    }
}

export const BoringsslEngine: MemscanEngine = {
    name: 'boringssl',
    runTiers: function (ranges: any, stats: any, errors: string[]): void {
        // Seed the Tier B needle from live SSL_read/SSL_write once. This makes
        // Tier B work on a purely pre-existing TLS session (no handshake for Tier
        // A to catch); it runs whether or not Tier A ever fires.
        installNeedleSeedHooks();
        // Tier B0 (idle-SSL bootstrap): only when NOTHING has seeded a needle yet.
        // It recovers a stripped-libssl idle socket by scanning the heap for a live
        // SSL3_STATE and emits the bundle straight from it, and — if it can reverse
        // -link the SSL* — seeds the needle so the Tier B pass below enumerates the
        // rest. Once any needle exists this is skipped, so it is zero-cost thereafter.
        // shouldRunTierB0() throttles it to every Nth of THIS profile's scans: without
        // a needle (stripped Cronet) the gate below would otherwise run this heavy
        // full-heap masked scan on EVERY cycle, pinning CPU into an ANR. The profile's
        // scan 0 still runs (emits the idle bundle once), then dedup keeps steady-state
        // quiet so the backoff can grow. The counter is PER PROFILE (not the global
        // state.scanIndex) so that with two boringssl profiles sharing the scan loop,
        // neither is starved by the other's parity — short-circuit means the counter
        // only advances on scans where Tier B0 is eligible (needle still null).
        if (resolveNeedleValue() === null && shouldRunTierB0(nextTierB0ProfileScan())) runTierB0(ranges, stats, errors);
        if (shouldRunTierA()) runTierA(ranges, stats, errors);
        else stats.tierA.skipped = true;
        runTierB(ranges, stats, errors);
        runTierC(ranges, stats, errors);
        state.lastTierBValidated = stats.tierB.validated;
    },
    // Teardown, run from the agent's `dispose` RPC before the script is unloaded.
    // The needle-seed hooks on SSL_read/SSL_write self-detach in onSslIoEnter once
    // a needle is found (the happy path), but on a target where none ever seeds —
    // stripped Cronet, the device case — they would otherwise stay attached to the
    // hot I/O path until frida's implicit detach, whose synchronous prologue
    // rewrite there stalls unload for minutes. Detaching them here is unconditional
    // (needle found or not) and idempotent: detachNeedleSeedHooks empties the list.
    stop: function (): void {
        detachNeedleSeedHooks();
    }
};
registerEngine(BoringsslEngine);
