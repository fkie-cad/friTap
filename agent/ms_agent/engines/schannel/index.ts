import { state } from "../../state.js";
import { registerEngine } from "../../registry.js";
import { MemscanEngine } from "../../types.js";
import { log } from "../../core/log.js";
import { hexBytes, readBytes, readPointerOrNull, readU8OrNull, readU32OrNull, scanRange, pointerToScanPattern } from "../../core/memory.js";
import { untag, looksLikeHeapPointer } from "../../core/pointers.js";
import { passesZeroFraction, passesEntropy } from "../../core/heuristics.js";


function schannelResolved() {
    var p = state.profile;
    if (p && p.resolved) return p.resolved;
    var arch = (p && p.arch) || {};
    return arch[Process.arch] || arch.arm64 || {};
}

/* Schannel's secret gate is entropy + zero-fraction only: every read is a fixed,
 * known length (a 48-byte master, or one of secret_lens for TLS 1.3), so the
 * BoringSSL hash-length/bounds checks (which need a constants block a schannel
 * profile does not carry) do not apply. */
function schannelLooksLikeSecret(bytes) {
    return bytes !== null && passesZeroFraction(bytes) && passesEntropy(bytes);
}

function pointerInModule(p, mod) {
    if (p === null || mod === null) return false;
    var u = untag(p);
    return u.compare(mod.base) >= 0 && u.compare(mod.base.add(mod.size)) < 0;
}

function reverseStr(s) {
    return s.split('').reverse().join('');
}

function bytesEqualAscii(bytes, str) {
    if (bytes === null || bytes.length < str.length) return false;
    for (var i = 0; i < str.length; i++) if (bytes[i] !== str.charCodeAt(i)) return false;
    return true;
}

/* Accept either byte order: the 4-char pool tags ('BDDD','ssl5'/'5lss') appear in
 * both spellings in the sources. Safe because a magic hit is only ever acted on
 * together with a valid 48-byte master AND an ncryptsslp pointer. */
function magicMatches(addr, magicStr) {
    var b = readBytes(addr, magicStr.length);
    if (b === null) return false;
    return bytesEqualAscii(b, magicStr) || bytesEqualAscii(b, reverseStr(magicStr));
}

function isAllZero(bytes) {
    if (bytes === null) return true;
    for (var i = 0; i < bytes.length; i++) if (bytes[i] !== 0) return false;
    return true;
}

/* Memory.scanSync pattern for a short ASCII tag ('3lss' -> '33 6c 73 73'). */
function asciiToScanPattern(str) {
    var parts = [];
    for (var i = 0; i < str.length; i++) {
        var h = str.charCodeAt(i).toString(16);
        parts.push(h.length < 2 ? '0' + h : h);
    }
    return parts.join(' ');
}

/* Each candidate is an rva within ncryptsslp.dll; the value to scan for is
 * module.base + rva, resolved at runtime so ASLR does not matter. An empty
 * candidate list (e.g. uncalibrated x64) resolves to no needles and the tls12/
 * session-cache tiers no-op safely rather than scan for garbage. */
function resolveSchannelNeedles() {
    var cfg = schannelResolved().needle;
    if (!cfg || !cfg.module) {
        log('warn', 'schannel: no needle configured for this arch; TLS 1.2 tier disabled');
        return { needles: [], module: null };
    }
    var mod = Process.findModuleByName(cfg.module);
    if (mod === null) {
        log('warn', 'schannel: needle module ' + cfg.module + ' not loaded; nothing to scan for');
        return { needles: [], module: null };
    }
    var out = [];
    var cands = cfg.candidates || [];
    for (var i = 0; i < cands.length; i++) {
        var value = mod.base.add(ptr(cands[i].rva));
        out.push({ value: value, module: cfg.module, rva: cands[i].rva });
        log('info', 'schannel needle ' + cfg.module + '+' + cands[i].rva + ' -> ' + value);
    }
    return { needles: out, module: { base: mod.base, size: mod.size } };
}

function ensureSchannelResolved() {
    if (state.schannelReady) return;
    var r = resolveSchannelNeedles();
    state.schannelNeedles = r.needles;
    state.schannelNeedleModule = r.module;
    var schan = Process.findModuleByName('schannel.dll');
    state.schannelModule = schan === null ? null : { base: schan.base, size: schan.size };
    state.schannelReady = true;
}

/* Unpaired only: without a client_random these cannot be keyed into an NSS line
 * here, so they go to the driver's unpaired report to be joined to the pcap
 * offline (WS5). Deduped across scans on kind + address + secret bytes.
 *
 * `group` (optional) is the per-connection id the offline correlator uses to
 * place EXPORTER_SECRET by elimination (5th sidecar column; parsed in
 * friTap/offline/schannel/unpaired.py, forwarded by engine.py:_write_unpaired).
 * It is sent ONLY when set — the dedupe key and the Python side both handle its
 * absence, so an un-grouped secret degrades to the old safe behavior. The group
 * is derived by runSchannelTls13Secret (see the proven rule there). */
function emitSchannelUnpaired(kind, ssl5, secret, sslVersion, stats, group?) {
    var key = kind + '|' + ssl5.toString() + '|' + secret;
    if (state.recorded[key] !== undefined) return;
    state.recorded[key] = secret;
    var msg: any = {
        type: 'unpaired', kind: kind,
        secret: secret, session_id: '',
        ssl_version: sslVersion, addr: ssl5.toString()
    };
    if (group) msg.group = group;      // omit entirely when not derived (safe)
    send(msg);
    stats.emitted++;
}

/* TLS 1.2 master tier — the confirmed path. Scan for each needle value; a hit is
 * the address of ssl5+needle_at, so ssl5 = hit - needle_at and master = ssl5 +
 * master_at. Read guarded, validate, emit unpaired. Validated ssl5 anchors are
 * handed to the session_cache tier so it need not re-scan for the needle. */
function runSchannelTls12Master(ranges, stats, errors, ssl5s) {
    var tier = (schannelResolved().tiers || {}).tls12_master;
    if (!tier || !tier.enabled || state.schannelNeedles.length === 0) return;
    var deltaToMaster = tier.master_at - tier.needle_at;    // hit -> master
    var sslVersion = 771;                                   // TLS 1.2, for the report
    for (var n = 0; n < state.schannelNeedles.length; n++) {
        var pattern = pointerToScanPattern(state.schannelNeedles[n].value);
        for (var r = 0; r < ranges.length; r++) {
            var hits = scanRange(ranges[r], pattern, errors);
            for (var h = 0; h < hits.length; h++) {
                stats.schannel.tls12Candidates++;
                try {
                    var hit = hits[h].address;
                    var ssl5 = hit.sub(tier.needle_at);
                    var bytes = readBytes(hit.add(deltaToMaster), tier.master_len);
                    if (!schannelLooksLikeSecret(bytes)) continue;
                    if (ssl5s) ssl5s.push(ssl5);
                    emitSchannelUnpaired('schannel_tls12_master', ssl5, hexBytes(bytes),
                                         sslVersion, stats);
                } catch (e: any) {
                    errors.push('schannel tls12 ' + hits[h].address + ': ' + e.message);
                }
            }
        }
    }
}

/* --- session_cache tier: the TLS 1.2 SESSION-ID correlator (read-only) --------
 * cacheItem+vftable_at   = CSslCacheClientItem vftable (a schannel.dll pointer)
 * cacheItem+bddd_ptr_at -> BDDD (magic 'BDDD' at +bddd_magic_at)
 * BDDD+ssl5_ptr_at       -> ssl5
 * ssl5+ssl5_needle_at    -> ncryptsslp.dll pointer (the tls12 invariant)
 * ssl5+master_at         -> 48-byte master
 * cacheItem+session_id_at-> the session id
 * The vftable is derived from a known ssl5 (reverse-scan -> BDDD -> cache item)
 * and cached, then forward-scanned once to enumerate every cache item — mirroring
 * the BoringSSL Tier A -> Tier B needle derivation. session_id_at is uncalibrated
 * on arm64/26200, so unless the profile marks session_id_calibrated=true the tier
 * DUMPS cache items instead of emitting a possibly-wrong session id. */

/* Reverse pointer scan: every location whose stored 8-byte value equals `value`. */
function scanForPointer(ranges, value, errors, cap) {
    var pattern = pointerToScanPattern(value);
    var hits = [];
    for (var r = 0; r < ranges.length; r++) {
        var found = scanRange(ranges[r], pattern, errors);
        for (var i = 0; i < found.length; i++) {
            hits.push(found[i].address);
            if (cap && hits.length >= cap) return hits;
        }
    }
    return hits;
}

/* When tls12_master handed us no ssl5, do a bounded needle scan to get a few. */
function bootstrapSchannelSsl5s(ranges, errors, cap) {
    var t = (schannelResolved().tiers || {}).tls12_master;
    var out = [];
    if (!t) return out;
    for (var n = 0; n < state.schannelNeedles.length && out.length < cap; n++) {
        var pattern = pointerToScanPattern(state.schannelNeedles[n].value);
        for (var r = 0; r < ranges.length && out.length < cap; r++) {
            var hits = scanRange(ranges[r], pattern, errors);
            for (var h = 0; h < hits.length && out.length < cap; h++) {
                var ssl5 = hits[h].address.sub(t.needle_at);
                if (schannelLooksLikeSecret(readBytes(ssl5.add(t.master_at), t.master_len)))
                    out.push(ssl5);
            }
        }
    }
    return out;
}

/* Derive and cache the cache-item vftable from a known ssl5. */
function bootstrapCacheVftable(ranges, ssl5s, sc, errors) {
    if (state.schannelCacheVftable !== null) return true;
    if (state.schannelModule === null) {
        log('warn', 'session_cache: schannel.dll not found; cannot validate cache items');
        return false;
    }
    var attempts = Math.min(ssl5s.length, sc.bootstrap_max_ssl5 || 4);
    for (var a = 0; a < attempts; a++) {
        var ssl5 = ssl5s[a];
        var toBddd = scanForPointer(ranges, ssl5, errors, sc.reverse_scan_cap || 64);
        for (var i = 0; i < toBddd.length; i++) {
            var bddd = toBddd[i].sub(sc.ssl5_ptr_at);
            if (!magicMatches(bddd.add(sc.bddd_magic_at), sc.bddd_magic)) continue;
            var toItem = scanForPointer(ranges, bddd, errors, sc.reverse_scan_cap || 64);
            for (var j = 0; j < toItem.length; j++) {
                var cacheItem = toItem[j].sub(sc.bddd_ptr_at);
                var vft = readPointerOrNull(cacheItem.add(sc.vftable_at));
                if (vft === null || !pointerInModule(vft, state.schannelModule)) continue;
                state.schannelCacheVftable = vft;
                log('info', 'session_cache: derived cache vftable ' + vft + ' from ssl5 ' + ssl5);
                return true;
            }
        }
    }
    log('warn', 'session_cache: could not derive the cache vftable from ' + attempts +
        ' ssl5(s) — nothing emitted (safe).');
    return false;
}

function emitSchannelSessionCache(sidHex, masterHex, ssl5, stats) {
    var line = 'RSA Session-ID:' + sidHex + ' Master-Key:' + masterHex;
    var key = 'sc|' + line;
    if (state.recorded[key] !== undefined) return;
    state.recorded[key] = masterHex;
    send({ type: 'keylog', line: line, tier: 'schannel_session_cache',
           ssl: ssl5.toString(), source: 'session_cache' });
    stats.schannel.sessionCacheEmitted++;
}

function emitSchannelCacheDump(cacheItem, ssl5, masterHex, sc, stats) {
    var key = 'dump|' + cacheItem.toString();
    if (state.recorded[key] !== undefined) return;
    state.recorded[key] = 1;
    var win = readBytes(cacheItem, sc.dump_bytes || 0x120);
    send({
        type: 'cachedump', cache_item: cacheItem.toString(), ssl5: ssl5.toString(),
        master: masterHex, session_id_at: sc.session_id_at,
        session_id_maxlen: sc.session_id_maxlen, bytes: win === null ? '' : hexBytes(win)
    });
    stats.schannel.sessionCacheDumped++;
}

/* Follow one cache item to its master; dump it or emit its session id. */
function processCacheItem(cacheItem, sc, dumpMode, stats) {
    var vft = readPointerOrNull(cacheItem.add(sc.vftable_at));
    if (!pointerInModule(vft, state.schannelModule)) return;      // stale forward-scan hit
    var bddd = readPointerOrNull(cacheItem.add(sc.bddd_ptr_at));
    if (!looksLikeHeapPointer(bddd)) return;
    if (!magicMatches(bddd.add(sc.bddd_magic_at), sc.bddd_magic)) return;
    var ssl5 = readPointerOrNull(bddd.add(sc.ssl5_ptr_at));
    if (!looksLikeHeapPointer(ssl5)) return;
    var needlePtr = readPointerOrNull(ssl5.add(sc.ssl5_needle_at));
    if (state.schannelNeedleModule !== null && !pointerInModule(needlePtr, state.schannelNeedleModule)) return;
    var master = readBytes(ssl5.add(sc.master_at), sc.master_len);
    if (!schannelLooksLikeSecret(master)) return;
    stats.schannel.cacheItems++;
    var masterHex = hexBytes(master);
    if (dumpMode) { emitSchannelCacheDump(cacheItem, ssl5, masterHex, sc, stats); return; }
    var sidLen = sc.session_id_maxlen;
    if (typeof sc.session_id_len_at === 'number') {
        var l = readU8OrNull(cacheItem.add(sc.session_id_len_at));
        if (l !== null && l > 0 && l <= sc.session_id_maxlen) sidLen = l;
    }
    var sid = readBytes(cacheItem.add(sc.session_id_at), sidLen);
    if (isAllZero(sid)) return;   // empty id (ticket/0-len session): nothing to key on
    emitSchannelSessionCache(hexBytes(sid), masterHex, ssl5, stats);
}

function runSchannelSessionCache(ranges, stats, errors, ssl5s) {
    var sc = (schannelResolved().tiers || {}).session_cache;
    if (!sc || !sc.enabled) return;
    if (ssl5s.length === 0) ssl5s = bootstrapSchannelSsl5s(ranges, errors, sc.bootstrap_max_ssl5 || 4);
    if (!bootstrapCacheVftable(ranges, ssl5s, sc, errors)) return;
    // Emit real session IDs only when the offset is calibrated (or forced on).
    var dumpMode = (sc.dump === true) || (sc.session_id_calibrated !== true);
    if (dumpMode && sc.dump !== true) {
        log('warn', 'session_cache: session_id_at is not marked calibrated; dumping cache ' +
            'items to calibrate rather than emitting possibly-wrong session IDs.');
    }
    var pattern = pointerToScanPattern(state.schannelCacheVftable);
    for (var r = 0; r < ranges.length; r++) {
        var hits = scanRange(ranges[r], pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            var cacheItem = hits[h].address.sub(sc.vftable_at);
            try { processCacheItem(cacheItem, sc, dumpMode, stats); }
            catch (e: any) { errors.push('session_cache ' + cacheItem + ': ' + e.message); }
        }
    }
}

/* Read a chain offset given numerically (secret_at: 106) or as a hypothesis
 * string ('YKSM+0x18'); fall back to `fallback` if neither is present. */
function chainOffset(value, fallback) {
    if (typeof value === 'number') return value;
    if (typeof value === 'string') {
        var m = value.match(/\+\s*0x([0-9a-fA-F]+)/);
        if (m) return parseInt(m[1], 16);
    }
    return fallback;
}

/* Per-connection grouping (RE-confirmed on Win11 arm64 26200, 2026-10-18, via
 * read-only lsass ground truth with concurrent SChannel TLS 1.3 connections).
 *
 * There is NO pointer-reachable parent above '3lss' on this build: across the
 * whole writable image, nothing points INTO a connection's secret containers,
 * the siblings share no heap pointer, and no needle-validated 'ssl5' references
 * them (all three measured zero). The '3lss' header carries only cipher/version
 * fields and the UTF-16 hash name — no connection id. What IS stable is layout:
 * a connection's three resident app secrets occupy one block at FIXED relative
 * offsets — SERVER_TRAFFIC_SECRET_0 @ base, CLIENT_TRAFFIC_SECRET_0 @ base+0xb0,
 * EXPORTER_SECRET @ base+0x4b8 (TLS_AES_256_GCM_SHA384). So the group id is the
 * base B of a structural TRIPLE: B is a '3lss' secret and B+clientOff AND
 * B+exporterOff are also '3lss' secrets. Keying on the exact geometry (not mere
 * proximity) isolates one connection even on a busy heap where a foreign
 * connection's secrets sit a few hundred bytes away — a nearby stray secret will
 * not fall at BOTH offsets. Each connection keeps several copies of its triple;
 * every copy is the same connection, and emitting in address order lets the
 * lowest-address copy stamp its three siblings first (the offline side dedupes on
 * (kind,secret) and keeps that first group). An anchor that is part of no triple
 * gets NO group — it cannot help elimination and must not invent an id. A 2nd
 * safety net backs this: the offline correlator discards any group whose placed
 * app secrets decrypt different streams, so a mis-grouped triple can only FAIL to
 * place the exporter, never place it on the wrong stream.
 *
 * Per-suite: static RE (dev/windows_re/verify_kit/STATIC_RE_FINDINGS.md) shows the
 * triple is NOT one struct but three separate heap allocations, so the offsets are
 * cipher-size dependent. Each base's offsets come from group.by_cipher[cipherId]
 * (cipher read at anchor+cipher_at) and fall back to client_off/exporter_off (the
 * SHA384-measured default) when the suite is unlisted — a wrong fallback offset
 * simply fails the geometry test and yields no group, never a wrong one. */
function pickGroupOffsets(cipher, g) {
    if (cipher !== null && g.by_cipher) {
        var e = g.by_cipher['0x' + cipher.toString(16)];
        if (e && typeof e.client_off === 'number' && typeof e.exporter_off === 'number')
            return { c: e.client_off, x: e.exporter_off };
    }
    return { c: g.client_off, x: g.exporter_off };          // default (TLS_AES_256_GCM_SHA384)
}

/* Reject a pairing only when BOTH cipher ids are known and differ (blocks a
 * cross-suite false triple on a busy heap); an unknown cipher never blocks a
 * pairing, so the verified single-suite grouping is preserved unchanged. */
function sameCipher(a, b) {
    return a.cipher === null || b.cipher === null || a.cipher === b.cipher;
}

function assignSchannelGroups(found, g) {
    found.sort(function (a, b) { return a.addr.compare(b.addr); });
    var byAddr: any = {};
    for (var i = 0; i < found.length; i++) byAddr[found[i].addr.toString()] = found[i];
    for (var i = 0; i < found.length; i++) {
        var base = found[i];
        var off = pickGroupOffsets(base.cipher, g);        // per-suite offsets (default = SHA384)
        var cli = byAddr[base.addr.add(off.c).toString()];
        var exp = byAddr[base.addr.add(off.x).toString()];
        if (cli !== undefined && exp !== undefined          // a full SRV/CLI/EXP triple ...
            && sameCipher(base, cli) && sameCipher(base, exp)) {   // ... of one cipher suite
            var gid = base.addr.toString();                // group = SERVER (lowest) anchor
            base.group = gid; cli.group = gid; exp.group = gid;
        }
    }
}

/* TLS 1.3 secret tier — anchor on the '3lss' container tag (either byte order),
 * read secret_lens bytes at 3lss+secret_at, keep it if it passes the validators.
 * Collect every validated secret first, derive each one's connection group from
 * the fixed secret-block geometry (see assignSchannelGroups), then emit UNPAIRED in address
 * order so a connection's lowest (primary) cluster stamps its three siblings with
 * one group before any duplicate copy — the offline side dedupes on (kind,secret)
 * and keeps that first group, keeping all three siblings consistent. */
function runSchannelTls13Secret(ranges, stats, errors) {
    var tier = (schannelResolved().tiers || {}).tls13_secret;
    if (!tier || !tier.enabled) return;
    var hyp = tier.hypothesis || {};
    var anchor = tier.anchor_tag || '3lss';
    var sizeAt = (typeof tier.size_at === 'number') ? tier.size_at : -1;
    var secretAt = chainOffset(tier.secret_at !== undefined ? tier.secret_at : hyp.secret_at, 0x6a);
    var lens = tier.secret_lens || [48, 32];
    var g = tier.group || {};
    var doGroup = g.enabled === true && typeof g.client_off === 'number' && typeof g.exporter_off === 'number';
    var cipherAt = (typeof g.cipher_at === 'number') ? g.cipher_at : 8;   // suite id offset from anchor
    // Per-suite secret length: the secret is 48 bytes for SHA384 suites (0x1302)
    // but 32 for SHA256 suites (0x1301/0x1303). The old fixed-order [48,32] trial
    // emitted a WRONG 48-byte secret for a 32-byte suite (32 real bytes + 16 trailing
    // heap bytes passes the entropy/zero-fraction gate, shadowing the correct 32-byte
    // read), so the length must be chosen by the cipher id at anchor+cipher_at. An
    // unlisted cipher falls back to the [48,32] trial (the verified SHA384 behavior).
    var lenByCipher = tier.secret_len_by_cipher || {};
    var sslVersion = 772;   // TLS 1.3, for the report
    var patterns = [asciiToScanPattern(anchor), asciiToScanPattern(reverseStr(anchor))];
    var found: any[] = [];
    for (var p = 0; p < patterns.length; p++) {
        for (var r = 0; r < ranges.length; r++) {
            var hits = scanRange(ranges[r], patterns[p], errors);
            for (var h = 0; h < hits.length; h++) {
                stats.schannel.tls13Candidates++;
                try {
                    var anchorAddr = hits[h].address;
                    var cipherId = readU32OrNull(anchorAddr.add(cipherAt));
                    var lenForCipher = (cipherId !== null) ? lenByCipher['0x' + cipherId.toString(16)] : undefined;
                    var declared = (sizeAt >= 0) ? readU32OrNull(anchorAddr.add(sizeAt)) : null;
                    var tryLens = (typeof lenForCipher === 'number') ? [lenForCipher]
                                : (declared === 32 || declared === 48) ? [declared] : lens;
                    for (var li = 0; li < tryLens.length; li++) {
                        var secret = readBytes(anchorAddr.add(secretAt), tryLens[li]);
                        if (!schannelLooksLikeSecret(secret)) continue;
                        found.push({ addr: anchorAddr, secret: hexBytes(secret),
                                     cipher: (typeof cipherId === 'number' ? cipherId : null), group: null });
                        break;
                    }
                } catch (e: any) {
                    errors.push('schannel tls13 ' + hits[h].address + ': ' + e.message);
                }
            }
        }
    }
    // Derive per-connection groups by the fixed secret-block geometry (no reverse
    // scan needed — a per-suite address-set membership test at two offsets).
    if (doGroup) {
        assignSchannelGroups(found, g);
    }
    for (var f = 0; f < found.length; f++) {
        emitSchannelUnpaired('schannel_tls13_secret', found[f].addr, found[f].secret,
                             sslVersion, stats, found[f].group);
    }
}

export const SchannelEngine: MemscanEngine = {
    name: 'schannel',
    runTiers: function (ranges: any, stats: any, errors: string[]): void {
        ensureSchannelResolved();
        stats.schannel = {
            tls12Candidates: 0, tls13Candidates: 0, cacheItems: 0,
            sessionCacheEmitted: 0, sessionCacheDumped: 0
        };
        var ssl5s = [];
        runSchannelTls12Master(ranges, stats, errors, ssl5s);
        runSchannelSessionCache(ranges, stats, errors, ssl5s);
        runSchannelTls13Secret(ranges, stats, errors);
    }
};
registerEngine(SchannelEngine);
