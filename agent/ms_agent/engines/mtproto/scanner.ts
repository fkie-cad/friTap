import { mtstate } from "./mtstate.js";
import { readConnectionEndpoint } from "./endpoint.js";

/* Operational caps: about how much WORK a scan may do, not about the target's
 * layout, which is why they live here and not in the JSON. Both can still be
 * overridden from the profile. The hit cap's real semantics are documented at
 * scanRange(), which is where it is applied. */
var DEFAULT_MAX_HITS_PER_SCAN = 200000;
var DEFAULT_TIER_D_MAX_WINDOWS = 200000;

function hex(u) {
    var s = '';
    for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16);
    return s;
}

/* Memory.scanSync wants the bytes space-separated; that is the only difference
 * from a plain hex string, so every needle is built from one. */
function hexToScanPattern(h) {
    return h.match(/../g).join(' ');
}

/* Every read of target memory goes through one of these four and returns null on
 * a fault: a candidate address is an integer we guessed at, so a failing read is
 * the normal case, not the exceptional one. */
function readBuffer(addr, len) {
    try { return addr.readByteArray(len); } catch (e: any) { return null; }
}

function readPointerOrNull(addr) {
    try { return addr.readPointer(); } catch (e: any) { return null; }
}

function readS32OrNull(addr) {
    try { return addr.readS32(); } catch (e: any) { return null; }
}

/* UNSIGNED, because the one caller compares it against the low 32 bits of an
 * address: a compressed ART reference to an object at 0x82000000 reads as a
 * negative int32 and would never equal a masked address. */
function readU32OrNull(addr) {
    try { return addr.readU32(); } catch (e: any) { return null; }
}

/* Pointer arithmetic by a SIGNED profile offset — several are negative (an
 * EncryptedChat's reference slots sit ahead of the field the scan finds), and
 * NativePointer.add(-n) is the one operation whose behaviour differs between
 * Frida versions and between the 32- and 64-bit paths. */
function shift(p, delta) {
    return delta < 0 ? p.sub(-delta) : p.add(delta);
}

/* A small histogram keyed by a number, used for the "which candidate offset
 * worked" counters. Keys are stringified: a retarget is visible as
 * dataOffsetHits {"8": 0, "12": 31} in the funnel rather than as silence. */
function countBy(map, key) {
    var name = String(key);
    map[name] = (map[name] || 0) + 1;
}

function log(level, msg) {
    send({ type: 'log', level: level, msg: msg });
}

/* The scan is read-only and every read is guarded, so a faulting page surfaces in
 * JS as a caught exception, not here. This handler exists purely for diagnostics
 * about faults raised on the TARGET's own threads; it returns false so the app
 * keeps its normal crash semantics — swallowing those would resume the faulting
 * instruction forever.
 *
 * Idempotent: configure() calls it, and Process.setExceptionHandler STACKS
 * handlers, so a second configure() would otherwise double-count every fault. */
function installExceptionHandler() {
    if (mtstate.handlerInstalled) return;
    mtstate.handlerInstalled = true;
    Process.setExceptionHandler(function (details) {
        mtstate.faults++;
        if (mtstate.faults <= 3) log('warn', 'native fault ' + details.type + ' at ' + details.address);
        return false;
    });
}

/* ---------------------------------------------------------------------------
 * Validators. Each one answers a single question about a candidate, and each one
 * exists because a specific class of false positive was observed on the target.
 * ------------------------------------------------------------------------- */

function parseValidators(v) {
    return {
        minEntropyBits: v.min_shannon_entropy_bits,
        maxEntropyBits: v.max_shannon_entropy_bits,
        minDistinctBytes: v.min_distinct_bytes,
        maxDistinctBytes: v.max_distinct_bytes,
        maxZeroFraction: v.max_zero_fraction,
        pointerMin: ptr(v.pointer_min),
        tagMask: ptr(v.pointer_tag_mask)
    };
}

/* ARM64 top-byte-ignore: heap pointers can carry a tag in bits 56-63. Dereferences
 * work through the tag, but any range lookup or pointer COMPARISON must untag —
 * Tier B's whole precision argument is a pointer comparison. */
function untag(p) {
    return p.and(mtstate.validators.tagMask);
}

/* Pointer arithmetic, not a hex-string round trip: this runs once per raw anchor
 * hit (~188k per Tier A pass). `alignment` is a power of two in every profile,
 * which is what makes the mask equivalent to the modulo. */
function isAligned(p, alignment) {
    if (!alignment) return true;
    return untag(p).and(alignment - 1).isNull();
}

/* ---------------------------------------------------------------------------
 * Mapped-address index. Process.findRangeByAddress costs milliseconds per call
 * and Tier A asks once per aligned anchor hit; one snapshot plus a binary search
 * answers the identical predicate far cheaper. Rebuilt every pass, because a
 * stale index rejects live pointers and that is a recall loss.
 * ------------------------------------------------------------------------- */

/* Interval endpoints are compared as Numbers, not NativePointers, because that is
 * what makes the binary search cheap. Userspace addresses on this target are
 * ~0x7xxxxxxxxx (39 significant bits) and the largest conceivable mapping end is
 * far below 2^53, so every value here is an exact integer and nothing is lost. */
function addressToNumber(p) {
    return parseInt(p.toString(16), 16);
}

/* Generic sorted-interval lookup, shared by the mapped-range index and the
 * /proc/self/maps name index. Returns the matching entry or null. Entries are
 * [start, end, payload] with a half-open [start, end). */
function findInterval(index, address) {
    if (index === null || index.length === 0) return null;
    var lo = 0, hi = index.length - 1;
    while (lo <= hi) {
        var mid = (lo + hi) >> 1;
        if (address < index[mid][0]) hi = mid - 1;
        else if (address >= index[mid][1]) lo = mid + 1;
        else return index[mid];
    }
    return null;
}

function buildMappedRangeIndex(ranges) {
    var index = new Array(ranges.length);
    for (var i = 0; i < ranges.length; i++) {
        var start = addressToNumber(ranges[i].base);
        index[i] = [start, start + ranges[i].size, null];       // half-open [start, end)
    }
    index.sort(function (a, b) { return a[0] - b[0]; });
    return index;
}

function isMappedAddress(untagged) {
    /* Before the first scanOnce() there is no snapshot yet; fall back to the slow
     * lookup so the predicate is never weaker than the one it replaced. */
    if (mtstate.mappedRanges === null) return Process.findRangeByAddress(untagged) !== null;
    return findInterval(mtstate.mappedRanges, addressToNumber(untagged)) !== null;
}

/* Freed scudo slots are poisoned and uninitialised storage is stale garbage, so
 * "is this address mapped" is the cheapest way to reject a field that only looks
 * like a pointer. */
function looksLikeHeapPointer(p) {
    if (p === null || p.isNull()) return false;
    var u = untag(p);
    if (u.compare(mtstate.validators.pointerMin) < 0) return false;
    return isMappedAddress(u);
}

/* ---------------------------------------------------------------------------
 * Entropy gate. A WINDOW, not a floor, and BOTH ceilings are load-bearing. The
 * four numbers are DERIVED, not fitted — see the profile's _validators_derivation.
 *
 * It is a PERFORMANCE prefilter for the SHA1 oracle, never a correctness check,
 * but the cost of a false positive is NOT uniform and this is no licence to widen
 * the window: Tier D pays one SHA1, Tier A pays a full native-range sweep per
 * survivor (it becomes a Tier B needle) and Tier C a full-heap sweep per surviving
 * group. Widening re-enters the ANR regime. A false negative silently loses a key,
 * which is why the thresholds are as loose as the derivation allows.
 * ------------------------------------------------------------------------- */

/* Shannon entropy in bits per byte, from an existing histogram. Key material sits
 * in a narrow band below 8; ASCII text, repeated structures and pointer arrays sit
 * far below it, and a lookup table sits exactly AT it. */
function shannonEntropyBits(counts, total) {
    var bits = 0, p;
    for (var i = 0; i < 256; i++) {
        if (counts[i] === 0) continue;
        p = counts[i] / total;
        bits -= p * (Math.log(p) / Math.LN2);
    }
    return bits;
}

/* One reused histogram. secretStats() runs tens of thousands of times per Tier C
 * pass, and a fresh 256-element array per call is tens of MB of allocation churn
 * inside the app this agent is trying not to ANR. Single-threaded by construction,
 * and never held across a call. */
var BYTE_COUNTS = new Array(256);

/* The single per-secret gate, and deliberately the ONLY way a blob becomes a
 * candidate in ANY tier. Returns {bits, distinct, zeros} or null. The order is for
 * speed, not for the verdict: the integer tests reject almost everything, so the
 * Shannon sum — up to 256 Math.log calls — runs only on what survives them. */
function secretStats(u8, expectedLength) {
    if (u8.length !== expectedLength) return null;
    var v = mtstate.validators;
    var counts = BYTE_COUNTS, i, distinct = 0;
    for (i = 0; i < 256; i++) counts[i] = 0;
    for (i = 0; i < u8.length; i++) counts[u8[i]]++;
    for (i = 0; i < 256; i++) if (counts[i] !== 0) distinct++;
    if (distinct < v.minDistinctBytes || distinct > v.maxDistinctBytes) return null;
    var zeros = counts[0] / u8.length;
    if (zeros > v.maxZeroFraction) return null;
    var bits = shannonEntropyBits(counts, u8.length);
    if (bits < v.minEntropyBits || bits > v.maxEntropyBits) return null;
    return { bits: bits, distinct: distinct, zeros: zeros };
}

/* The oracle. Checksum.compute returns lowercase hex, and the id is the LAST
 * auth_key_id_len bytes of the digest — the low 64 bits MTProto puts in every
 * record header. */
function sha1LowId(buf) {
    var digest = Checksum.compute('sha1', buf);
    return digest.slice(-(mtstate.profile.constants.auth_key_id_len * 2));
}

/* ---------------------------------------------------------------------------
 * /proc/self/maps name index.
 *
 * DEFECT (a), measured: /proc/self/maps zero-pads start addresses ("02000000")
 * while NativePointer.toString(16) does not ("2000000"). A name lookup keyed by
 * hex STRING therefore silently drops the 512 MiB [anon:dalvik-main space] — the
 * ONE region with a leading zero, and the ONE region that holds every Secret-Chat
 * key. This index is therefore keyed by NUMERIC interval and searched, never by
 * string equality. Do not "simplify" it back into a dictionary.
 *
 * maps is consulted for NAMES only: Frida's enumerateRanges does not carry the
 * kernel's [anon:<label>] annotations, and without them no allowlist can match.
 * ------------------------------------------------------------------------- */

function loadMapsIndex() {
    var text;
    try {
        text = File.readAllText('/proc/self/maps');
    } catch (e: any) {
        mtstate.mapsIndex = [];
        log('warn', 'cannot read /proc/self/maps (' + e.message + '); range names are ' +
                    'unavailable, so both name lists match nothing this scan');
        return;
    }
    /* "02000000-22000000 rw-p 00000000 00:00 0    [anon:dalvik-main space]" */
    var lines = text.split('\n'), out = [], i, m;
    for (i = 0; i < lines.length; i++) {
        m = /^([0-9a-f]+)-([0-9a-f]+) \S+ \S+ \S+ \S+\s*(.*)$/.exec(lines[i]);
        if (m === null) continue;
        out.push([parseInt(m[1], 16), parseInt(m[2], 16), (m[3] || '').trim()]);
    }
    out.sort(function (a, b) { return a[0] - b[0]; });
    mtstate.mapsIndex = out;
}

function labelAt(address) {
    var entry = findInterval(mtstate.mapsIndex, address);
    return entry === null ? '' : entry[2];
}

function rangeLabel(range) {
    /* The kernel's annotation is the more specific of the two and is the only one
     * that can say "dalvik-main space", so it wins over Frida's file path. */
    return labelAt(addressToNumber(range.base)) || (range.file ? range.file.path : '');
}

/* Both sides are lower-cased. The kernel, Frida and the profile each pick their
 * own case, and a denylist that matches only by accident of case is a denylist
 * that silently lets memory through. */
function matchesAny(label, needles) {
    if (!needles || needles.length === 0) return false;
    var haystack = label.toLowerCase();
    for (var i = 0; i < needles.length; i++) {
        if (haystack.indexOf(needles[i].toLowerCase()) !== -1) return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Agent-owned ranges — an ADDRESS-based exclusion, and it cannot be left to
 * name_denylist: when /proc/self/maps is unreadable every rangeLabel() is '', so
 * BOTH name lists match nothing and selectRanges() widens to a much larger set
 * that includes Frida's own QuickJS heap. Module bases and sizes do not depend on
 * a name being available, so this exclusion cannot switch itself off.
 * ------------------------------------------------------------------------- */

var AGENT_MODULE_PATTERNS = [/frida/i, /gum-js-loop/i, /quickjs/i];

function looksAgentOwned(text) {
    if (!text) return false;
    for (var i = 0; i < AGENT_MODULE_PATTERNS.length; i++) {
        if (AGENT_MODULE_PATTERNS[i].test(text)) return true;
    }
    return false;
}

function buildAgentOwnedRanges() {
    var owned = [];
    try {
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var m = modules[i];
            if (looksAgentOwned(m.name) || looksAgentOwned(m.path)) {
                owned.push({ base: m.base, end: m.base.add(m.size) });
            }
        }
    } catch (e: any) {
        log('warn', 'enumerateModules failed (' + e.message + '); the agent\'s own ' +
                    'ranges cannot be excluded by address this scan');
    }
    return owned;
}

/* Overlap, not containment: one reservation can straddle a module. */
function isAgentOwnedRange(range, owned) {
    var end = range.base.add(range.size);
    for (var i = 0; i < owned.length; i++) {
        if (range.base.compare(owned[i].end) < 0 && owned[i].base.compare(end) < 0) return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Per-pass snapshot. Mappings come and go, so this MUST be rebuilt once per pass
 * — but it used to be built three times WITHIN one, plus the modules twice. One
 * snapshot, filtered per caller, is the same answer for a third of the work.
 * ------------------------------------------------------------------------- */

function beginPass() {
    loadMapsIndex();
    return {
        /* protection '---' is a minimum, not a filter: it means "every mapping",
         * including the PROT_NONE guard pages findRangeByAddress also reports. */
        ranges: Process.enumerateRanges({ protection: '---', coalesce: false }),
        owned: buildAgentOwnedRanges()
    };
}

/* Frida's own protection semantics, applied in JS to the '---' snapshot: 'r', 'w'
 * and 'x' are required in that position, '-' is don't-care. */
function protectionSatisfies(actual, required) {
    if (!required) return true;
    for (var i = 0; i < required.length; i++) {
        if (required[i] === '-') continue;
        if (!actual || actual[i] !== required[i]) return false;
    }
    return true;
}

/* Takes a scan_regions config so that Tier C can pass its OWN override (the
 * native tiers DENY dalvik; Tier C scans nothing else). */
function selectRanges(cfg, pass) {
    var all = pass.ranges, owned = pass.owned;

    /* One pass, one rangeLabel() per range: each call crosses the JS/native
     * bridge for base.toString(16), and chained filters would pay for it twice. */
    var eligible = [], allowed = [], i, r, label;
    for (i = 0; i < all.length; i++) {
        r = all[i];
        if (!protectionSatisfies(r.protection, cfg.protection)) continue;
        if (cfg.require_anonymous && r.file) continue;
        if (cfg.max_range_bytes && r.size > cfg.max_range_bytes) continue;
        if (isAgentOwnedRange(r, owned)) continue;
        label = rangeLabel(r);
        if (looksAgentOwned(label)) continue;
        if (matchesAny(label, cfg.name_denylist)) continue;
        eligible.push(r);
        if (matchesAny(label, cfg.name_allowlist)) allowed.push(r);
    }

    /* An empty allowlist result means "no names", not "no heap": Frida does not
     * expose [anon:...] names on every version/kernel combination. Falling back to
     * everything eligible keeps recall; it costs precision and time, so it is
     * loud about it. */
    if (allowed.length === 0) {
        log('warn', 'no range matched name_allowlist [' + (cfg.name_allowlist || []).join(', ') +
                    '] — range names are unavailable, which means name_denylist [' +
                    (cfg.name_denylist || []).join(', ') + '] matched nothing either. ' +
                    'Falling back to ALL ' + eligible.length + ' eligible ' + cfg.protection +
                    ' ranges, ' + totalBytes(eligible) + ' bytes now in scope; only the ' +
                    'address-based agent-module exclusion still applies.');
        return eligible;
    }
    return allowed;
}

function totalBytes(ranges) {
    var n = 0;
    for (var i = 0; i < ranges.length; i++) n += ranges[i].size;
    return n;
}

/* WHAT THE CAP ACTUALLY BOUNDS: one Memory.scanSync call — this range, this
 * pattern. It is NOT a per-scan total, despite mtstate.maxHitsPerScan's name (the
 * driver's RPC field name, which cannot be changed from here), so a pass may
 * legitimately return many times the cap across all ranges and anchors with
 * nothing truncated. The headroom argument is therefore per (range, pattern): the
 * bare length anchor's ~135k hits are 135k in ONE 202 MiB range against a 200k
 * cap. A truncation is recorded in `errors` so a capped run is never mistaken for
 * a complete one. */
function scanRange(range, pattern, errors) {
    var hits;
    try {
        hits = Memory.scanSync(range.base, range.size, pattern);
    } catch (e: any) {
        errors.push('scan ' + range.base + ': ' + e.message);
        return [];
    }
    if (hits.length > mtstate.maxHitsPerScan) {
        errors.push('hit cap ' + mtstate.maxHitsPerScan + ' reached at ' + range.base +
                    ' for pattern "' + pattern + '" (' + hits.length + ' hits) — truncated');
        hits = hits.slice(0, mtstate.maxHitsPerScan);
    }
    return hits;
}

function scanRanges(ranges, pattern, errors) {
    var hits = [], i, found, j;
    for (i = 0; i < ranges.length; i++) {
        found = scanRange(ranges[i], pattern, errors);
        for (j = 0; j < found.length; j++) hits.push(found[j].address);
    }
    return hits;
}

/* ---------------------------------------------------------------------------
 * Emission. `emittedLines` makes re-emitting an identical line a no-op;
 * `recorded` ("LABEL|key_id" -> key hex) carries the conflict rule: two DIFFERENT
 * blobs with the same SHA1-low-64 mean a 2^-64 coincidence or a corrupted read,
 * so the pair is logged and dropped. The same key CAN legitimately be emitted
 * twice under different LINES (dc_id 0 now, a probed dc_id later) — the keylog
 * joins on the id, so a better-attributed line is additive.
 * ------------------------------------------------------------------------- */

function emitKeylog(label, keyId, keyHex, line, tier, source, stats) {
    var idKey = label + '|' + keyId;
    var previous = mtstate.recorded[idKey];
    if (previous !== undefined && previous !== keyHex) {
        log('warn', 'conflict for ' + idKey + ': a different key already carries this id ' +
                    '(SHA1 collision or corrupted read) — not emitting from ' + source);
        return false;
    }
    if (mtstate.emittedLines[line] === true) return false;    // already sent, stay quiet
    mtstate.recorded[idKey] = keyHex;
    mtstate.emittedLines[line] = true;
    send({ type: 'keylog', line: line, label: label, tier: tier, keyId: keyId, source: source });
    stats.emitted++;
    return true;
}

/* MTPROTO_AUTH_KEY <dc_id> <auth_key_id_hex16> <auth_key_hex512> <perm|temp> */
function emitAuthKey(keyId, keyHex, dcId, keyType, tier, source, stats) {
    var label = mtstate.profile.tiers.B_authkeyid_roundtrip.label;
    var line = label + ' ' + dcId + ' ' + keyId + ' ' + keyHex + ' ' + keyType;
    return emitKeylog(label, keyId, keyHex, line, tier, source, stats);
}

/* MTPROTO_E2E_KEY <key_fingerprint_hex16> <shared_key_hex512> <chat_id> */
function emitE2eKey(fingerprint, keyHex, chatId, tier, source, stats) {
    var label = mtstate.profile.tiers.C_art_secretchat_key.label;
    var line = label + ' ' + fingerprint + ' ' + keyHex + ' ' + chatId;
    return emitKeylog(label, fingerprint, keyHex, line, tier, source, stats);
}

/* MTPROTO_OBF_KEY <key_out64> <iv_out32> <key_in64> <iv_in32> <num_out> <num_in> <endpoint|->
 *
 * Mirrors emitAuthKey/emitE2eKey: dedups through the same emittedLines/recorded
 * machinery so an identical Connection re-observed on a later pass is a no-op. The
 * conflict-rule key is key_out (the client->server key uniquely identifies the
 * connection's out direction); the endpoint hint is blank ("-") for now — tying a
 * recovered key to a specific 4-tuple is deferred, and the offline path joins by
 * trial de-obfuscation regardless. */
function emitObfKey(keyOutHex, ivOutHex, keyInHex, ivInHex, numOut, numIn, endpoint, tier, source, stats) {
    var label = mtstate.profile.tiers.E_connection_ctr_state.label;
    var ep = endpoint && String(endpoint).length > 0 ? endpoint : '-';
    var line = label + ' ' + keyOutHex + ' ' + ivOutHex + ' ' + keyInHex + ' ' +
               ivInHex + ' ' + numOut + ' ' + numIn + ' ' + ep;
    return emitKeylog(label, keyOutHex, keyOutHex, line, tier, source, stats);
}

/* A blob that passed every entropy check but whose id the oracle could NOT find.
 * It may still be a key (the id can live in a register or a file, or simply not be
 * materialised), but nothing proves it — so it goes to a separate report. */
function emitUnpaired(kind, keyId, candidate, tier) {
    send({
        type: 'unpaired', kind: kind, keyId: keyId,
        entropy: candidate.entropy, distinct: candidate.distinct,
        addr: candidate.keyPtr.toString(), tier: tier
    });
}

/* Attribution is only possible for a slot whose position inside its Datacenter is
 * known. Everything else — Tier A fallbacks, Tier D matches — uses the key type of
 * the FIRST role, which is the one tgnet serialises first (authKeyPerm). */
function defaultKeyType() {
    var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
    return tier.role_keylog_key_type[tier.slot_roles[0]];
}

/* ---------------------------------------------------------------------------
 * Tier A — ByteArray{length FIRST, bytes pointer SECOND}, so a ByteArray holding
 * a 256-byte key begins with the bytes 00 01 00 00: a cheap phase-1 needle, and
 * the funnel behind it measured 49510 raw -> 3560 aligned -> 862 ptrOk -> 17.
 * Emits nothing; its whole product is the auth_key_id needles Tier B confirms.
 * ------------------------------------------------------------------------- */

function processByteArrayCandidate(structBase, tier, stats) {
    var keyPtr = readPointerOrNull(structBase.add(tier.key_ptr_offset));
    if (!looksLikeHeapPointer(keyPtr)) return null;
    stats.tierA.ptrOk++;

    /* Untagged: the pointer is compared against Tier B's round-trip value and used
     * as an identity, and a tag would break both. */
    var keyAddr = untag(keyPtr);
    var buf = readBuffer(keyAddr, tier.key_len);
    if (buf === null) return null;

    var u8 = new Uint8Array(buf);
    var bstats = secretStats(u8, tier.key_len);
    if (bstats === null) return null;
    stats.tierA.entropyOk++;

    return {
        base: untag(structBase),          // the ByteArray — Tier B's round-trip target
        keyPtr: keyAddr,
        keyHex: hex(u8),
        id: sha1LowId(buf),
        entropy: bstats.bits,
        distinct: bstats.distinct,
        confirmed: false
    };
}

function runTierA(ranges, stats, errors) {
    var tier = mtstate.profile.tiers.A_bytearray_authkey;
    var candidates = [];
    if (!tier.enabled) return candidates;
    stats.tierA.state = 'ran';

    /* The anchors overlap by construction, so a struct reached twice must be
     * walked once — and iterating them in PROFILE ORDER is load-bearing: the
     * narrow, strictly redundant anchor is a safety net only if it is walked
     * before the broad scan can truncate at scanRange's hit cap. See the
     * profile's _anchor_order_note. */
    var seenStructs = {}, seenIds = {};
    for (var a = 0; a < tier.anchors.length; a++) {
        var hits = scanRanges(ranges, tier.anchors[a].pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            stats.tierA.candidates++;
            var structBase = hits[h].sub(tier.anchor_offset_in_struct);
            /* Alignment BEFORE dedup, because it rejects ~97.6% of raw anchor hits
             * (~188k -> ~4.5k measured): testing it first keeps seenStructs — and
             * the address string each entry costs — off every reject. */
            if (!isAligned(structBase, tier.require_alignment)) continue;
            var key = structBase.toString();
            if (seenStructs[key] === true) continue;
            seenStructs[key] = true;
            stats.tierA.aligned++;
            try {
                var candidate = processByteArrayCandidate(structBase, tier, stats);
                if (candidate === null) continue;
                rememberNeedle(candidate);
                /* Two ByteArrays can hold the same key (a copy in flight); scanning
                 * for the same id twice would only duplicate work. */
                if (seenIds[candidate.id] === true) continue;
                seenIds[candidate.id] = true;
                candidates.push(candidate);
            } catch (e: any) {
                errors.push('tierA ' + structBase + ': ' + e.message);
            }
        }
    }
    return candidates;
}

function rememberNeedle(candidate) {
    if (mtstate.needles[candidate.id] !== undefined) return;
    mtstate.needles[candidate.id] = {
        keyPtr: candidate.keyPtr.toString(),
        byteArray: candidate.base.toString()
    };
}

/* ---------------------------------------------------------------------------
 * Tier B — THE precision tier. A Datacenter key slot is {ByteArray *key; int64_t
 * auth_key_id;}: scan for sha1(key)[-8:] and demand that the qword just before the
 * hit points back at the very ByteArray the key was read from. Two independent
 * facts agreeing — a SHA1 the process computed and a pointer it stored — is what
 * turns a byte-pattern hit into a confirmed key. Attribution then comes from the
 * geometry: slots cluster at a uniform stride in tgnet serialisation order.
 * ------------------------------------------------------------------------- */

/* Turn auth_key_id hits into confirmed slots: a hit is a real slot only when the
 * qword just before it points back at the very ByteArray the key was read from.
 * Shared by the scoped and full-fallback scans so both apply the identical
 * round-trip test. */
function slotsFromIdHits(hits, candidate, tier, stats) {
    stats.tierB.idHits += hits.length;
    var slots = [], seenSlots = {};
    for (var h = 0; h < hits.length; h++) {
        var slot = hits[h].add(tier.roundtrip_ptr_offset);
        var back = readPointerOrNull(slot);
        if (back === null || back.isNull()) continue;
        if (!untag(back).equals(candidate.base)) continue;      // not OUR ByteArray
        var key = slot.toString();
        if (seenSlots[key] === true) continue;
        seenSlots[key] = true;
        slots.push({ addr: addressToNumber(untag(slot)), slot: slot, candidate: candidate });
    }
    return slots;
}

/* Scan the whole native set for this candidate's auth_key_id round-trip slot.
 * NOTE: a "scoped-first" variant (scan only the ByteArray's own scudo range before
 * the full set) was tried and REVERTED after Pixel 7 validation showed 0/25 scoped
 * confirmations — the referencing Datacenter object does NOT share the ByteArray's
 * scudo range on this target, so the scoped pass never hit and was pure overhead.
 * `native` is the full range set runTierB passes. */
function confirmCandidate(candidate, tier, native, stats, errors) {
    var needle = hexToScanPattern(candidate.id);
    var slots = slotsFromIdHits(scanRanges(native, needle, errors),
                                candidate, tier, stats);
    if (slots.length > 0) candidate.confirmed = true;
    return slots;
}

/* Confirmed slots within slot_group_window of each other are the key slots of ONE
 * Datacenter object. The group is capped at max_slots_per_datacenter so that a
 * dense heap cannot merge two Datacenters into one group and shift every role by
 * one — a shifted role mislabels perm as temp, which is worse than not labelling. */
function groupConfirmedSlots(slots) {
    var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
    var maxPerGroup = mtstate.profile.constants.max_slots_per_datacenter;
    slots.sort(function (a, b) { return a.addr - b.addr; });

    var groups = [], current = null;
    for (var i = 0; i < slots.length; i++) {
        var previous = current === null ? null : current[current.length - 1];
        if (previous === null ||
            slots[i].addr - previous.addr > tier.slot_group_window ||
            current.length >= maxPerGroup) {
            current = [];
            groups.push(current);
        }
        current.push(slots[i]);
    }
    return groups;
}

/* The Datacenter's own id sits somewhere ahead of its key slots. We probe
 * backwards from the first slot, NEAREST FIRST, for an aligned int32 in the
 * plausible dc range and take the first one. A fault ends the probe: it means the
 * mapping ended, and everything further back is further away still.
 *
 * MEASURED CAVEAT (tgnet 49 / Telegram 12.10.1): the probe is NOT trustworthy on
 * its own. Every 4-byte offset within +-8 KiB of the key slots -- allowing for a
 * first slot that is temp rather than perm -- yielded NO offset giving a distinct
 * id across the 8 Datacenter objects observed, so the nearest-in-range int32 is
 * frequently some other small field. Hence checkGroupDcIds(). dc_id is an
 * informational hint (friTap joins records on auth_key_id), so a truthful 0 beats
 * a confident wrong number. */
function probeDatacenterId(firstSlot) {
    var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
    var c = mtstate.profile.constants;
    for (var off = 4; off <= tier.dc_id_probe_window; off += 4) {
        var value = readS32OrNull(firstSlot.sub(off));
        if (value === null) break;
        if (value >= c.dc_id_min && value <= c.dc_id_max) return value;
    }
    return 0;
}

/* Accept the probed ids only if they are pairwise distinct. Two Datacenters
 * cannot share an id, so a duplicate proves the probe latched onto the wrong
 * field -- and then NONE of the values can be trusted, not just the duplicates. */
function checkGroupDcIds(groups) {
    var ids = [], seen = {}, i, value;
    for (i = 0; i < groups.length; i++) {
        value = probeDatacenterId(groups[i][0].slot);
        ids.push(value);
        if (value !== 0 && seen[value]) {
            log('warn', 'dc_id probe produced duplicate id ' + value +
                ' across Datacenter groups; reporting dc_id 0 for all of them ' +
                '(the id is an informational hint and is not used for decryption)');
            return null;
        }
        seen[value] = true;
    }
    return ids;
}

/* Remember a confirmed auth key so an INCREMENTAL pass can re-emit it without a
 * heap sweep (see revalidateConfirmed). Keyed by id; the slot addresses accumulate
 * because one ByteArray can be referenced from more than one Datacenter slot, and
 * revalidation only needs ONE of them to still round-trip. */
function rememberConfirmedAuthKey(candidate, slotPtr, dcId, keyType) {
    var entry = mtstate.confirmedAuthKeys[candidate.id];
    if (entry === undefined) {
        entry = {
            id: candidate.id,
            byteArray: candidate.base.toString(),
            keyPtr: candidate.keyPtr.toString(),
            keyHex: candidate.keyHex,
            slots: [],
            dcId: dcId,
            keyType: keyType
        };
        mtstate.confirmedAuthKeys[candidate.id] = entry;
    }
    var s = untag(slotPtr).toString();
    if (entry.slots.indexOf(s) === -1) entry.slots.push(s);
}

function emitDatacenterGroup(group, dcId, stats) {
    var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
    for (var i = 0; i < group.length; i++) {
        /* Defensive: groups are capped at slot_roles.length, so this cannot run off
         * the end unless the profile's constants and roles disagree. */
        var role = tier.slot_roles[i] || tier.slot_roles[tier.slot_roles.length - 1];
        var candidate = group[i].candidate;
        var keyType = tier.role_keylog_key_type[role];
        emitAuthKey(candidate.id, candidate.keyHex, dcId, keyType,
                    'B', role + '@' + group[i].slot, stats);
        rememberConfirmedAuthKey(candidate, group[i].slot, dcId, keyType);
    }
}

function runTierB(ranges, candidates, stats, errors) {
    var tier = mtstate.profile.tiers.B_authkeyid_roundtrip;
    if (!tier.enabled) return;
    stats.tierB.state = 'ran';

    var confirmed = [];
    for (var i = 0; i < candidates.length; i++) {
        stats.tierB.needles++;
        try {
            Array.prototype.push.apply(
                confirmed, confirmCandidate(candidates[i], tier, ranges, stats, errors));
        } catch (e: any) {
            errors.push('tierB ' + candidates[i].keyPtr + ': ' + e.message);
        }
    }
    stats.tierB.confirmed += confirmed.length;

    var groups = groupConfirmedSlots(confirmed);
    var dcIds = checkGroupDcIds(groups);
    for (var g = 0; g < groups.length; g++) {
        try { emitDatacenterGroup(groups[g], dcIds === null ? 0 : dcIds[g], stats); }
        catch (e: any) { errors.push('tierB group ' + groups[g][0].slot + ': ' + e.message); }
    }
}

/* Unconfirmed means "the oracle did not close", not "not a key". Reported, never
 * emitted — unless the driver explicitly asked for the lossy behaviour. */
function reportUnconfirmed(candidates, stats) {
    for (var i = 0; i < candidates.length; i++) {
        var candidate = candidates[i];
        if (candidate.confirmed) continue;
        if (mtstate.emitUnconfirmed) {
            emitAuthKey(candidate.id, candidate.keyHex, 0, defaultKeyType(),
                        'A', 'unconfirmed', stats);
        } else {
            emitUnpaired('authkey_unconfirmed', candidate.id, candidate, 'A');
        }
    }
}

/* ---------------------------------------------------------------------------
 * Tier C — Secret-Chat (E2EE) keys on the ART heap.
 *
 * Same oracle, different container. An ART byte[] is {klass u32 @0, monitor u32 @4,
 * length u32 @8, data @12}, so a byte[256] with an unlocked monitor reads
 * 00 00 00 00 | 00 01 00 00 at +4 — anchoring on monitor AND length cuts the hit
 * count ~5x versus length alone. It uses its OWN scan_regions: the native tiers
 * DENY dalvik, and the dalvik spaces are the only place a Secret-Chat key exists.
 *
 * Android's concurrent mark-compact collector keeps the object graph at TWO
 * addresses at once, and each EncryptedChat copy references the byte[] next to IT.
 * A fingerprint scan therefore returns a PAIR of sites, each closing only against
 * its own copy's base — so phase 1 must keep BOTH copies and phase 2 must test the
 * full cross product. Splitting the phases also removes the redundant 3.7 GiB
 * sweeps a per-hit scan performed, which is this tier's dominant cost.
 * ------------------------------------------------------------------------- */

function readSecretChatId(fingerprintSite) {
    /* EncryptedChat offsets are relative to key_fingerprint, because that field is
     * what the scan actually finds. chat_id is a hint, so 0 is a valid answer. */
    var off = mtstate.profile.struct_offsets.EncryptedChat;
    var chatId = readS32OrNull(shift(fingerprintSite.sub(off.key_fingerprint), off.chat_id));
    return chatId === null ? 0 : chatId;
}

function isNonEmptyArray(value) {
    return Object.prototype.toString.call(value) === '[object Array]' && value.length > 0;
}

/* An ordered candidate list, or the single scalar when the profile predates it.
 * The list exists because a scalar alone fails SILENTLY: on a build whose ART
 * object header is a different size every read lands off the key and the tier
 * reports zero — indistinguishable from "this account has no Secret Chats". */
function offsetsOrScalar(list, scalar) {
    if (isNonEmptyArray(list)) return list;
    return typeof scalar === 'number' ? [scalar] : [];
}

/* Key-data offsets. The scalar spelling stays required in the profile (a
 * derived-offset validator terminates on it), so both are accepted. */
function artDataOffsets(tier) {
    return offsetsOrScalar(tier.key_data_offset_candidates_from_anchor,
                           tier.key_data_offset_from_anchor);
}

/* The ART back-reference offsets, candidate list only — its presence is a
 * configure() precondition, see checkArtRefOffsets(). */
function artRefOffsets() {
    var off = mtstate.profile.struct_offsets.EncryptedChat;
    return isNonEmptyArray(off.auth_key_ref_candidates) ? off.auth_key_ref_candidates : [];
}

/* An object base plus the 32-bit value a stored reference to it would carry.
 * `decodable` is false when the base does not fit in 32 bits: on the measured
 * build object_base >> 32 == 0, so a reference is just the truncated address, but
 * on a build mapping the ART heap higher the truncation is AMBIGUOUS and the
 * honest answer is "this check does not apply", not "the round trip failed". */
function describeArtBase(artBase) {
    var untagged = untag(artBase);
    var address = addressToNumber(untagged);
    return {
        ptr: untagged,
        low32: (address % 4294967296) >>> 0,
        decodable: Math.floor(address / 4294967296) === 0
    };
}

/* Candidate offsets closer together than key_len read OVERLAPPING windows (8 and
 * 12 share 252 of their 256 bytes), so one span read serves them all instead of a
 * full re-read per candidate. Returns {buf, lo} or null; the caller falls back to
 * per-offset reads, because the span is wider than any single window and can
 * therefore fault where a window would not. */
function readOffsetSpan(hit, offsets, len) {
    var lo = offsets[0], hi = offsets[0], i;
    for (i = 1; i < offsets.length; i++) {
        if (offsets[i] < lo) lo = offsets[i];
        if (offsets[i] > hi) hi = offsets[i];
    }
    var buf = readBuffer(shift(hit, lo), (hi - lo) + len);
    return buf === null ? null : { buf: buf, lo: lo };
}

/* Phase 1. One anchor hit -> at most one entry in the fingerprint groups. */
function processArtCandidate(hit, tier, stats, groups) {
    var artBase = hit.sub(tier.anchor_offset_in_struct);
    if (!isAligned(artBase, tier.require_alignment)) return;

    /* Offsets are FROM THE HIT, not from the object base. Candidates are tried IN
     * ORDER, the first blob passing the entropy gate wins, and which one won is
     * counted — that is what makes a changed ART header size visible in the funnel
     * instead of silent. Adjacent candidates shadow each other, so for those the
     * list buys diagnosis rather than recovery: profile _key_data_offset_note. */
    var offsets = artDataOffsets(tier);
    var span = readOffsetSpan(hit, offsets, tier.key_len);
    for (var i = 0; i < offsets.length; i++) {
        var buf = span === null
            ? readBuffer(shift(hit, offsets[i]), tier.key_len)
            : span.buf.slice(offsets[i] - span.lo, offsets[i] - span.lo + tier.key_len);
        if (buf === null) continue;

        var u8 = new Uint8Array(buf);
        var bstats = secretStats(u8, tier.key_len);
        if (bstats === null) continue;
        stats.tierC.entropyOk++;
        countBy(stats.tierC.dataOffsetHits, offsets[i]);
        rememberArtGroup(groups, sha1LowId(buf), u8, shift(hit, offsets[i]), artBase, bstats);
        return;
    }
}

/* Group by fingerprint, keep every DISTINCT object base under it.
 *
 * Keeping every base is the whole point: the two GC copies of one EncryptedChat
 * hold the same key, so they share a fingerprint, and the site that closes is
 * whichever one sits next to the copy being tested. Dropping the second copy here
 * is what made the round trip look broken. */
function rememberArtGroup(groups, fingerprint, u8, keyAddr, artBase, bstats) {
    var group = groups[fingerprint];
    if (group === undefined) {
        group = {
            fingerprint: fingerprint,
            keyHex: hex(u8),
            bases: [],
            seenBases: {},
            candidate: { keyPtr: keyAddr, entropy: bstats.bits, distinct: bstats.distinct }
        };
        groups[fingerprint] = group;
    }
    var key = untag(artBase).toString();
    if (group.seenBases[key] === true) return;
    group.seenBases[key] = true;
    group.bases.push(describeArtBase(artBase));
}

/* The round trip for ONE site, against ALL of this fingerprint's bases. It adds
 * nothing to the ~2^-64 SHA1 argument; what it buys is a second independent fact
 * tying the site to THIS key's container, hence trustworthy chat_id attribution
 * — see the profile's _art_ref_note. An ART built with heap poisoning stores the
 * negation of the address, so -value is compared too when the profile allows. */
function closeArtRoundTrip(site, bases, offsets, tier) {
    var acceptPoisoned = tier.art_ref_accept_poisoned !== false;
    for (var i = 0; i < offsets.length; i++) {
        var value = readU32OrNull(shift(site, offsets[i]));
        if (value === null) continue;
        var negated = (-value) >>> 0;
        for (var b = 0; b < bases.length; b++) {
            if (!bases[b].decodable) continue;
            if (value === bases[b].low32) {
                return { offset: offsets[i], poisoned: false, base: bases[b] };
            }
            if (acceptPoisoned && negated === bases[b].low32) {
                return { offset: offsets[i], poisoned: true, base: bases[b] };
            }
        }
    }
    return null;
}

function anyBaseIsDecodable(bases) {
    for (var i = 0; i < bases.length; i++) if (bases[i].decodable) return true;
    return false;
}

/* EVERY site is tested, not just up to the first that closes: with two GC copies
 * alive BOTH close, and a count that stopped early would hide the pairing this
 * tier depends on. The first closing site wins the chat_id read — sites come back
 * in address order, so the choice is deterministic and does not depend on which
 * copy phase 1 walked first. */
function testArtSites(sites, group, offsets, tier, stats) {
    var match = null, chosen = null;
    for (var s = 0; s < sites.length; s++) {
        stats.tierC.sitesTested++;
        var closed = closeArtRoundTrip(sites[s], group.bases, offsets, tier);
        if (closed === null) continue;
        stats.tierC.roundTrips++;
        if (closed.poisoned) stats.tierC.roundTripsPoisoned++;
        countBy(stats.tierC.roundTripByOffset, closed.offset);
        if (match !== null) continue;
        match = closed;
        chosen = sites[s];
    }
    return { match: match, chosen: chosen };
}

/* Phase 2. ONE fingerprint scan per key, then the full site x base cross product.
 * The round trip GRADES the evidence and never gates emission — a key that fails
 * it is still confirmed by the oracle, and dropping it would be a recall
 * regression. It only picks WHICH site chat_id is read from (the closing one, else
 * sites[0]) and what `source` says, so a line carries its own evidence level. */
function confirmArtGroup(group, tier, ranges, stats, errors) {
    var sites = scanRanges(ranges, hexToScanPattern(group.fingerprint), errors);
    if (sites.length === 0) {
        if (mtstate.emitUnconfirmed) {
            emitE2eKey(group.fingerprint, group.keyHex, 0, 'C', 'unconfirmed', stats);
        } else {
            emitUnpaired('e2e_unconfirmed', group.fingerprint, group.candidate, 'C');
        }
        return;
    }
    stats.tierC.confirmed++;

    /* Three states, not two: the check can be switched off, it can RUN, or it can
     * be INAPPLICABLE on this build. "Inapplicable" must not read as "failed" — a
     * base above 32 bits makes the truncation ambiguous, and a profile that states
     * no reference offset asks no question. Both are recorded as a skipped check
     * with its reason, never as a key whose round trip did not close. */
    var roundTrip = tier.art_ref_roundtrip !== false;
    var offsets = artRefOffsets();
    var skipReason = null;
    if (roundTrip) {
        if (offsets.length === 0) skipReason = 'no-ref-offset-in-profile';
        else if (!anyBaseIsDecodable(group.bases)) skipReason = 'base-above-32-bit';
    }
    var chosen = sites[0], match = null;

    if (roundTrip && skipReason === null) {
        var tested = testArtSites(sites, group, offsets, tier, stats);
        match = tested.match;
        if (tested.chosen !== null) chosen = tested.chosen;
    }

    var source = 'fingerprint@' + chosen;
    if (!roundTrip) {
        /* The check is switched off in the profile: say nothing about evidence
         * that was never gathered. */
    } else if (skipReason !== null) {
        stats.tierC.refCheckSkipped++;
        source += ' ref-check-skipped(' + skipReason + ')';
    } else if (match !== null) {
        source += ' +ref@' + match.offset + (match.poisoned ? '(poisoned)' : '');
    } else {
        stats.tierC.colocatedOnly++;
        source += ' colocated-only';
    }
    emitE2eKey(group.fingerprint, group.keyHex, readSecretChatId(chosen), 'C', source, stats);
}

/* LEGACY, kept only as the fallback for a profile that carries no
 * min_rescan_interval_ms — shouldRunTierCNow() is what decides today. A pass COUNT
 * silently couples E2EE coverage to --interval: the same rescan_every 4 is a Tier
 * C pass every 20 s at --interval 5 and every 4 minutes at --interval 60. */
function shouldRunTierC(tier) {
    var every = tier.rescan_every;
    if (every === undefined || every === null || every < 1) return true;
    return (mtstate.scanIndex % every) === 0;
}

/* The throttle in effect. Returns null to run, or the reason it was skipped.
 *
 * MEASURED: one Tier C pass over the ~3.7 GiB ART heap is harmless, but
 * back-to-back passes ANR'd the app — an 18 s pass on a 10 s interval leaves no
 * idle time. Secret-chat keys are long-lived, so only Tier C is throttled.
 *
 * Elapsed time since the last pass COMPLETED, not started: the ANR is about the
 * idle gap left for the app, and measuring from the start would shrink it by
 * those 18 s. 0 means every pass, and the first pass always runs (a --once run
 * must reach Secret Chats). Exactly ONE throttle applies — the pass-count branch
 * is consulted only when there is no min_rescan_interval_ms. */
function shouldRunTierCNow(tier, now) {
    var interval = tier.min_rescan_interval_ms;
    if (typeof interval === 'number' && isFinite(interval) && interval >= 0) {
        if (mtstate.tierCCompletedAt === null) return null;
        return (now - mtstate.tierCCompletedAt) >= interval ? null : 'interval';
    }
    return shouldRunTierC(tier) ? null : 'pass-count';
}

function runTierC(pass, stats, errors) {
    var tier = mtstate.profile.tiers.C_art_secretchat_key;
    if (!tier) return;
    /* "off", "throttled this pass" and "ran and found nothing" are three different
     * findings and send the reader to three different places, so the tier reports
     * which one it was rather than leaving the driver to infer it. */
    stats.tierC.enabled = tier.enabled === true;
    if (!stats.tierC.enabled) return;

    var reason = shouldRunTierCNow(tier, Date.now());
    if (reason !== null) {
        stats.tierC.state = 'throttled';
        stats.tierC.skipped = true;
        stats.tierC.throttledBy = reason;
        return;
    }
    stats.tierC.state = 'ran';
    var ranges = selectRanges(tier.scan_regions || mtstate.profile.scan_regions, pass);

    // --- phase 1: anchor hits -> object bases grouped by fingerprint ---------
    var groups = {};
    for (var a = 0; a < tier.anchors.length; a++) {
        var hits = scanRanges(ranges, tier.anchors[a].pattern, errors);
        for (var h = 0; h < hits.length; h++) {
            stats.tierC.candidates++;
            try { processArtCandidate(hits[h], tier, stats, groups); }
            catch (e: any) { errors.push('tierC ' + hits[h] + ': ' + e.message); }
        }
    }

    // --- phase 2: ONE fingerprint scan per distinct key ----------------------
    for (var fingerprint in groups) {
        if (!groups.hasOwnProperty(fingerprint)) continue;
        try { confirmArtGroup(groups[fingerprint], tier, ranges, stats, errors); }
        catch (e: any) { errors.push('tierC ' + fingerprint + ': ' + e.message); }
    }

    /* Stamped AFTER the work, because the interval throttle measures the idle gap
     * the app gets, not the gap between the moments this tier started. */
    mtstate.tierCCompletedAt = Date.now();
}

/* ---------------------------------------------------------------------------
 * Tier D — the escape hatch, for the day tgnet changes ByteArray outright. A
 * strided entropy sweep has no anchor and no round trip, so it has no oracle of
 * its own: it can only CONFIRM against ids supplied from outside. Hence
 * require_external_ids, and hence it ships disabled. It is BOUNDED rather than
 * exhaustive — a stride-8 sweep of 202 MiB is ~25M windows — so max_windows caps
 * it and the cap is reported.
 * ------------------------------------------------------------------------- */

function sweepRangeForIds(range, tier, budget, stats, errors) {
    var keyLen = tier.key_len;
    var stride = tier.stride;
    var limit = range.size - keyLen;
    for (var off = 0; off <= limit; off += stride) {
        if (budget.windows >= budget.max) {
            errors.push('tierD window cap ' + budget.max + ' reached at ' + range.base.add(off) +
                        ' — sweep truncated');
            return false;
        }
        budget.windows++;
        var addr = range.base.add(off);
        var buf = readBuffer(addr, keyLen);
        if (buf === null) continue;
        var u8 = new Uint8Array(buf);
        /* The entropy window is the prefilter: SHA1 only runs on what could be a
         * key, which is what keeps a sweep this dumb affordable at all. */
        var bstats = secretStats(u8, keyLen);
        if (bstats === null) continue;
        stats.tierD.candidates++;
        var id = sha1LowId(buf);
        if (mtstate.externalIds[id] !== true) continue;
        stats.tierD.confirmed++;
        emitAuthKey(id, hex(u8), 0, defaultKeyType(), 'D', 'sweep@' + addr, stats);
    }
    return true;
}

function runTierD(ranges, stats, errors) {
    var tier = mtstate.profile.tiers.D_entropy_sweep;
    if (!tier) return;
    stats.tierD.enabled = tier.enabled === true;
    if (!stats.tierD.enabled) return;

    if (tier.require_external_ids && countKeys(mtstate.externalIds) === 0) {
        /* Enabled but unusable: it did not run, so its zeros are not evidence
         * about the heap, which is exactly what state "off" says. */
        errors.push('tierD skipped: require_external_ids is set and configure() ' +
                    'received no externalIds');
        return;
    }
    stats.tierD.state = 'ran';
    var budget = {
        windows: 0,
        max: positiveOr(tier.max_windows, DEFAULT_TIER_D_MAX_WINDOWS)
    };
    for (var i = 0; i < ranges.length; i++) {
        try {
            if (!sweepRangeForIds(ranges[i], tier, budget, stats, errors)) return;
        } catch (e: any) {
            errors.push('tierD ' + ranges[i].base + ': ' + e.message);
        }
    }
}

/* ---------------------------------------------------------------------------
 * Tier E — per-connection obfuscated-transport CTR state (mid-stream recovery).
 *
 * ENABLED and validated on-device (Pixel 7 / libtmessages.49, 2026-09). This tier
 * recovers the live AES-256-CTR state (raw key + live 16-byte counter `ivec` +
 * byte-phase `num`) for BOTH directions of an OPEN tgnet `Connection`, and emits it
 * as MTPROTO_OBF_KEY so the offline path can de-obfuscate a Telegram connection
 * whose 64-byte init block was never captured (the connection was already open when
 * capture started).
 *
 * The struct offsets are calibrated per-profile in memory_scanning/patterns.json
 * (profile `tgnet-android-arm64-2026`; see also definitions/tgnet.ts). The tier is
 * still gated on those offsets being present: with EMPTY offsets every entry path
 * early-returns and self-reports "off" and never reads target memory — but with the
 * shipped offsets it is active. End-to-end verified: recovers mid-stream flows and
 * decrypts real messages.sendMessage payloads from a live capture.
 *
 * The Connection object MUST be ALIVE during the scan: once tgnet tears it down the
 * CTR fields are freed/reused. The anchor is the object's first qword, its C++
 * vtable pointer (`_ZTV10Connection`), resolved at configure time; the runtime
 * needle is that pointer's little-endian bytes, mirroring how Tier B needles an
 * auth_key_id.
 * ------------------------------------------------------------------------- */

/* Resolve _ZTV10Connection to a runtime address once at configure time, best
 * effort: a symbol miss (stripped build) simply leaves the tier "off". Only
 * attempted when the tier is enabled, so a disabled tier resolves nothing and
 * changes nothing. */
/* Find the loaded tgnet module (libtmessages.<n>.so) so the calibrated RVA can be
 * turned into a runtime address. The numeric soname suffix changes between builds;
 * a name/path regex tolerates that (the RVA is still build-specific — a soname the
 * profile was not calibrated against must be recalibrated). */
function findTgnetModule(tier) {
    var re;
    try { re = new RegExp(tier.module_name_regex || 'libtmessages\\.\\d+\\.so'); }
    catch (e: any) { re = /libtmessages\.\d+\.so/; }
    try {
        var mods = Process.enumerateModules();
        for (var i = 0; i < mods.length; i++) {
            if (re.test(mods[i].name) || re.test(mods[i].path)) return mods[i];
        }
    } catch (e: any) { /* fall through -> null */ }
    return null;
}

/* The tgnet module's own readable ranges (rodata + relocated .data.rel.ro live
 * here — that is where the RTTI graph and its type-name strings sit). Falls back to
 * filtering all process ranges by the module bounds if Module.enumerateRanges is
 * unavailable on this Frida build. */
function moduleReadableRanges(mod) {
    var out = [], prots = ['r--', 'r-x'], p, i;
    for (p = 0; p < prots.length; p++) {
        try {
            var rs = mod.enumerateRanges(prots[p]);
            for (i = 0; i < rs.length; i++) out.push(rs[i]);
        } catch (e: any) { /* try the next protection / the fallback below */ }
    }
    if (out.length === 0) {
        try {
            var lo = untag(mod.base), hi = lo.add(mod.size);
            var all = Process.enumerateRanges({ protection: 'r--', coalesce: false });
            for (var j = 0; j < all.length; j++) {
                var b = untag(all[j].base);
                if (b.compare(lo) >= 0 && b.compare(hi) < 0) out.push(all[j]);
            }
        } catch (e: any) { /* give up -> caller treats empty as "not found" */ }
    }
    return out;
}

/* Every address at which `pattern` occurs across the given ranges, capped. */
function scanRangesAll(ranges, pattern, cap) {
    var out = [], i, j;
    for (i = 0; i < ranges.length; i++) {
        try {
            var hits = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
            for (j = 0; j < hits.length; j++) {
                out.push(hits[j].address);
                if (cap && out.length >= cap) return out;
            }
        } catch (e: any) { /* skip an unreadable range */ }
    }
    return out;
}

/* SELF-HEALING vtable resolution via the Itanium C++ RTTI graph. A Telegram update
 * recompiles libtmessages and shifts every RVA, which silently breaks a hardcoded
 * vtable_ptr_rva (the failure mode observed on 12.10.3 -> 12.10.5). RTTI survives
 * stripping, so we rediscover the vtable from the loaded image, version-independently:
 *   1. the mangled RTTI type-name string "<len><name>" (e.g. "10Connection"),
 *      stored NUL-terminated in .rodata;
 *   2. the std::type_info whose __type_name field points at that string — its base
 *      T is that pointer's location minus one pointer width;
 *   3. the vtable whose type_info slot (structure+8) points at T, told apart from
 *      RTTI base-type references by requiring offset_to_top (structure+0) == 0 and
 *      the first virtual-function slot (structure+16) to land inside the module.
 * Returns the value a live object stores in this[0] (== &vtable + 16), or null.
 * Validated offline against libtmessages.49 / Telegram 12.10.5 (rva 0x126ce90). */
function deriveConnectionVtableViaRtti(mod, tier) {
    var mangled = (tier && typeof tier.rtti_type_name_mangled === 'string' &&
                   tier.rtti_type_name_mangled.length > 0)
                  ? tier.rtti_type_name_mangled : '10Connection';
    var ranges = moduleReadableRanges(mod);
    if (ranges.length === 0) return null;

    // 1) the standalone, NUL-terminated type-name string (leading NUL forces a
    //    whole-string match, so "10Connection" is not caught inside a longer name).
    var nameBytes = [0], c;
    for (c = 0; c < mangled.length; c++) nameBytes.push(mangled.charCodeAt(c) & 0xff);
    nameBytes.push(0);
    var namePattern = hexToScanPattern(hex(new Uint8Array(nameBytes)));
    var nameHits = scanRangesAll(ranges, namePattern, 8);

    for (var n = 0; n < nameHits.length; n++) {
        var nameAddr = nameHits[n].add(1); // skip the leading NUL
        // 2) a type_info.__type_name field pointing at nameAddr; T = its slot - ptr.
        var l1s = scanRangesAll(ranges, pointerToScanNeedle(nameAddr), 8);
        for (var a = 0; a < l1s.length; a++) {
            var T = l1s[a].sub(Process.pointerSize);
            // 3) a vtable type_info slot pointing at T, validated structurally.
            var l2s = scanRangesAll(ranges, pointerToScanNeedle(T), 32);
            for (var b = 0; b < l2s.length; b++) {
                var offTop = readPointerOrNull(l2s[b].sub(Process.pointerSize));
                if (offTop === null || !offTop.isNull()) continue; // offset_to_top must be 0
                var vfnSlot = l2s[b].add(Process.pointerSize);
                var vfn = readPointerOrNull(vfnSlot);
                if (vfn === null) continue;
                var v = untag(vfn), lo = untag(mod.base), hi = lo.add(mod.size);
                if (v.compare(lo) < 0 || v.compare(hi) >= 0) continue; // vfn in-module
                return vfnSlot; // == &vtable + 16, i.e. the value stored in this[0]
            }
        }
    }
    return null;
}

function resolveConnectionVtable(profile) {
    var tier = profile.tiers && profile.tiers.E_connection_ctr_state;
    if (!tier || tier.enabled !== true) return null;
    var mod = findTgnetModule(tier);

    /* PREFERRED: derive the vtable from RTTI at runtime — version-independent, so a
     * Telegram update does not silently disable OBF capture. See
     * deriveConnectionVtableViaRtti(). */
    if (mod) {
        try {
            var derived = deriveConnectionVtableViaRtti(mod, tier);
            if (derived && !derived.isNull()) {
                mtstate.connectionVtableSource = 'rtti';
                mtstate.connectionVtableRva = derived.sub(mod.base);
                log('info', '[Tier E] Connection vtable resolved via RTTI at ' + derived +
                    ' (rva 0x' + mtstate.connectionVtableRva.toString(16) + ', self-healing)');
                return derived;
            }
        } catch (e: any) { /* fall through to the calibrated RVA */ }
    }

    /* FALLBACK: module base + measured RVA. tgnet ships STRIPPED, so the C++ vtable
     * symbol does NOT resolve by name; the on-device-validated vtable_ptr_rva is a
     * build-specific anchor (goes stale on a Telegram update, which is exactly why
     * the RTTI walk above is preferred). The value stored at a live Connection's
     * this[0] (i.e. _ZTV10Connection + 16). */
    var rva = tier.vtable_ptr_rva;
    if (typeof rva === 'number' && isFinite(rva) && mod) {
        try {
            mtstate.connectionVtableSource = 'rva';
            mtstate.connectionVtableRva = ptr(rva);
            return mod.base.add(rva);
        } catch (e: any) { /* fall through */ }
    }

    /* LAST RESORT: DebugSymbol — only works on an unstripped / local-symbol build. */
    var symbol = tier.vtable_symbol;
    if (typeof symbol === 'string' && symbol.length > 0) {
        try {
            var sym = DebugSymbol.fromName(symbol);
            if (sym && sym.address && !sym.address.isNull()) {
                mtstate.connectionVtableSource = 'symbol';
                return sym.address;
            }
        } catch (e: any) { /* fall through -> null */ }
    }
    mtstate.connectionVtableSource = null;
    return null;
}

/* The scan needle for a Connection object: the vtable pointer's raw bytes in the
 * target's pointer width and byte order (little-endian on every supported arch),
 * so a hit is an object whose first qword is that vtable. */
function pointerToScanNeedle(p) {
    var bytes = [], value = untag(p), i;
    for (i = 0; i < Process.pointerSize; i++) {
        bytes.push(parseInt(value.and(0xff).toString(10), 10));
        value = value.shr(8);
    }
    return hexToScanPattern(hex(new Uint8Array(bytes)));
}

/* Reconstruct a raw AES-256 key from an expanded OpenSSL-style key schedule: the
 * first 8 schedule words ARE the original 256-bit key, stored big-endian by the
 * key-expansion (GETU32). Reading each word as a native u32 and re-emitting it
 * big-endian reproduces the original key bytes.
 *
 * RE CAVEAT: the storage endianness/word order MUST be re-confirmed on the target
 * build during Phase-0 — a different AES implementation could store the round keys
 * in a different order. Returns a 32-byte Uint8Array, or null on a faulting read. */
function readAes256KeyFromSchedule(scheduleAddr) {
    var out = new Uint8Array(32), i, word;
    for (i = 0; i < 8; i++) {
        word = readU32OrNull(scheduleAddr.add(i * 4));
        if (word === null) return null;
        out[i * 4 + 0] = (word >>> 24) & 0xff;
        out[i * 4 + 1] = (word >>> 16) & 0xff;
        out[i * 4 + 2] = (word >>> 8) & 0xff;
        out[i * 4 + 3] = word & 0xff;
    }
    return out;
}

/* True only when every CTR offset this tier dereferences is a real number. A null
 * (un-RE'd) offset keeps the tier "off" rather than reading garbage. */
function connectionOffsetsComplete(off) {
    if (!off) return false;
    var fields = ['encrypt_key', 'encrypt_ivec', 'encrypt_num',
                  'decrypt_key', 'decrypt_ivec', 'decrypt_num'];
    for (var i = 0; i < fields.length; i++) {
        if (typeof off[fields[i]] !== 'number') return false;
    }
    return true;
}

/* Recover the raw AES-256 key from the expanded key schedule, honouring the
 * profile's byteswap_schedule_words flag. On this build (libtmessages.49 / arm64)
 * AES_set_encrypt_key dispatches to the ARMv8 hardware path, which stores the first
 * 32 schedule bytes as the raw key VERBATIM — VALIDATED on-device (5/5 CTR-identity
 * checks). byteswap_schedule_words=false therefore reads the 32 bytes directly;
 * =true falls back to the per-word big-endian reconstruction (aes_nohw GETU32
 * storage) for builds/arches that use the C path. */
function readRawAes256Key(scheduleAddr, rawLen, byteswap) {
    if (byteswap) return readAes256KeyFromSchedule(scheduleAddr);
    var b = readBuffer(scheduleAddr, rawLen || 32);
    return b === null ? null : new Uint8Array(b);
}

/* Read the live CTR state for one Connection object and emit MTPROTO_OBF_KEY. One
 * hit -> at most one emitted line. Every read is guarded; a faulting field (a
 * freed/torn-down Connection) drops the candidate silently. */
function processConnectionCandidate(objBase, off, stats) {
    var byteswap = off.byteswap_schedule_words === true;
    var rawLen = typeof off.raw_key_len === 'number' ? off.raw_key_len : 32;
    var keyOut = readRawAes256Key(shift(objBase, off.encrypt_key), rawLen, byteswap);
    var keyIn = readRawAes256Key(shift(objBase, off.decrypt_key), rawLen, byteswap);
    if (keyOut === null || keyIn === null) return false;
    var ivOut = readBuffer(shift(objBase, off.encrypt_ivec), 16);
    var ivIn = readBuffer(shift(objBase, off.decrypt_ivec), 16);
    if (ivOut === null || ivIn === null) return false;
    var numOut = readS32OrNull(shift(objBase, off.encrypt_num));
    var numIn = readS32OrNull(shift(objBase, off.decrypt_num));
    if (numOut === null || numIn === null) return false;

    /* Decode the peer 4-tuple from the ConnectionSocket sockaddr at the same
     * object base. Prefers the sockaddr (survives fd==-1) and can never throw:
     * a faulting/short read or an unknown family yields '-', so a bad endpoint
     * degrades the line rather than dropping the recovered key. */
    var endpoint = readConnectionEndpoint(objBase, off);

    stats.tierE.candidates++;
    emitObfKey(
        hex(keyOut), hex(new Uint8Array(ivOut)), hex(keyIn), hex(new Uint8Array(ivIn)),
        numOut & 15, numIn & 15, endpoint, 'E', 'connection@' + untag(objBase), stats);
    return true;
}

/* Remember a live Connection object base so an INCREMENTAL pass can re-read its CTR
 * state (ivec/num advance every packet) without re-scanning the heap for the vtable
 * needle — see revalidateConfirmed. Deduped by untagged address string. */
function rememberConnection(objBase) {
    var s = untag(objBase).toString();
    if (mtstate.confirmedConnections.indexOf(s) === -1) mtstate.confirmedConnections.push(s);
}

function runTierE(ranges, stats, errors) {
    var tier = mtstate.profile.tiers && mtstate.profile.tiers.E_connection_ctr_state;
    if (!tier) return;
    /* Three findings, one field: "off" (disabled or un-RE'd), "ran and found
     * nothing", "ran and emitted". Anything that keeps the tier from touching the
     * target is reported as "off" with a reason, never as an empty successful run. */
    stats.tierE.enabled = tier.enabled === true;
    if (!stats.tierE.enabled) return;

    var off = mtstate.profile.struct_offsets && mtstate.profile.struct_offsets.Connection;
    if (!connectionOffsetsComplete(off)) {
        stats.tierE.skipReason = 'offsets-not-reverse-engineered';
        return;
    }
    if (mtstate.connectionVtable === null || mtstate.connectionVtable.isNull()) {
        stats.tierE.skipReason = 'vtable-unresolved';
        return;
    }

    stats.tierE.state = 'ran';
    stats.tierE.vtableSource = mtstate.connectionVtableSource || null;
    var needle = pointerToScanNeedle(mtstate.connectionVtable);
    var hits = scanRanges(ranges, needle, errors);
    stats.tierE.vtableHits += hits.length;
    if (hits.length === 0 && !mtstate.tierEWarned) {
        mtstate.tierEWarned = true;
        log('warn', '[Tier E] 0 live Connection objects matched the vtable anchor ' +
            mtstate.connectionVtable + ' (source=' + (mtstate.connectionVtableSource || '?') +
            '). No MTPROTO_OBF_KEY will be emitted, so a mid-stream (attach) Telegram ' +
            'connection cannot be decrypted offline. Likely: (a) no Connection was alive ' +
            'during this scan — keep Telegram in the foreground and exchange a few messages; ' +
            'or (b) the vtable anchor is stale for this build and the RTTI walk failed — ' +
            'recalibrate struct_offsets.Connection / vtable_ptr_rva.');
    }
    for (var h = 0; h < hits.length; h++) {
        /* The hit is the vtable pointer field at the object's base (offset 0). */
        try {
            if (processConnectionCandidate(hits[h], off, stats)) rememberConnection(hits[h]);
        }
        catch (e: any) { errors.push('tierE ' + hits[h] + ': ' + e.message); }
    }
}

/* ---------------------------------------------------------------------------
 * configure() input normalisation
 * ------------------------------------------------------------------------- */

function countKeys(obj) {
    var n = 0;
    for (var k in obj) if (obj.hasOwnProperty(k)) n++;
    return n;
}

function positiveOr(value, fallback) {
    if (typeof value !== 'number' || !isFinite(value) || value < 1) return fallback;
    return Math.floor(value);
}

/* profile.match.pointer_size is the one JSON declaration describing the TARGET
 * rather than the layout, and only the agent can check it: Process.pointerSize is
 * a property of the process it was injected into. It matters because every offset
 * here was derived on arm64 and assumes an 8-byte pointer, so against a 32-bit
 * (armeabi-v7a) Telegram no read lands on anything — the run would complete, find
 * nothing, and the silence report would blame the byte patterns, which are the one
 * part of the profile that would still have been correct. Hence a REFUSAL, not a
 * warning: a 32-bit target needs its own profile with re-derived offsets. */
function checkPointerSize(profile) {
    var declared = profile.match && profile.match.pointer_size;
    if (declared === Process.pointerSize) return;
    throw new Error('profile \'' + profile.id + '\' declares match.pointer_size ' +
                    declared + ' but this process reports Process.pointerSize ' +
                    Process.pointerSize + '; every offset in this profile assumes an ' +
                    declared + '-byte pointer, so a target of a different width needs a ' +
                    'different profile, not a flag.');
}

/* The ART round trip's offsets are a PRECONDITION, not an option, whenever the
 * check is on: without them every Secret-Chat key would still be emitted, but with
 * a chat_id nothing had verified, and the only trace would be a note buried in the
 * emitted `source` string. Refused here so it is one loud failure at attach. */
function checkArtRefOffsets(profile) {
    var tier = profile.tiers.C_art_secretchat_key;
    if (!tier || tier.enabled !== true || tier.art_ref_roundtrip === false) return;
    var off = profile.struct_offsets && profile.struct_offsets.EncryptedChat;
    if (off && isNonEmptyArray(off.auth_key_ref_candidates)) return;
    throw new Error('profile \'' + profile.id + '\' enables C_art_secretchat_key with ' +
                    'art_ref_roundtrip but carries no struct_offsets.EncryptedChat.' +
                    'auth_key_ref_candidates list, so the ART back-reference check has ' +
                    'no offset to try and every emitted chat_id would be unverified.');
}

/* Tier D's ids come from the driver as hex strings. They are lower-cased and
 * stripped of an optional 0x so that a caller's formatting choice can never turn
 * into a silent miss. */
function normaliseExternalIds(ids) {
    var set = {};
    if (!ids || !ids.length) return set;
    for (var i = 0; i < ids.length; i++) {
        var id = String(ids[i]).toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
        if (id.length > 0) set[id] = true;
    }
    return set;
}

/* ---------------------------------------------------------------------------
 * Entry points. The standalone scanner exposed configure()/scanOnce()/needles()
 * via rpc.exports; here the shared agent owns rpc, so the two the host uses are
 * exported as plain functions instead. needles() is unused by the host and not
 * ported.
 * ------------------------------------------------------------------------- */

export function mtprotoConfigure(profile: any): void {
    checkPointerSize(profile);
    checkArtRefOffsets(profile);
    mtstate.profile = profile;
    mtstate.validators = parseValidators(profile.validators);
    mtstate.emitUnconfirmed = profile.emitUnconfirmed === true;
    mtstate.externalIds = normaliseExternalIds(profile.externalIds);
    mtstate.maxHitsPerScan = positiveOr(profile.maxHitsPerScan, DEFAULT_MAX_HITS_PER_SCAN);
    // Tier E (obfuscated-transport CTR state): resolve the Connection vtable anchor
    // once, best-effort. A no-op while the tier is disabled (the usual case today).
    mtstate.connectionVtable = resolveConnectionVtable(profile);
    // NB: the shared memory-scan agent already installs ONE process exception
    // handler in its rpc configure() (core/memory.ts installExceptionHandler).
    // We deliberately do NOT install a second one here: Frida STACKS handlers, and
    // a redundant handler adds no safety (every native read in this scanner is
    // already guarded by try/catch — see readBuffer/readPointerOrNull) while
    // double-counting faults and running extra code on the target's faulting
    // threads. The scanner's own installExceptionHandler() is kept above only so
    // the port stays a faithful copy of scanner.js; it is intentionally uncalled.
}

/* ---------------------------------------------------------------------------
 * Incremental passes. A FULL pass re-enumerates the whole heap; an INCREMENTAL
 * pass skips Memory.scanSync entirely and just re-reads the objects a recent full
 * pass confirmed. Keys and Connections are long-lived, so between full sweeps the
 * only thing that MUST be re-read is Tier E's live CTR state (ivec/num advance on
 * every packet). If any remembered object fails revalidation the next pass is
 * forced full, so a torn-down object can never leave the emitted set stale.
 * ------------------------------------------------------------------------- */

/* How often a full re-enumeration runs, in passes. Read from the profile like the
 * other constants; 8 when the profile omits it. */
function fullRescanEvery() {
    var c = mtstate.profile.constants;
    return positiveOr(c && c.full_rescan_every, 8);
}

/* Re-confirm one remembered auth key by pointer, no scan: the key must still hash
 * to its id (proves the ByteArray was not freed/reused) AND at least one remembered
 * slot must still point back at it. On success re-emit through the normal path —
 * emittedLines makes the identical line a no-op, so this only keeps the record
 * alive. Returns false when the object is gone, which forces a full next pass. */
function revalidateAuthKey(entry, tier, stats) {
    var buf = readBuffer(ptr(entry.keyPtr), tier.key_len);
    if (buf === null) return false;
    if (sha1LowId(buf) !== entry.id) return false;      // key moved, freed or reused

    var byteArray = untag(ptr(entry.byteArray)), live = false;
    for (var i = 0; i < entry.slots.length; i++) {
        var back = readPointerOrNull(ptr(entry.slots[i]));
        if (back !== null && !back.isNull() && untag(back).equals(byteArray)) { live = true; break; }
    }
    if (!live) return false;

    emitAuthKey(entry.id, entry.keyHex, entry.dcId, entry.keyType, 'B', 'revalidated', stats);
    return true;
}

/* An incremental pass that re-reads remembered Connections runs Tier E's
 * per-object read (processConnectionCandidate counts candidates and emits keys),
 * so its stats must not stay at the pass-start 'off'/enabled=false: report the
 * tier as enabled in state 'revalidated'. Remembered Connections only exist if a
 * prior full pass ran Tier E enabled. Exported for unit tests. */
export function markTierERevalidated(tierE: { state: string; enabled: boolean }): void {
    tierE.enabled = true;
    tierE.state = 'revalidated';
}

/* The INCREMENTAL body: re-read every remembered auth key and Connection. A single
 * revalidation miss sets forceFullNext so the next pass re-enumerates. */
function revalidateConfirmed(stats) {
    // revalidateAuthKey re-reads the key buffer, so it needs Tier A's key_len (the
    // ByteArray key length); Tier B carries the round-trip offsets, NOT key_len, so
    // passing tierB here made key_len undefined and every re-read fail (all keys
    // "missed", forcing a full pass every other cycle). Use Tier A.
    var tierA = mtstate.profile.tiers.A_bytearray_authkey;
    for (var id in mtstate.confirmedAuthKeys) {
        if (!mtstate.confirmedAuthKeys.hasOwnProperty(id)) continue;
        var ok = false;
        try { ok = revalidateAuthKey(mtstate.confirmedAuthKeys[id], tierA, stats); }
        catch (e: any) { stats.errors.push('reval authkey ' + id + ': ' + e.message); }
        if (ok) { stats.revalidated++; }
        else { stats.revalidationMisses++; mtstate.forceFullNext = true; }
    }

    var off = mtstate.profile.struct_offsets && mtstate.profile.struct_offsets.Connection;
    var vtable = mtstate.connectionVtable;
    if (mtstate.confirmedConnections.length > 0) markTierERevalidated(stats.tierE);
    for (var c = 0; c < mtstate.confirmedConnections.length; c++) {
        var objBase = ptr(mtstate.confirmedConnections[c]);
        var alive = false;
        try {
            /* Cheap liveness gate before touching the CTR fields: the object's first
             * qword must still be the Connection vtable. */
            var first = readPointerOrNull(objBase);
            if (first !== null && vtable !== null &&
                untag(first).equals(untag(vtable))) {
                alive = processConnectionCandidate(objBase, off, stats);
            }
        } catch (e: any) { stats.errors.push('reval conn ' + objBase + ': ' + e.message); }
        if (alive) { stats.revalidated++; }
        else { stats.revalidationMisses++; mtstate.forceFullNext = true; }
    }
}

export function mtprotoScanOnce(): any {
        var started = Date.now();
        var stats = {
            /* `state` is the tier's 3-way answer — "off", "throttled" or "ran" —
             * and is the field to read. The older enabled/skipped/throttledBy
             * booleans are kept beside it for compatibility; throttledBy is detail
             * of "throttled". */
            tierA: { state: 'off', candidates: 0, aligned: 0, ptrOk: 0, entropyOk: 0 },
            tierB: { state: 'off', needles: 0, idHits: 0, confirmed: 0 },
            /* Tier C also carries the evidence counters for the ART back-reference
             * round trip. The two offset->count maps are what makes a retarget
             * VISIBLE: dataOffsetHits says which key-data offset produced the
             * blobs, roundTripByOffset which reference slot closed. */
            tierC: {
                state: 'off', candidates: 0, entropyOk: 0, confirmed: 0,
                enabled: false, skipped: false, throttledBy: null,
                sitesTested: 0, roundTrips: 0, roundTripsPoisoned: 0,
                colocatedOnly: 0, refCheckSkipped: 0,
                dataOffsetHits: {}, roundTripByOffset: {}
            },
            tierD: { state: 'off', enabled: false, candidates: 0, confirmed: 0 },
            /* Tier E (obfuscated-transport CTR state) mirrors tierB/tierD: `state`
             * is the 3-way answer, `skipReason` explains an enabled-but-off tier
             * (offsets not yet reverse-engineered, or vtable unresolved). ENABLED and
             * validated on-device; when the tier is off it self-reports "off" with a
             * reason and touches nothing at runtime. On an INCREMENTAL pass that re-read
             * remembered Connections, state is "revalidated" (see markTierERevalidated). */
            tierE: { state: 'off', enabled: false, skipReason: null, vtableHits: 0, candidates: 0, vtableSource: null },
            /* Incremental-pass telemetry: `mode` is the pass kind, revalidated/
             * revalidationMisses count remembered objects re-read on an incremental
             * pass (both stay 0 on a full pass). */
            mode: 'full', revalidated: 0, revalidationMisses: 0,
            emitted: 0, faults: 0, durationMs: 0, errors: []
        };
        if (mtstate.profile === null) {
            stats.errors.push('configure() has not been called');
            return stats;
        }

        /* Pass mode is decided HERE, inside the agent, so the scanOnce RPC signature
         * and the driver's poll loop stay unchanged. A full pass runs on the first
         * pass, when a prior revalidation miss forced it, every full_rescan_every
         * passes, or whenever nothing is remembered yet (an incremental pass would
         * have nothing to re-read). Everything else is an incremental pass. */
        var scanIndex = mtstate.scanIndex;
        var nothingRemembered = countKeys(mtstate.confirmedAuthKeys) === 0 &&
                                mtstate.confirmedConnections.length === 0;
        /* Tier E (OBF/CTR Connection discovery) runs on FULL passes only, and a live
         * Connection object is transient: it is often not discoverable in the single
         * full pass right after attach, while the auth keys (found on pass 0) already
         * make `nothingRemembered` false. Keep scanning fully until at least one
         * Connection has been discovered, so Tier E gets repeated attempts to catch it
         * (restores the pre-incremental behaviour that reliably captured OBF keys).
         * Once a Connection is remembered, incremental passes resume (revalidateConfirmed
         * re-reads it) with periodic full re-discovery every full_rescan_every. */
        var noConnectionDiscoveredYet = mtstate.confirmedConnections.length === 0;
        var fullPass = scanIndex === 0 || mtstate.forceFullNext || nothingRemembered ||
                       noConnectionDiscoveredYet ||
                       (scanIndex % fullRescanEvery() === 0);
        stats.mode = fullPass ? 'full' : 'incremental';

        if (fullPass) {
            /* Rebuild the remembered set from scratch every full pass, so a key or
             * Connection that has since been torn down drops out instead of lingering
             * across the incremental passes that follow. */
            mtstate.confirmedAuthKeys = {};
            mtstate.confirmedConnections = [];

            var pass = beginPass();
            mtstate.mappedRanges = buildMappedRangeIndex(pass.ranges);

            var native = selectRanges(mtstate.profile.scan_regions, pass);
            var candidates = runTierA(native, stats, stats.errors);
            runTierB(native, candidates, stats, stats.errors);
            reportUnconfirmed(candidates, stats);
            runTierC(pass, stats, stats.errors);
            runTierD(native, stats, stats.errors);
            /* Tier E scans the same rw- native ranges as A/B/D for LIVE Connection
             * objects. ENABLED and validated on-device; it self-reports "off" with a
             * skipReason only if the Connection offsets or vtable cannot be resolved. */
            runTierE(native, stats, stats.errors);

            mtstate.forceFullNext = false;
        } else {
            /* Incremental pass: no Memory.scanSync and no buildMappedRangeIndex — just
             * re-read the remembered objects. isMappedAddress()'s null fallback covers
             * the few guarded reads that consult it. */
            revalidateConfirmed(stats);
        }

        mtstate.scanIndex++;
        /* Cumulative since injection, not per pass: the handler counts faults on
         * the target's own threads, which are not tied to a scan. */
        stats.faults = mtstate.faults;
        stats.durationMs = Date.now() - started;
        /* Dropped rather than kept: together these are 1-3 MB, and holding them
         * across the 6-16 s idle gap the Tier C throttle exists to create would
         * spend that gap's memory headroom on an index the next pass rebuilds
         * anyway. isMappedAddress() has a documented null fallback. */
        mtstate.mappedRanges = null;
        mtstate.mapsIndex = null;
        return stats;
}
