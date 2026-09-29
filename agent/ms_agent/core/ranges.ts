import { state } from "../state.js";
import { log } from "./log.js";

/* ---------------------------------------------------------------------------
 * Range selection. The ranges themselves always come from the protection mask in
 * the profile, NEVER from parsing /proc/self/maps by name: PartitionAlloc
 * super-page reservations interleave PROT_NONE guard pages with rw- slots, and
 * reading a guard page faults. /proc/self/maps is consulted for NAMES only,
 * because Frida's enumerateRanges does not carry the kernel's [anon:<label>]
 * annotations and without them the allowlist can never match.
 * ------------------------------------------------------------------------- */

/* Numeric sorted intervals [loNum, hiNum, name] parsed from /proc/self/maps and
 * binary-searched by numeric address — NOT a hex-STRING-keyed dict. /proc/self/maps
 * zero-pads start addresses ("02000000") while NativePointer.toString(16) does not
 * ("2000000"), so a string-key lookup silently drops every zero-padded range —
 * exactly the scudo ranges libsignal's TLS structs live in on Android (measured on
 * Pixel 7 / Android 17). A numeric interval search is immune to that formatting
 * mismatch, and containment (not exact-start) also tolerates a range base that is
 * not itself a maps start. Ported from research/memory_scan_signal/agent/scanner.js
 * (loadMapsIndex / findInterval / labelAt). */
var mapsIndex: any = null;

/* NativePointer -> Number. Android arm64 user addresses are <= 2^48, well within
 * the 2^53 exact-integer range, so no precision is lost. */
export function addressToNumber(ptr): number {
    return parseInt(ptr.toString(16), 16);
}

/* Only names that one of the two lists could possibly match are worth keeping:
 * the map then holds tens of entries instead of the thousands of lines
 * /proc/self/maps has in a Chrome browser process. */
export function nameNeedles(cfg) {
    return [].concat(cfg.name_allowlist || [], cfg.name_denylist || []);
}

export function loadAnonNames(needles) {
    mapsIndex = [];
    var text;
    try {
        text = File.readAllText('/proc/self/maps');
    } catch (e: any) {
        log('warn', 'cannot read /proc/self/maps (' + e.message + '); ' +
                    'range names unavailable, allowlist will be skipped');
        return;
    }
    var lines = text.split('\n');
    for (var i = 0; i < lines.length; i++) {
        var line = lines[i];
        /* Two cheap indexOf scans before the expensive regex. The overwhelming
         * majority of lines are either unnamed (no '[' and no '/' in the final
         * column) or named something neither list cares about, and for those the
         * regex — and the map entry — would be pure waste. */
        if (line.indexOf('[') === -1 && line.indexOf('/') === -1) continue;
        if (!matchesAny(line, needles)) continue;
        /* "7000001000-7000002000 rw-p 00000000 00:00 0    [anon:partition_alloc]" */
        var m = /^([0-9a-f]+)-([0-9a-f]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(.+)$/.exec(line);
        if (m !== null) mapsIndex.push([parseInt(m[1], 16), parseInt(m[2], 16), m[3].trim()]);
    }
    /* Sorted by numeric start so rangeLabel() can binary-search. */
    mapsIndex.sort(function (a, b) { return a[0] - b[0]; });
}

/* Binary-search the sorted interval index for the entry CONTAINING `value`. */
export function findInterval(index, value) {
    var lo = 0, hi = index.length - 1;
    while (lo <= hi) {
        var mid = (lo + hi) >> 1;
        var e = index[mid];
        if (value < e[0]) hi = mid - 1;
        else if (value >= e[1]) lo = mid + 1;
        else return e;
    }
    return null;
}

export function rangeLabel(range) {
    if (range.file) return range.file.path;
    if (range.name) return range.name;
    if (mapsIndex === null) return '';
    var e = findInterval(mapsIndex, addressToNumber(range.base));
    return e === null ? '' : e[2];
}

/* Both sides are lower-cased. The kernel, Frida and the profile each pick their
 * own case, and a denylist that matches only by accident of case is a denylist
 * that silently lets memory through. */
export function matchesAny(label, needles) {
    if (!needles || needles.length === 0) return false;
    var haystack = label.toLowerCase();
    for (var i = 0; i < needles.length; i++) {
        if (haystack.indexOf(needles[i].toLowerCase()) !== -1) return true;
    }
    return false;
}

export function isAnonymous(range) {
    return !range.file;
}

/* ---------------------------------------------------------------------------
 * Agent-owned ranges — an ADDRESS-based exclusion, ported from the parent repo's
 * agent/shared/scan/scan_safety.ts (buildAgentOwnedRanges / isAgentOwnedRange).
 *
 * Why it cannot be left to name_denylist: when /proc/self/maps is unreadable
 * every rangeLabel() is '', so the denylist matches nothing AND the allowlist
 * matches nothing, and selectRanges() then falls back to "all anonymous rw-
 * ranges" — which includes Frida's own QuickJS heap. Scanning that is pointless
 * work at best and re-enters the running scanner at worst. Module bases and sizes
 * do not depend on any name being available, so this exclusion cannot switch
 * itself off the way the name lists can.
 * ------------------------------------------------------------------------- */

var AGENT_MODULE_PATTERNS = [/frida/i, /gum-js-loop/i];

export function looksAgentOwned(text) {
    if (!text) return false;
    for (var i = 0; i < AGENT_MODULE_PATTERNS.length; i++) {
        if (AGENT_MODULE_PATTERNS[i].test(text)) return true;
    }
    return false;
}

export function buildAgentOwnedRanges() {
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

/* Overlap, not containment: a super-page reservation can straddle a module. */
export function isAgentOwnedRange(range, owned) {
    var end = range.base.add(range.size);
    for (var i = 0; i < owned.length; i++) {
        if (range.base.compare(owned[i].end) < 0 && owned[i].base.compare(end) < 0) return true;
    }
    return false;
}

/* ---------------------------------------------------------------------------
 * Windows range selection — a scaffold ported from the research prototype at
 * research/memory_scan_lsass/agent/schannel_scanner.js (its selectRanges).
 *
 * Windows has no /proc/self/maps, so the whole loadAnonNames() / name-allowlist /
 * name-denylist step below simply does not apply: range NAMES are unavailable.
 * The Windows path therefore selects rw- ranges purely by protection (from the
 * profile's scan_regions.protection, exactly as the POSIX path does) and excludes
 * agent-owned/module ranges by ADDRESS via the very same buildAgentOwnedRanges() /
 * isAgentOwnedRange() the POSIX path uses. The mapped-range index
 * (buildMappedRangeIndex/isMappedAddress) is shared unchanged across both paths.
 *
 * No engine's Windows tiers are implemented yet; this only makes the platform
 * split exist so a Windows profile has a sound range set to scan.
 * ------------------------------------------------------------------------- */
export function selectRangesWindows() {
    var cfg = state.profile.scan_regions;
    var owned = buildAgentOwnedRanges();
    var all = Process.enumerateRanges({ protection: cfg.protection, coalesce: false });
    var eligible = [];
    for (var i = 0; i < all.length; i++) {
        var r = all[i];
        if (cfg.require_anonymous && !isAnonymous(r)) continue;
        if (cfg.max_range_bytes && r.size > cfg.max_range_bytes) continue;
        if (isAgentOwnedRange(r, owned)) continue;
        eligible.push(r);
    }
    return eligible;
}

export function selectRanges() {
    /* Windows carries no [anon:...] map names, so take the name-free path above.
     * The existing Linux/Android body below is left exactly as it was. */
    if (Process.platform === 'windows') return selectRangesWindows();

    var cfg = state.profile.scan_regions;
    loadAnonNames(nameNeedles(cfg));
    var owned = buildAgentOwnedRanges();
    var all = Process.enumerateRanges({ protection: cfg.protection, coalesce: false });

    /* One pass, one rangeLabel() per range: each call crosses the JS/native
     * bridge for base.toString(16), and the two chained filters this replaces
     * paid for that twice. */
    var eligible = [];
    var allowed = [];
    for (var i = 0; i < all.length; i++) {
        var r = all[i];
        if (cfg.require_anonymous && !isAnonymous(r)) continue;
        if (cfg.max_range_bytes && r.size > cfg.max_range_bytes) continue;
        if (isAgentOwnedRange(r, owned)) continue;
        var label = rangeLabel(r);
        if (matchesAny(label, cfg.name_denylist)) continue;
        eligible.push(r);
        if (matchesAny(label, cfg.name_allowlist)) allowed.push(r);
    }

    /* Frida does not expose [anon:...] names on every version/kernel combination,
     * so an empty allowlist result means "no names", not "no heap". */
    if (allowed.length === 0) {
        var fallback = eligible.filter(isAnonymous);
        log('warn', 'no range matched name_allowlist [' + (cfg.name_allowlist || []).join(', ') +
                    '] — range names are unavailable, which means name_denylist [' +
                    (cfg.name_denylist || []).join(', ') + '] matched nothing either. ' +
                    'Falling back to ALL ' + fallback.length + ' anonymous ' + cfg.protection +
                    ' ranges, ' + totalBytes(fallback) + ' bytes now in scope instead of the ' +
                    'partition_alloc subset; scudo/guard/linker pages are no longer excluded ' +
                    'and only the address-based agent-module exclusion still applies.');
        return fallback;
    }
    return allowed;
}

export function totalBytes(ranges) {
    return ranges.reduce(function (sum, r) { return sum + r.size; }, 0);
}
