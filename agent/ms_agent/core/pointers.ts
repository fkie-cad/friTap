import { state } from "../state.js";

/* ARM64 top-byte-ignore: heap pointers can carry a tag in bits 56-63. Dereferences
 * work through the tag, but any range lookup or pointer COMPARISON must untag. */
export function untag(p) {
    return p.and(state.validators.tagMask);
}

/* ---------------------------------------------------------------------------
 * Mapped-address index.
 *
 * "Is this address mapped" is the cheapest way to reject a field that only looks
 * like a pointer, but the obvious implementation is not cheap at all:
 * Process.findRangeByAddress costs 5.66 ms per call on the target and a single
 * scan asks the question 60-130 times — ~566 ms of a 600-1600 ms scan, i.e. the
 * dominant cost of the whole agent. One full Process.enumerateRanges over every
 * mapping costs 27 ms, so ONE snapshot per scan plus a binary search answers the
 * identical predicate for roughly a twentieth of the price.
 *
 * The snapshot is rebuilt at the start of EVERY scan: the target's heap grows
 * between scans, and a stale index would reject live pointers — a recall loss,
 * which is the one thing we cannot trade away.
 * ------------------------------------------------------------------------- */

/* Interval endpoints are compared as Numbers, not NativePointers, because that is
 * what makes the binary search cheap. Userspace addresses on this target are
 * ~0x7xxxxxxxxx (39 significant bits) and the largest conceivable mapping end is
 * far below 2^53, so every value here is an exact integer and nothing is lost.
 * The caller always passes the UNTAGGED pointer, exactly as the findRangeByAddress
 * path did. */
export function addressToNumber(p) {
    return parseInt(p.toString(16), 16);
}

export function buildMappedRangeIndex() {
    /* protection '---' is a minimum, not a filter: it means "every mapping",
     * including the PROT_NONE guard pages findRangeByAddress also reports. */
    var ranges = Process.enumerateRanges({ protection: '---', coalesce: false });
    var index = new Array(ranges.length);
    for (var i = 0; i < ranges.length; i++) {
        var start = addressToNumber(ranges[i].base);
        index[i] = [start, start + ranges[i].size];    // half-open [start, end)
    }
    index.sort(function (a, b) { return a[0] - b[0]; });
    return index;
}

export function indexContains(index, address) {
    var lo = 0, hi = index.length - 1;
    while (lo <= hi) {
        var mid = (lo + hi) >> 1;
        if (address < index[mid][0]) hi = mid - 1;
        else if (address >= index[mid][1]) lo = mid + 1;
        else return true;
    }
    return false;
}

export function isMappedAddress(untagged) {
    /* Before the first scanOnce() there is no snapshot yet; fall back to the slow
     * lookup so the predicate is never weaker than the one it replaced. */
    if (state.mappedRanges === null) return Process.findRangeByAddress(untagged) !== null;
    return indexContains(state.mappedRanges, addressToNumber(untagged));
}

/* Freed PartitionAlloc slots are poisoned (0xefefefef...) and uninitialised
 * storage is stale garbage, so "is this address mapped" is the cheapest way to
 * reject a field that only looks like a pointer. */
export function looksLikeHeapPointer(p) {
    if (p === null || p.isNull()) return false;
    var u = untag(p);
    if (u.compare(state.validators.pointerMin) < 0) return false;
    return isMappedAddress(u);
}
