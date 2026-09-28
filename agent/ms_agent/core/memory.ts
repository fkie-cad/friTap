import { state } from "../state.js";
import { log } from "./log.js";

export function hexBytes(u) {
    var s = '';
    for (var i = 0; i < u.length; i++) s += (u[i] < 16 ? '0' : '') + u[i].toString(16);
    return s;
}

export function hex(buf) {
    if (buf === null) return '';
    return hexBytes(new Uint8Array(buf));
}

export function readHex(addr, len) {
    try { return hex(addr.readByteArray(len)); } catch (e: any) { return null; }
}

export function readBytes(addr, len) {
    try {
        var buf = addr.readByteArray(len);
        return buf === null ? null : new Uint8Array(buf);
    } catch (e: any) { return null; }
}

export function readPointerOrNull(addr) {
    try { return addr.readPointer(); } catch (e: any) { return null; }
}

export function readU8OrNull(addr) {
    try { return addr.readU8(); } catch (e: any) { return null; }
}

export function readU16OrNull(addr) {
    try { return addr.readU16(); } catch (e: any) { return null; }
}

export function readU32OrNull(addr) {
    try { return addr.readU32(); } catch (e: any) { return null; }
}

/* Convert a NativePointer to a plain number. User-space bases and range sizes on
 * every supported target fit well under 2^53, so this loses no precision. */
function ptrToNum(p): number {
    return parseInt(p.toString(), 16);
}

/* Pure clamp (exported for unit tests): of the requested `size` bytes starting at
 * `base`, how many stay inside the live mapping [rangeBase, rangeBase+rangeSize)?
 * A base before the mapping, or one at/after its end, clamps to 0; a request that
 * runs off the end is truncated to the mapping's end. All inputs are addresses as
 * plain numbers. */
export function clampReadableLength(base: number, size: number, rangeBase: number, rangeSize: number): number {
    if (size <= 0 || rangeSize <= 0) return 0;
    if (base < rangeBase) return 0;
    var available = rangeBase + rangeSize - base;
    if (available <= 0) return 0;
    return available < size ? available : size;
}

/* How many bytes from `base` are mapped and readable RIGHT NOW, capped at `size`?
 * The profile's range list is snapshotted at configure() time; between then and the
 * scan a page can be freed, flipped to no-access / PAGE_GUARD, or SHRUNK so the live
 * mapping no longer covers all of [base, base+size) (a TOCTOU race). Memory.scanSync
 * past the live end raises a NATIVE access violation that a JS try/catch cannot trap —
 * it surfaces as a "native fault" via the exception handler and aborts the range.
 *
 * Checking only the protection at `base` was not enough: a range whose FIRST page is
 * still readable but that has since shrunk would pass and then fault mid-scan. So we
 * also clamp the scan length to the live mapping's end (rd.base+rd.size) and skip
 * when nothing readable remains. Returns 0 to skip. */
function readableScanLength(base, size): number {
    try {
        var rd = (Process as any).findRangeByAddress(base);
        // No live mapping (freed/unmapped), or the first protection char is not 'r'
        // (no-access '---' or a page whose read bit is cleared, e.g. PAGE_GUARD): skip.
        if (rd === null || !rd.protection || rd.protection.charAt(0) !== 'r') return 0;
        return clampReadableLength(ptrToNum(base), size, ptrToNum(rd.base), rd.size);
    } catch (e: any) { return 0; }
}

export function scanRange(range, pattern, errors) {
    var len = readableScanLength(range.base, range.size);
    if (len <= 0) {
        // Silent skip: a range unmapped/protected/shrunk since the snapshot is not an
        // error, and scanning it would fault. Counting it as an error would spam a
        // healthy scan.
        return [];
    }
    try {
        // Clamp to the live mapping's end: a range that shrank since the snapshot is
        // scanned only over the bytes still mapped, never past the live end.
        return Memory.scanSync(range.base, len, pattern);
    } catch (e: any) {
        errors.push('scan ' + range.base + ': ' + e.message);
        return [];
    }
}

/* The scan is read-only and every read is guarded, so a faulting page surfaces in
 * JS as a caught exception, not here. This handler exists purely for diagnostics
 * about faults raised on the TARGET's own threads; it returns false so the app
 * keeps its normal crash semantics — swallowing those would resume the faulting
 * instruction forever.
 *
 * Idempotent: configure() calls it, and Process.setExceptionHandler STACKS
 * handlers, so a second configure() would otherwise double-count every fault. */
export function installExceptionHandler() {
    if (state.handlerInstalled) return;
    state.handlerInstalled = true;
    Process.setExceptionHandler(function (details) {
        state.faults++;
        // Diagnostic only, and expected during a read-only heap sweep, so keep it
        // at debug: surfacing the first few faults as warnings alarms users on a
        // perfectly healthy scan. The cumulative count lives in state.faults.
        if (state.faults <= 3) log('debug', 'native fault ' + details.type + ' at ' + details.address);
        return false;
    });
}

/* Render a pointer's raw bytes as a space-separated hex scan pattern (little- or
 * big-endian exactly as the target stores it), for Memory.scanSync. Shared by
 * the boringssl and schannel engines, so it lives in core. Moved verbatim from
 * the former single-file agent (memory_scan_agent.ts:705). */
export function pointerToScanPattern(p) {
    var buf = Memory.alloc(Process.pointerSize);
    buf.writePointer(p);
    return hex(buf.readByteArray(Process.pointerSize)).match(/../g).join(' ');
}
