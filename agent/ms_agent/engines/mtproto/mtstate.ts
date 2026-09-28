/*
 * MTProto engine state. The scanner ported from
 * research/memory_scan_MTProto/agent/scanner.js keeps a single module-global
 * `var state`; here it is exported (renamed to `mtstate`) so the ported helpers
 * and the two mtprotoConfigure/mtprotoScanOnce entry points share one object.
 *
 * Everything layout-related lives under `profile`; everything countable about a
 * single scan lives on that scan's `stats` object instead.
 */
'use strict';

export const mtstate: any = {
    profile: null,
    validators: null,        // parsed once by configure(), see parseValidators()
    // opt-in: emit keylog lines the oracle did NOT confirm. Default false; set true
    // only when the driver's profile carries `emitUnconfirmed: true`, which the host
    // stamps on mtproto profiles for the `--ms-emit-unconfirmed` CLI flag (E4). Read
    // in mtprotoConfigure(); gates reportUnconfirmed()/confirmArtGroup() emission.
    emitUnconfirmed: false,
    externalIds: null,       // Tier D: {authKeyIdHex: true}, supplied by the driver
    maxHitsPerScan: 0,       // per (range, pattern) cap, see scanRange()
    needles: {},             // auth_key_id hex -> {keyPtr, byteArray}, this session
    recorded: {},            // "LABEL|key_id" -> key hex, for the conflict rule
    emittedLines: {},        // complete keylog line -> true, for the dedup rule
    scanIndex: 0,            // pass counter; ONLY reader is the legacy shouldRunTierC()
    tierCCompletedAt: null,  // ms; when the last Tier C pass FINISHED, see shouldRunTierCNow()
    faults: 0,               // native faults seen by the exception handler, cumulative
    handlerInstalled: false, // configure() is allowed to be called more than once
    mappedRanges: null,      // per-pass address index, see buildMappedRangeIndex()
    mapsIndex: null,         // per-pass /proc/self/maps index, see loadMapsIndex()
    // Tier E (obfuscated-transport CTR state): the resolved `_ZTV10Connection`
    // vtable address, or null when unresolved / the tier is off. Resolved once at
    // configure time (RTTI walk first, calibrated RVA as fallback) and used to build
    // the Connection-object scan needle. See resolveConnectionVtable() / runTierE().
    connectionVtable: null,
    // How connectionVtable was resolved, for diagnostics: 'rtti' (self-healed via the
    // Itanium RTTI graph — version-independent), 'rva' (calibrated fallback, build-
    // specific), 'symbol', or null (unresolved). connectionVtableRva is that anchor's
    // module RVA.
    connectionVtableSource: null,
    connectionVtableRva: null,
    // one-shot guard so the "0 Connection vtable hits" warning is logged once, not
    // on every scan pass.
    tierEWarned: false,
    // Incremental-pass memory (see scanner.ts revalidateConfirmed()). A FULL pass
    // rebuilds these from scratch; the INCREMENTAL passes in between re-read them
    // without sweeping the heap.
    //   confirmedAuthKeys:   id hex -> {id, byteArray, keyPtr, keyHex, slots:[addr…], dcId, keyType}
    //   confirmedConnections: [objBase hex, …] live Tier E Connection object bases
    //   forceFullNext:       a revalidation miss forces the next pass to re-enumerate
    confirmedAuthKeys: {},
    confirmedConnections: [],
    forceFullNext: false
};
