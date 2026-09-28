/*
 * Shared memory-scan agent state.
 *
 * This is the former global `var state` from memory_scan_agent.ts, lifted out
 * verbatim into a single shared mutable singleton. Every core helper and every
 * engine imports THIS object, so the semantics are byte-for-byte identical to
 * the old single-file global: there is one `state` per loaded agent bundle and
 * all modules read and mutate it directly.
 *
 * Everything layout-related lives under `profile`; everything countable about a
 * single scan lives on that scan's `stats` object instead (see driver.ts).
 */
'use strict';

export const state: any = {
    profile: null,          // the ACTIVE profile for the current scan/tier group
    profiles: null,         // all profiles configure() was handed (see rpc.ts);
                            // a single profile is stored as a one-element list so
                            // scanOnce() has one code path. null until configure().
    validators: null,       // parsed once by configure(), see parseValidators()
    needle: null,           // Tier B needle derived by Tier A: {value, module, rva}
    recorded: {},           // "LABEL|client_random" -> secret hex
    faults: 0,              // native faults seen by the exception handler
    handlerInstalled: false,// configure() is allowed to be called more than once
    mappedRanges: null,     // per-scan address index, see buildMappedRangeIndex()
    scanIndex: 0,           // 0 on the FIRST scan, so scan 1 is never throttled
    lastTierBValidated: null,// Tier B's validated count on the previous scan;
                            // null means "there has not been one yet"

    // --- Schannel engine state (WS4). Resolved once per process; a schannel
    // profile only ever runs in one lsass session, so caching globally is safe.
    schannelReady: false,   // resolveSchannelNeedles()/module lookups done?
    schannelNeedles: [],    // [{value, module, rva}] ncryptsslp invariant pointers
    schannelNeedleModule: null, // {base,size} of ncryptsslp.dll
    schannelModule: null,   // {base,size} of schannel.dll (session-cache vftable host)
    schannelCacheVftable: null, // CSslCacheClientItem vftable, derived + cached

    // --- RC4 engine state (WS3).
    rc4KatOk: null,         // known-answer-test result, run once (null = not yet)
    rc4Sboxes: [],          // S-boxes found this scan
    rc4Emitted: {}          // dedup for emitted rc4_key messages across scans
};
