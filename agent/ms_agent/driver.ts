/*
 * Scan driver: profile activation + the per-profile scan loop, plus engine
 * dispatch through the registry.
 *
 * This is the former profileEngine()/activateProfile()/scanProfileOnce()/
 * runEngineTiers() code from memory_scan_agent.ts, moved verbatim. The only
 * change is that runEngineTiers() now looks the engine up in the registry
 * instead of an inline if-chain — behaviour is identical, including the
 * "unknown engine" error path.
 */
import { state } from "./state.js";
import { getEngine } from "./registry.js";
import { parseValidators } from "./core/heuristics.js";
import { buildMappedRangeIndex } from "./core/pointers.js";
import { selectRanges } from "./core/ranges.js";

/** profile.engine, defaulting to 'boringssl' when absent (unchanged). */
export function profileEngine(profile: any): string {
    var e = profile && profile.engine;
    return (typeof e === 'string' && e) ? e : 'boringssl';
}

/* Make `profile` the active one: everything layout-related is read off
 * state.profile, and the per-secret validators are derived from it. Splitting
 * this out is what lets configure()/scanOnce() walk a LIST of profiles. A
 * profile with no validators (e.g. a scaffold engine profile) leaves
 * state.validators null rather than throwing. */
export function activateProfile(profile: any): void {
    state.profile = profile;
    state.validators = profile && profile.validators ? parseValidators(profile.validators) : null;
}

/* Pick the matching engine's tier group from the registry and run it. An
 * unknown engine is a profile bug; surface it rather than silently scanning
 * with the wrong (or no) tier group. */
function runEngineTiers(ranges: any, stats: any, errors: string[]): void {
    var engine = profileEngine(state.profile);
    var impl = getEngine(engine);
    if (impl) { impl.runTiers(ranges, stats, errors); return; }
    errors.push('unknown engine "' + engine + '"; no tiers run for profile ' +
                (state.profile && state.profile.id));
}

/* One scan of ONE profile. This is the former scanOnce() body verbatim, only
 * parameterised by profile: for the single-profile case the profile is already
 * active (configure set it), so nothing is re-parsed and behaviour is identical.
 */
/* Whether this profile needs the per-scan '---' range index built. The code default
 * (true) preserves today's always-build behavior; a profile that never classifies
 * pointers (e.g. RC4 heap-scan) sets needs_mapped_index:false to skip it. Recall is
 * unaffected because isMappedAddress falls back to findRangeByAddress when the index
 * is null (see agent/ms_agent/core/pointers.ts). */
export function needsMappedIndex(profile: any): boolean {
    var params = (profile && profile.params) || {};
    return params.needs_mapped_index !== false;
}

export function scanProfileOnce(profile: any): any {
    var started = Date.now();
    var stats: any = {
        // `skipped` distinguishes "Tier A ran and found nothing" from "Tier A
        // did not run this scan"; both would otherwise print as A 0/0.
        tierA: { candidates: 0, validated: 0, skipped: false },
        tierB: { candidates: 0, validated: 0 },
        tierC: { candidates: 0, validated: 0 },
        // Tier B candidates whose handshake state could not be determined;
        // see classifyHandshake(). Deliberate misses, not errors.
        indeterminateHs: 0,
        emitted: 0, durationMs: 0, errors: [],
        profileId: profile === null || profile === undefined ? null : profile.id
    };
    if (profile === null || profile === undefined) {
        stats.errors.push('configure() has not been called');
        return stats;
    }
    // Only re-activate when switching profiles, so the single-profile flow never
    // re-parses validators and stays byte-for-byte the old behaviour.
    if (state.profile !== profile) activateProfile(profile);
    // Rebuilt every scan: the heap grows, and a stale index costs recall. Profiles that
    // never classify pointers (e.g. RC4 heap-scan) opt out via needs_mapped_index; when
    // skipped, isMappedAddress falls back to findRangeByAddress, so recall/correctness for
    // every engine is unaffected.
    state.mappedRanges = needsMappedIndex(profile) ? buildMappedRangeIndex() : null;
    var ranges = selectRanges();
    runEngineTiers(ranges, stats, stats.errors);
    state.scanIndex++;
    stats.durationMs = Date.now() - started;
    return stats;
}
