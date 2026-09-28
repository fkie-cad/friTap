/*
 * RPC surface. The Python driver is written against exactly these three methods
 * (configure / scanOnce / needle) and their result shapes — preserved verbatim
 * from the former single-file rpc.exports block.
 */
import { state } from "./state.js";
import { installExceptionHandler } from "./core/memory.js";
import { selectRanges, totalBytes } from "./core/ranges.js";
import { activateProfile, scanProfileOnce } from "./driver.js";

/** Build the object assigned to `rpc.exports` by the entry module. */
export function buildRpcExports(): any {
    // The one scan entry point, exported as scanOnce. frida-python's
    // _to_camel_case maps both `scanOnce` and `scan_once` to the same wire name
    // ('scanOnce'), so a second snake_case export alias would be unreachable —
    // the host reaches this method whether it calls rpc.scan_once() or
    // rpc.scanOnce().
    const scanOnce = function () {
        // Single profile (the common case): return that one profile's stats
        // object exactly as before. state.profiles is [profile] after configure,
        // or [null] when configure was never called (same error stats as before).
        var profiles = state.profiles !== null ? state.profiles : [state.profile];
        if (profiles.length <= 1) {
            return scanProfileOnce(profiles.length === 1 ? profiles[0] : null);
        }
        // Multiple profiles: run each and return an array of per-profile stats.
        var results = [];
        for (var i = 0; i < profiles.length; i++) results.push(scanProfileOnce(profiles[i]));
        return results;
    };
    return {
        configure: function (profileOrProfiles: any) {
            try {
                // Accept EITHER a single profile (today's shape) OR a list. A single
                // profile is normalised to a one-element list so scanOnce() has one
                // path; the RPC result keeps its single-profile shape below.
                var profiles = Array.isArray(profileOrProfiles) ? profileOrProfiles : [profileOrProfiles];
                state.profiles = profiles;
                installExceptionHandler();
                var totalRanges = 0;
                var totalRangeBytes = 0;
                var ids = [];
                for (var i = 0; i < profiles.length; i++) {
                    activateProfile(profiles[i]);
                    var ranges = selectRanges();
                    totalRanges += ranges.length;
                    totalRangeBytes += totalBytes(ranges);
                    ids.push(profiles[i].id);
                }
                // Single profile: identical result object to before (profileId is the
                // id string, ranges/rangeBytes are that profile's). Multiple: additive
                // fields only, never a breaking change to the single-profile contract.
                if (profiles.length === 1) {
                    return {
                        ok: true,
                        profileId: profiles[0].id,
                        ranges: totalRanges,
                        rangeBytes: totalRangeBytes
                    };
                }
                return {
                    ok: true,
                    profileId: ids,
                    profiles: profiles.length,
                    ranges: totalRanges,
                    rangeBytes: totalRangeBytes
                };
            } catch (e: any) {
                return { ok: false, error: e.message };
            }
        },

        scanOnce: scanOnce,

        needle: function () {
            if (state.needle === null) return null;
            return {
                value: state.needle.value.toString(),
                module: state.needle.module,
                rva: state.needle.rva
            };
        }
    };
}
