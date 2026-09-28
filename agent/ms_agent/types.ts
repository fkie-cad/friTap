/*
 * Memory-scan agent type surface.
 *
 * Deliberately light: tsconfig has strictNullChecks/noImplicitAny OFF, and the
 * ported scanner logic is written in a pragmatic `any` style. The one type that
 * earns its keep is the engine contract, because it is the seam every current
 * and future engine (boringssl / schannel / rc4 / mtproto / ...) plugs into.
 */

/** A resolved pattern profile (one element of patterns.json). Layout is data. */
export type Profile = any;

/** Per-scan mutable counters/handles, built fresh by scanProfileOnce(). */
export type Stats = any;

/** A Tier-A-derived Tier-B needle: {value, module, rva}. */
export type NeedleInfo = { value: any; module: any; rva: any };

/*
 * A secret-extraction engine. A profile selects one via profile.engine; the
 * registry maps that string to the implementation. runTiers() keeps the exact
 * (ranges, stats, errors) signature the former runXxxTiers() functions used, so
 * moving a tier group behind this interface changes no behaviour.
 */
export interface MemscanEngine {
    /** Engine key matched against profile.engine (e.g. 'boringssl', 'mtproto'). */
    name: string;
    /** Run this engine's tier group for the active profile, emitting via send(). */
    runTiers(ranges: any, stats: Stats, errors: string[]): void;
}
