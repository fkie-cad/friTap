// agent/tls/shared/learned_plaintext_cache.ts
//
// Agent side of the host's learned plaintext-RVA cache (friTap/learned_offsets.py).
// The host entries (config_batch.learned_plaintext, keyed by `build_id|size|arch`)
// are read through the installed LearnedModuleCache; locator hits are reported
// back as `plaintext_api_learned` so the next run on the same library build skips the scan.

import { devlog_debug } from "../../util/log.js";
import { PlaintextApiLearnedPayload, sendPlaintextApiLearned } from "../../shared/shared_structures.js";
import {
    type ModuleIdentity, type PrologueHasher, identifyModule, isPlainObject, isRva, isSha256Hex, learnedHostEntry,
    learnedKey, moduleBasename, reportCacheHit, rvaOf, sha256Prologue,
} from "../../shared/learned_module_cache.js";
import type { PlaintextPrologueHashes, PlaintextRvas } from "../../schemas/messages.js";
import { LocatedPlaintextApi } from "./boringssl_plaintext_locator.js";
import {
    LearnedPlaintextEntry, LearnedPlaintextSource, LocatorResolvedListener, PlaintextModule,
    setLearnedPlaintextSource, setLocatorResolvedListener,
} from "./boringssl_plaintext_resolver.js";

export { identifyModule, learnedKey };
export type { ModuleIdentity };

/** One value of the host's entries_for_agent() dict (always complete: both functions). */
export interface HostLearnedEntry {
    module: string;
    rvas: PlaintextRvas;
    prologue_sha256: PlaintextPrologueHashes;
}
export type HostLearnedEntries = Record<string, HostLearnedEntry>;

export type ModuleIdentifier = (mod: PlaintextModule) => ModuleIdentity | null;

function pickBoth<T>(source: unknown, isValid: (v: unknown) => v is T): { SSL_read: T; SSL_write: T } | null {
    if (!isPlainObject(source)) return null;
    const { SSL_read, SSL_write } = source;
    return isValid(SSL_read) && isValid(SSL_write) ? { SSL_read, SSL_write } : null;
}

/** The host entry as the resolver's LearnedPlaintextEntry; null unless both functions are valid in a module of `size` bytes. */
export function toLearnedEntry(entry: unknown, size: number): LearnedPlaintextEntry | null {
    if (!isPlainObject(entry)) return null;
    const rvas = pickBoth(entry.rvas, (v: unknown): v is number => isRva(v, size));
    const prologueSha256 = pickBoth(entry.prologue_sha256, isSha256Hex);
    return rvas !== null && prologueSha256 !== null ? { rvas, prologueSha256 } : null;
}

/**
 * A LearnedPlaintextSource over the installed LearnedModuleCache's host entries.
 * An accepted entry counts as that cache's (once per module per session) cache hit.
 */
export function createLearnedPlaintextSource(): LearnedPlaintextSource {
    return {
        lookup(mod: PlaintextModule): LearnedPlaintextEntry | null {
            return toLearnedEntry(learnedHostEntry(mod), mod.size);
        },
        onAccepted(mod: PlaintextModule): void {
            reportCacheHit(mod);
        },
    };
}

/** The `plaintext_api_learned` payload for a locator hit, or null when it cannot be cached. */
export function learnedMessage(mod: PlaintextModule, api: LocatedPlaintextApi, identity: ModuleIdentity,
                               hashPrologue: PrologueHasher = sha256Prologue): PlaintextApiLearnedPayload | null {
    const readRva = rvaOf(mod, api.sslRead, identity.size);
    const writeRva = rvaOf(mod, api.sslWrite, identity.size);
    if (readRva === null || writeRva === null) return null;
    const readHash = hashPrologue(api.sslRead);
    const writeHash = hashPrologue(api.sslWrite);
    if (readHash === null || writeHash === null) return null;
    return {
        module: moduleBasename(mod.name),
        build_id: identity.buildId,
        size: identity.size,
        arch: identity.arch,
        rvas: { SSL_read: readRva, SSL_write: writeRva },
        prologue_sha256: { SSL_read: readHash.toLowerCase(), SSL_write: writeHash.toLowerCase() },
    };
}

/** Locator listener that reports each cacheable hit to the host. */
export function createLocatorReporter(identify: ModuleIdentifier = identifyModule,
                                      emit: (message: PlaintextApiLearnedPayload) => void = sendPlaintextApiLearned,
                                      hashPrologue: PrologueHasher = sha256Prologue): LocatorResolvedListener {
    return (mod, api, elapsedMs) => {
        const identity = identify(mod);
        const message = identity === null ? null : learnedMessage(mod, api, identity, hashPrologue);
        if (message === null) {
            devlog_debug(`[BoringSSL plaintext] ${mod.name}: locator hit not cacheable (no build id or partial API)`);
            return;
        }
        devlog_debug(`[BoringSSL plaintext] ${mod.name}: reporting locator hit (${elapsedMs} ms) for the learned cache`);
        emit(message);
    };
}

/**
 * Wire the resolver to the host cache: look up entries in the installed
 * LearnedModuleCache (installLearnedModuleCache) and report locator hits.
 */
export function installLearnedPlaintextCache(): void {
    setLearnedPlaintextSource(createLearnedPlaintextSource());
    setLocatorResolvedListener(createLocatorReporter());
}
