// agent/shared/boringssl_learned_keylog.ts
//
// The byte-pattern tier and tier 4 both find bssl::ssl_log_secret; tier 4 stores
// it in the learned-offsets cache as LEARNED_SSL_LOG_SECRET. This module lets the
// pattern tier (legacy and modern) reuse that entry instead of re-scanning a
// large module like libchrome.so, and feed its own matches back into the cache.

import { devlog_debug } from "../util/log.js";
import type { CacheModule } from "./module_mapping.js";
import {
    type DecodeVerdict, reportDecodedSslLogSecret, sslLogSecretDecodes, validatedLearnedSslLogSecret,
} from "./boringssl_anchor_locator.js";
import { attachSslLogSecretHook, type DumpKeysCb } from "./boringssl_symbol_hook.js";
import { claimForLiveSslLogSecretHook, guardKeylogDumpKeys, type KeylogHookTier } from "./boringssl_keylog_outcome.js";
import { hasUsablePatternsFor } from "../tls/shared/cronet_patterns.js";

export interface LearnedSslLogSecretDeps {
    arch: () => string;
    decodes: (mod: CacheModule, fnAddr: NativePointer) => DecodeVerdict;
    attach: (fnAddr: NativePointer, tier: KeylogHookTier, cb: DumpKeysCb, moduleName: string) => boolean;
}

const defaultDeps: LearnedSslLogSecretDeps = {
    arch: () => Process.arch,
    // attachSslLogSecretHook reads the call's arguments, so the s3/cr decode suffices too.
    decodes: sslLogSecretDecodes,
    attach: attachSslLogSecretHook,
};

/** User-supplied (--patterns) JSON and the pattern-file key consulted when the module has none. */
export interface UserDumpKeysPatterns {
    json: string | undefined;
    fallbackModuleName: string;
}

/** True when the user supplied Dump-Keys patterns for `moduleName`; they win over the learned cache, like --offsets. */
export function userDumpKeysPatternsApply(moduleName: string, user: UserDumpKeysPatterns): boolean {
    return !!user.json && hasUsablePatternsFor(user.json, moduleName, user.fallbackModuleName, "Dump-Keys");
}

/** Learned entries are written by the arm64 locator and validated by its arm64 body decode. */
function cacheApplies(deps: LearnedSslLogSecretDeps): boolean {
    return deps.arch() === "arm64";
}

/**
 * Hook ssl_log_secret from the learned cache. True iff the hook is live, so the
 * caller skips its pattern scan and the deferred symbol fallback / tier 4.
 */
export function hookLearnedSslLogSecret(mod: CacheModule, dumpKeys: DumpKeysCb,
                                        deps: LearnedSslLogSecretDeps = defaultDeps): boolean {
    if (!cacheApplies(deps)) return false;
    const fnAddr = validatedLearnedSslLogSecret(mod, (a) => deps.decodes(mod, a), `[bssl-learned] ${mod.name}`);
    if (fnAddr === null) return false;
    if (!deps.attach(fnAddr, "pattern", guardKeylogDumpKeys(mod.name, "pattern", dumpKeys), mod.name)) return false;
    // Claimed up front so no later tier (tier 4, a parallel symbol hook) installs a second
    // hook. A tier that already hooked this address keeps the claim: only its guard emits.
    claimForLiveSslLogSecretHook(mod.name, fnAddr, "pattern");
    devlog_debug(`ssl_log_secret for ${mod.name} from learned cache (pattern path skipped)`);
    return true;
}

/**
 * hookLearnedSslLogSecret for a module by name, unless the user's Dump-Keys
 * patterns cover it. `findModule` overrides the lookup (e.g. a .so-name fallback).
 */
export function hookLearnedSslLogSecretByName(moduleName: string, dumpKeys: DumpKeysCb, user: UserDumpKeysPatterns,
                                              findModule: () => CacheModule | null = () => Process.findModuleByName(moduleName),
                                              deps: LearnedSslLogSecretDeps = defaultDeps): boolean {
    if (userDumpKeysPatternsApply(moduleName, user)) return false;
    const mod = findModule();
    return mod !== null && hookLearnedSslLogSecret(mod, dumpKeys, deps);
}

/** Report a pattern-matched ssl_log_secret to the learned cache once its body decodes. */
export function reportPatternMatchedSslLogSecret(mod: CacheModule, matchedAddress: NativePointer | null,
                                                 deps: LearnedSslLogSecretDeps = defaultDeps): boolean {
    if (matchedAddress === null || !cacheApplies(deps)) return false;
    return reportDecodedSslLogSecret(mod, matchedAddress, (a) => deps.decodes(mod, a));
}
