// agent/shared/ssl_layout_autolocate.ts
//
// Generic ssl_st layout lookup for stripped BoringSSL modules (libhttpengine in
// --modern, Cronet plaintext, and the Chromium monoliths of chromium_plaintext.ts).
//
// When a record of a module is about to be emitted without a client_random and
// no layout locator was ever started for that module, ssl_identity.ts reports
// the miss here. If the module looks like a stripped BoringSSL (arm64, no
// SSL_get_client_random export, not a known non-BoringSSL library) we start
// locateSslLayout() ONCE for it, in the background, install the decoded layout
// on success and mark the locator settled either way. Every other module is
// remembered as "considered" so the hot path pays one Set lookup per miss.
//
// Early trigger: the first record can arrive before a lookup that only starts on
// it has settled (~2.6 s on device), so plaintext hook installers call
// prefetchSslLayout(module) to start the very same, equally gated, once-per-module
// lookup at hook-install time. The client_random miss stays as the fallback
// trigger; both share one auto-locator, so a module is looked up at most once.
//
// The core (createSslLayoutAutoLocator) takes its Frida dependencies injected
// and is unit-tested under Node; the Frida wiring is installed by
// installSslLayoutAutoLocate(), called from the agent entry point.

import { devlog } from "../util/log.js";
import {
    hasLayoutLocatorStarted, markLayoutLocatorSettled, markLayoutLocatorStarted, setClientRandomMissObserver,
    setSslLayout,
} from "./ssl_identity.js";
import { findModuleExport } from "./module_exports.js";
import { locateSslLayout } from "./boringssl_anchor_locator.js";
import { pairip_safe } from "../fritap_agent.js";

/** Libraries that are never BoringSSL: their ssl_st differs, so a lookup is pointless. */
export const NON_BORINGSSL_MODULE_PATTERNS: readonly RegExp[] = [
    /^libssl[.-]/i, /^libcrypto[.-]/i, /gnutls/i, /nss3/i, /wolfssl/i, /mbedtls/i,
    /^libs2n/i, /matrixssl/i, /rustls/i, /schannel/i,
];

export interface SslLayoutAutoLocateDeps {
    isArm64(): boolean;
    /** False under --pairip-safe: the lookup is an xref memory scan. */
    scansAllowed(): boolean;
    /** True when the module exports SSL_get_client_random (the read path needs no layout). */
    hasClientRandomExport(module: string): boolean;
    locate(module: string): Promise<{ s3Off: number; crOff: number } | null>;
    log(message: string): void;
}

/** True when `module` is a known non-BoringSSL TLS library. */
export function isKnownNonBoringSslModule(module: string): boolean {
    return NON_BORINGSSL_MODULE_PATTERNS.some((pattern) => pattern.test(module));
}

/** Gate for a lookup: arm64, scans allowed, not a known non-BoringSSL library, and no client_random export. */
export function shouldLocateLayoutFor(module: string, deps: SslLayoutAutoLocateDeps): boolean {
    if (!module || !deps.isArm64() || !deps.scansAllowed() || isKnownNonBoringSslModule(module)) return false;
    try {
        return !deps.hasClientRandomExport(module);
    } catch (_e) {
        return false;
    }
}

/**
 * What started a lookup: a record that lacked client_random, a plaintext hook
 * being installed, or chromium_plaintext.ts hooking a stripped Chromium monolith.
 */
export type SslLayoutLookupTrigger = "client-random-miss" | "hook-install" | "chromium-install";

const TRIGGER_DESCRIPTIONS: Record<SslLayoutLookupTrigger, string> = {
    "client-random-miss": "record without client_random",
    "hook-install": "plaintext hooks installed",
    "chromium-install": "Chromium BoringSSL plaintext hooks installed",
};

/** Start the module's (async) layout lookup; settles the locator whatever the outcome. */
function startLayoutLookup(module: string, deps: SslLayoutAutoLocateDeps, trigger: SslLayoutLookupTrigger): Promise<void> {
    markLayoutLocatorStarted(module);
    deps.log(`[ssl-layout] ${module}: ${TRIGGER_DESCRIPTIONS[trigger]}; locating ssl_st layout`);
    return deps.locate(module)
        .then((layout) => {
            if (layout) setSslLayout(module, { s3Off: layout.s3Off, crOff: layout.crOff, source: "decoded", validated: false });
            else deps.log(`[ssl-layout] ${module}: ssl_st layout not decoded`);
        })
        .catch((e) => deps.log(`[ssl-layout] ${module}: ssl_st layout lookup failed: ${e}`))
        .finally(() => markLayoutLocatorSettled(module));
}

/** Decides once per module whether to look its layout up; returns the lookup promise, else null. */
export type SslLayoutAutoLocator = (module: string, trigger?: SslLayoutLookupTrigger) => Promise<void> | null;

/**
 * The shared trigger behind the client_random miss observer and the hook-install
 * prefetches: decides once per module, and starts at most one lookup per module —
 * none when a locator for it was already started elsewhere.
 * Returns the lookup promise (tests await it), else null.
 */
export function createSslLayoutAutoLocator(deps: SslLayoutAutoLocateDeps): SslLayoutAutoLocator {
    const consideredModules = new Set<string>();
    return (module: string, trigger: SslLayoutLookupTrigger = "client-random-miss") => {
        if (consideredModules.has(module)) return null;
        consideredModules.add(module);
        if (hasLayoutLocatorStarted(module) || !shouldLocateLayoutFor(module, deps)) return null;
        return startLayoutLookup(module, deps, trigger);
    };
}

const fridaAutoLocateDeps: SslLayoutAutoLocateDeps = {
    isArm64: () => Process.arch === "arm64",
    scansAllowed: () => !pairip_safe,
    hasClientRandomExport: (module) => findModuleExport(module, "SSL_get_client_random") !== null,
    locate: (module) => locateSslLayout(module),
    log: (message) => devlog(message),
};

let fridaAutoLocator: SslLayoutAutoLocator | null = null;

/** The one Frida-backed auto-locator shared by both triggers (so "once per module" holds across them). */
function sharedFridaAutoLocator(): SslLayoutAutoLocator {
    if (!fridaAutoLocator) fridaAutoLocator = createSslLayoutAutoLocator(fridaAutoLocateDeps);
    return fridaAutoLocator;
}

/** Register the Frida-backed auto-locator as ssl_identity's client_random miss observer. */
export function installSslLayoutAutoLocate(): void {
    const autoLocate = sharedFridaAutoLocator();
    setClientRandomMissObserver((module) => { autoLocate(module, "client-random-miss"); });
}

/**
 * Start the module's ssl_st layout lookup now, at plaintext-hook install time,
 * instead of on its first record without a client_random. Same gating (arm64,
 * no --pairip-safe, ...) and once-per-module guarantee as the lazy trigger.
 * Fire-and-forget; never throws.
 */
export function prefetchSslLayout(moduleName: string, trigger: SslLayoutLookupTrigger = "hook-install"): void {
    try {
        sharedFridaAutoLocator()(moduleName, trigger);
    } catch (e) {
        devlog(`[ssl-layout] ${moduleName}: layout prefetch failed: ${e}`);
    }
}
