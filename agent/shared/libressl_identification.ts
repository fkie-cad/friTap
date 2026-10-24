// agent/shared/libressl_identification.ts
//
// Content-based LibreSSL identification.
//
// The hook registry matches modules by NAME only (and path filters); it carries
// no content predicate. But on Linux/Windows/Wine a LibreSSL libssl is named
// exactly like a genuine OpenSSL one (libssl.so / libssl-*.dll), and a
// statically linked host (curl.exe) has no telling name at all. Since LibreSSL
// needs a completely different key-extraction path from OpenSSL/BoringSSL (KDF
// hooks, not the keylog callback / SSL_log_secret), the platform executors use
// this helper to decide at run time whether a module is LibreSSL before routing.
//
// Signal: LibreSSL stamps the literal version string "LibreSSL X.Y.Z" into the
// binary (returned by OpenSSL_version()/SSLeay_version()). Genuine OpenSSL and
// BoringSSL never contain the ASCII token "LibreSSL". The string check is
// cheapest, so it runs first; the symbol probe (tls13_hkdf_expand_label present,
// ssl_log_secret absent) only covers builds where the string isn't found.

import { devlog } from "../util/log.js";
import { findNonExportedSymbols } from "./shared_functions.js";
import { findAnchorString } from "./arm64_xref.js";

// Positive results are cached per module name so repeated routing decisions
// (base hook + dynamic-loader re-dispatch) don't re-scan a large image.
const _identCache = new Map<string, boolean>();

/**
 * True when `moduleName` is (or statically embeds) LibreSSL rather than genuine
 * OpenSSL / BoringSSL. Result is cached per module.
 */
export function isLibreSslModule(moduleName: string): boolean {
    const cached = _identCache.get(moduleName);
    if (cached !== undefined) return cached;

    let result = false;
    try {
        const mod = Process.getModuleByName(moduleName);

        // Primary: the "LibreSSL" version string.
        if (findAnchorString(mod, "LibreSSL")) {
            result = true;
        } else {
            // Secondary: KDF symbol present AND ssl_log_secret absent. BoringSSL
            // has ssl_log_secret; OpenSSL has neither tls13_hkdf_expand_label as
            // a distinct symbol pair nor the LibreSSL string, so this stays
            // specific to LibreSSL.
            const syms = findNonExportedSymbols(moduleName, [
                "tls13_hkdf_expand_label",
                "ssl_log_secret",
            ]);
            if (syms.get("tls13_hkdf_expand_label") && !syms.get("ssl_log_secret")) {
                result = true;
            }
        }
    } catch (e) {
        devlog(`[LibreSSL] identification of ${moduleName} failed: ${e}`);
    }

    _identCache.set(moduleName, result);
    if (result) devlog(`[LibreSSL] ${moduleName} identified as LibreSSL`);
    return result;
}

type Executor = (moduleName: string, is_base_hook: boolean) => void;

/**
 * Registry hookFn for a libssl module name that can be either LibreSSL or
 * OpenSSL/BoringSSL: routes to `libressl` or `other` by content.
 */
export function libresslAwareDispatch(libressl: Executor, other: Executor): Executor {
    return (moduleName, is_base_hook) =>
        (isLibreSslModule(moduleName) ? libressl : other)(moduleName, is_base_hook);
}
