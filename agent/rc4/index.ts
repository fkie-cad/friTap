/**
 * agent/rc4/index.ts — PUBLIC RC4 key-capture hook unit.
 *
 * Registers the cross-platform RC4 key-setup hooks as contributed hook rows,
 * gated under `--protocol rc4`. RC4 is a FIRST-CLASS, INDEPENDENT protocol: it
 * does NOT imply TLS and TLS does not imply it. `registerProtocolImplication`
 * is therefore deliberately NOT called.
 *
 *   - `--protocol rc4`      → these RC4 key hooks install; no TLS hooks.
 *   - `--protocol tls,rc4`  → BOTH the TLS hooks and these RC4 key hooks install
 *                             (the nested plaintext→RC4→TLS case). No implication
 *                             — each is present only because it was selected.
 *   - `--protocol tls`      → no RC4 hooks (rc4 not in the selected set).
 *
 * Unlike the private Signal unit (wired only into the full build), RC4 is public
 * and wired directly into the public entry agent/fritap_agent.ts (a side-effect
 * import), so `collectContributedHooks()` returns these rows in every build. The
 * import runs before the platform loaders call `collectContributedHooks()`
 * during platform-load, so the rows are present at registration time.
 */
import { registerHookContributor } from "../shared/hook_contributors.js";
import {
    rc4_openssl_execute_linux,
    rc4_nettle_execute_linux,
    rc4_mbedtls_execute_linux,
} from "./platforms/linux/rc4_linux.js";
import {
    rc4_openssl_execute_darwin,
    rc4_nettle_execute_darwin,
    rc4_mbedtls_execute_darwin,
} from "./platforms/darwin/rc4_darwin.js";
import {
    rc4_cng_execute_windows,
    rc4_capi_execute_windows,
    rc4_openssl_execute_windows,
    rc4_mbedtls_execute_windows,
    rc4_nettle_execute_windows,
} from "./platforms/windows/rc4_windows.js";

// The RC4 core's known-answer self-test is NOT run here: this module is imported
// into every agent build, so a load-time KAT ran for every session regardless of
// --protocol. It runs lazily on the first RC4 hook install instead
// (ensureRc4SelfTest, called by makeRc4Executor in ./libs/rc4_hooks.ts).

registerHookContributor([
    // --- Linux + Android (registry platform "linux") ---
    { platform: "linux", pattern: /libcrypto.*\.so/, hookFn: rc4_openssl_execute_linux, library: "OpenSSL/LibreSSL/BoringSSL RC4 (RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "linux", pattern: /libssl.*\.so/, hookFn: rc4_openssl_execute_linux, library: "OpenSSL/BoringSSL RC4 (libssl, RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "linux", pattern: /libnettle.*\.so/, hookFn: rc4_nettle_execute_linux, library: "Nettle/GnuTLS RC4 (nettle_arcfour_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "linux", pattern: /libmbedcrypto.*\.so/, hookFn: rc4_mbedtls_execute_linux, library: "mbedTLS RC4 (mbedtls_arc4_setup)", libraryType: "rc4", protocol: "rc4" },
    { platform: "linux", pattern: /libmbedtls.*\.so/, hookFn: rc4_mbedtls_execute_linux, library: "mbedTLS RC4 (libmbedtls, mbedtls_arc4_setup)", libraryType: "rc4", protocol: "rc4" },

    // --- macOS + iOS (registry platform "darwin") ---
    { platform: "darwin", pattern: /libcrypto.*\.dylib/, hookFn: rc4_openssl_execute_darwin, library: "OpenSSL/LibreSSL/BoringSSL RC4 (RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "darwin", pattern: /libssl.*\.dylib/, hookFn: rc4_openssl_execute_darwin, library: "OpenSSL/BoringSSL RC4 (libssl, RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "darwin", pattern: /libnettle.*\.dylib/, hookFn: rc4_nettle_execute_darwin, library: "Nettle/GnuTLS RC4 (nettle_arcfour_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "darwin", pattern: /libmbedcrypto.*\.dylib/, hookFn: rc4_mbedtls_execute_darwin, library: "mbedTLS RC4 (mbedtls_arc4_setup)", libraryType: "rc4", protocol: "rc4" },
    { platform: "darwin", pattern: /libmbedtls.*\.dylib/, hookFn: rc4_mbedtls_execute_darwin, library: "mbedTLS RC4 (libmbedtls, mbedtls_arc4_setup)", libraryType: "rc4", protocol: "rc4" },

    // --- Windows (registry platform "windows") ---
    { platform: "windows", pattern: /bcrypt\.dll/i, hookFn: rc4_cng_execute_windows, library: "Windows CNG RC4 (BCryptGenerateSymmetricKey)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /advapi32\.dll/i, hookFn: rc4_capi_execute_windows, library: "Windows CryptoAPI RC4 (CryptEncrypt/CALG_RC4)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /libcrypto.*\.dll/i, hookFn: rc4_openssl_execute_windows, library: "OpenSSL RC4 (libcrypto DLL, RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /libeay32\.dll/i, hookFn: rc4_openssl_execute_windows, library: "OpenSSL RC4 (libeay32.dll, RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /libssl.*\.dll/i, hookFn: rc4_openssl_execute_windows, library: "OpenSSL/BoringSSL RC4 (libssl DLL, RC4_set_key)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /mbedcrypto.*\.dll/i, hookFn: rc4_mbedtls_execute_windows, library: "mbedTLS RC4 (mbedcrypto DLL, mbedtls_arc4_setup)", libraryType: "rc4", protocol: "rc4" },
    { platform: "windows", pattern: /nettle.*\.dll/i, hookFn: rc4_nettle_execute_windows, library: "Nettle RC4 (nettle DLL, nettle_arcfour_set_key)", libraryType: "rc4", protocol: "rc4" },
]);
