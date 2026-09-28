/**
 * agent/rc4/platforms/darwin/rc4_darwin.ts — macOS/iOS RC4 key-setup executors.
 *
 * One `(moduleName, is_base_hook) => void` entry per RC4-bearing library family.
 * Registered in agent/rc4/index.ts under protocol "rc4". The macOS and iOS
 * registries both use the "darwin" platform, so these cover both.
 */

import {
    makeRc4Executor,
    installOpenSslRc4Hooks,
    installNettleRc4Hooks,
    installMbedtlsRc4Hooks,
} from "../../libs/rc4_hooks.js";

/** OpenSSL / LibreSSL / BoringSSL (libcrypto/libssl) RC4_set_key. */
export const rc4_openssl_execute_darwin = makeRc4Executor("openssl(darwin)", installOpenSslRc4Hooks);
/** Nettle (GnuTLS) nettle_arcfour_set_key. */
export const rc4_nettle_execute_darwin = makeRc4Executor("nettle(darwin)", installNettleRc4Hooks);
/** mbedTLS mbedtls_arc4_setup. */
export const rc4_mbedtls_execute_darwin = makeRc4Executor("mbedtls(darwin)", installMbedtlsRc4Hooks);
