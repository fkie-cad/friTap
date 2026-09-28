/**
 * agent/rc4/platforms/linux/rc4_linux.ts — Linux/Android RC4 key-setup executors.
 *
 * One `(moduleName, is_base_hook) => void` entry per RC4-bearing library family,
 * mirroring the tgnet/signal android executor shape. Registered in
 * agent/rc4/index.ts under protocol "rc4". The Android registry uses the "linux"
 * platform, so these cover both Linux and Android.
 */

import {
    makeRc4Executor,
    installOpenSslRc4Hooks,
    installNettleRc4Hooks,
    installMbedtlsRc4Hooks,
} from "../../libs/rc4_hooks.js";

/** OpenSSL / LibreSSL / BoringSSL (libcrypto/libssl) RC4_set_key. */
export const rc4_openssl_execute_linux = makeRc4Executor("openssl(linux)", installOpenSslRc4Hooks);
/** Nettle (GnuTLS) nettle_arcfour_set_key. */
export const rc4_nettle_execute_linux = makeRc4Executor("nettle(linux)", installNettleRc4Hooks);
/** mbedTLS mbedtls_arc4_setup. */
export const rc4_mbedtls_execute_linux = makeRc4Executor("mbedtls(linux)", installMbedtlsRc4Hooks);
