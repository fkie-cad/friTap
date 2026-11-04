/**
 * agent/rc4/platforms/windows/rc4_windows.ts — Windows RC4 key-setup executors.
 *
 * One `(moduleName, is_base_hook) => void` entry per RC4 provider on Windows:
 * the two Windows crypto providers (CNG bcrypt.dll, legacy CryptoAPI
 * advapi32.dll) plus the cross-platform crypto libraries when present as DLLs
 * (OpenSSL, mbedTLS, Nettle). Registered in agent/rc4/index.ts under protocol
 * "rc4". Mirrors the Windows executor shape used by agent/tls/platforms/windows.
 */

import {
    makeRc4Executor,
    installOpenSslRc4Hooks,
    installNettleRc4Hooks,
    installMbedtlsRc4Hooks,
    installWindowsCngRc4Hooks,
    installWindowsCapiRc4Hooks,
} from "../../libs/rc4_hooks.js";
import { ensureRc4WindowsMemscanArmed } from "../../libs/rc4_memscan.js";
import { devlog } from "../../../util/log.js";

// bcrypt.dll and advapi32.dll are loaded in virtually every Windows process, so
// installing either RC4 provider hook is a reliable moment to ALSO arm the managed-RC4
// memory-scan recovery (SSPI ciphertext capture + trial-decrypt). That covers programs
// that implement RC4 themselves in managed byte arrays and never call a crypto API — the
// API hooks below never fire for them, but the in-memory key is still recoverable. Arming
// is idempotent, so doing it from both providers is harmless.
// The executor reports what actually attached: the RC4 library is announced only when an
// API hook did. The memory recovery is a process-wide capability, not a hook on this
// provider, so arming it never makes the provider count as hooked.
function installProviderPlusMemscan(install: (moduleName: string) => boolean, moduleName: string): boolean {
    const hooked = install(moduleName);
    ensureRc4WindowsMemscanArmed();
    if (!hooked) devlog(`[rc4] ${moduleName}: no RC4 API hook attached; managed-RC4 memory recovery armed only`);
    return hooked;
}
function installCngRc4PlusMemscan(moduleName: string): boolean {
    return installProviderPlusMemscan(installWindowsCngRc4Hooks, moduleName);
}
function installCapiRc4PlusMemscan(moduleName: string): boolean {
    return installProviderPlusMemscan(installWindowsCapiRc4Hooks, moduleName);
}

/** Windows CNG (bcrypt.dll): BCryptOpenAlgorithmProvider + BCryptGenerateSymmetricKey, plus managed-RC4 memory recovery. */
export const rc4_cng_execute_windows = makeRc4Executor("cng(windows)", installCngRc4PlusMemscan);
/** Windows legacy CryptoAPI (advapi32.dll): CryptEncrypt + CryptGetKeyParam + CryptExportKey, plus managed-RC4 memory recovery. */
export const rc4_capi_execute_windows = makeRc4Executor("capi(windows)", installCapiRc4PlusMemscan);
/** OpenSSL / LibreSSL / BoringSSL (libcrypto/libeay/libssl DLLs) RC4_set_key. */
export const rc4_openssl_execute_windows = makeRc4Executor("openssl(windows)", installOpenSslRc4Hooks);
/** mbedTLS mbedtls_arc4_setup. */
export const rc4_mbedtls_execute_windows = makeRc4Executor("mbedtls(windows)", installMbedtlsRc4Hooks);
/** Nettle nettle_arcfour_set_key. */
export const rc4_nettle_execute_windows = makeRc4Executor("nettle(windows)", installNettleRc4Hooks);
