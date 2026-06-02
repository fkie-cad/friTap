// Modern Cronet executor.
//
// Keylog (+ the SSL_free lifecycle hook) is installed by the shared BoringSSL
// family executor via the three-tier chain. PLAINTEXT capture is owned by the
// Cronet class: we pass skipReadWriteHooks:true so the generic definition path
// does NOT also install SSL_read/SSL_write — the Cronet class is the single
// owner, which avoids emitting duplicate PCAP frames.
//
// The Cronet class:
//   - uses the symbol-resolved SSL_get_fd decoder when the fork exports the
//     read/write/fd/session symbols (e.g. libwarp_mobile.so) — this is the
//     legacy Cronet plaintext implementation, ported into the modern path; and
//   - exposes a pattern-based SSL_get_fd hook point (resolveSslGetFdPattern)
//     for stripped builds that inline BoringSSL and export nothing.
//
// Platforms that intentionally stay keylog-only (iOS, macOS) keep calling
// executeBoringSSLFamily directly and do NOT route through here.

import { executeBoringSSLFamily } from "./boringssl_family_executor.js";
import { Cronet } from "../libs/cronet.js";

export function cronetExecuteModern(
    moduleName: string,
    socketLibrary: string,
    isBaseHook: boolean,
    enableDefaultFd: boolean,
): void {
    // Keylog + lifecycle via the family chain; generic read/write suppressed so
    // the Cronet class can own plaintext without double-hooking.
    executeBoringSSLFamily(moduleName, socketLibrary, isBaseHook, enableDefaultFd, {
        skipReadWriteHooks: true,
    });

    const cronet = new Cronet(moduleName, socketLibrary, isBaseHook);
    cronet.install_plaintext_read_hook();
    cronet.install_plaintext_write_hook();
}
