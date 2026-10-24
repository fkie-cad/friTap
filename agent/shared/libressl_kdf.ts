// agent/shared/libressl_kdf.ts
//
// Shared LibreSSL key-derivation-function locator and tls1_PRF hook, used by
// BOTH the modern definition (agent/tls/definitions/libressl.ts) and the legacy class
// (agent/legacy/tls/platforms/macos/libressl_macos.ts, reused on every platform).
//
// WHY THIS EXISTS
// ---------------
// LibreSSL has NO keylog mechanism: SSL_CTX_set_keylog_callback exists (3.5+)
// but is *never invoked* by LibreSSL, and there is no SSL_log_secret (that is
// BoringSSL-only). Keys can only be reconstructed by hooking LibreSSL's internal
// key-schedule functions:
//   * TLS 1.3: tls13_hkdf_expand_label / tls13_hkdf_expand_label_with_length
//   * TLS 1.2: tls1_PRF
//
// These are not exported. On a dynamically-linked libssl (libssl.so /
// libssl-*.dll) they usually survive in the symbol table and
// findNonExportedSymbols() resolves them. On a *statically linked, stripped*
// host (e.g. a curl-for-win curl.exe) the symbol table is gone, so we fall back
// to byte-pattern scanning. This module unifies both so the platform executors
// stay thin.

import { devlog, devlog_error, log } from "../util/log.js";
import { findNonExportedSymbols } from "./shared_functions.js";
import { normalizeArchKey, currentPlatformKey } from "../util/process_infos.js";
import { sendKeylog } from "./shared_structures.js";
import { readHexFromPointer } from "../tls/decoders/hex_utils.js";
import { readSslClientRandom, getLibreSslClientRandom } from "./libressl_client_random.js";

export interface LibreSslKdfAddrs {
    /** tls13_hkdf_expand_label (fixed-length-label variant). */
    hkdf: NativePointer | null;
    /** tls13_hkdf_expand_label_with_length (explicit label-length variant). */
    hkdfWithLen: NativePointer | null;
    /** tls1_PRF (TLS 1.2). arg0 is the SSL*. */
    prf: NativePointer | null;
}

type KdfKind = "hkdfWithLen" | "prf";

// Bundled x86-64 byte signatures (Win64 ABI, as compiled into PE binaries),
// derived from the curl-for-win LibreSSL 4.4.0 build. They are build-specific;
// other builds/arches supply overrides via --patterns (see resolveKdfPattern)
// or regenerate them with agent_gdb/wine/utils/wine_hunter.py.
//
// LEGACY-SYNC: mirrors friTap/patterns/default_patterns.json#libressl.
export const BUNDLED_LIBRESSL_KDF: Record<string, Partial<Record<KdfKind, string>>> = {
    x64: {
        // tls13_hkdf_expand_label_with_length @ curl-for-win 4.4.0:
        //   endbr64; push rbp; push r14; push rsi; push rdi; push rbx;
        //   sub rsp, 0xA0; lea rbp, [rsp+0x80]
        hkdfWithLen:
            "F3 0F 1E FA 55 41 56 56 57 53 48 81 EC A0 00 00 00 48 8D AC 24 80 00 00",
        // tls1_PRF @ curl-for-win 4.4.0:
        //   endbr64; push rbp; push r15..r12; push rsi; push rdi; push rbx;
        //   sub rsp, 0xD8
        prf:
            "F3 0F 1E FA 55 41 57 41 56 41 55 41 54 56 57 53 48 81 EC D8 00 00 00",
    },
};

function nodeToPatterns(node: any): string[] {
    if (!node) return [];
    if (typeof node === "string" && node.length > 0) return [node];
    if (Array.isArray(node)) return node.filter((p) => typeof p === "string" && p.length > 0);
    const list: string[] = [];
    for (const key of ["primary", "fallback", "second_fallback"]) {
        const p = node[key];
        if (typeof p === "string" && p.length > 0) list.push(p);
    }
    return list;
}

/**
 * Ordered byte patterns for one KDF function: a user --patterns override if
 * present, else the bundled bytes for this arch (empty if neither). Accepted
 * override paths, each a string, string[] or {primary,fallback,second_fallback}:
 *
 *   modules.libressl.<arch>.<kind>        (legacy pattern.json shape)
 *   libressl.<platform>.<arch>.<kind>     (default_patterns.json shape)
 *   libressl.<arch>.<kind>
 */
export function resolveKdfPattern(kind: KdfKind, userPatterns: any): string[] {
    const archKey = normalizeArchKey(Process.arch);
    const platformKey = currentPlatformKey();
    try {
        const candidates = [
            userPatterns?.modules?.libressl?.[archKey]?.[kind],
            userPatterns?.libressl?.[platformKey]?.[archKey]?.[kind],
            userPatterns?.libressl?.[archKey]?.[kind],
        ];
        for (const node of candidates) {
            const list = nodeToPatterns(node);
            if (list.length > 0) {
                devlog(`[LibreSSL] Using --patterns override (arch=${archKey}) for ${kind}`);
                return list;
            }
        }
    } catch (e) {
        devlog_error(`[LibreSSL] Error reading --patterns override for ${kind}: ${e}`);
    }

    const bundled = BUNDLED_LIBRESSL_KDF[archKey]?.[kind];
    return bundled ? [bundled] : [];
}

/** First match of `pattern` within the module's executable (r-x / rwx) ranges. */
function scanModuleFirst(moduleName: string, pattern: string): NativePointer | null {
    let mod: Module;
    try {
        mod = Process.getModuleByName(moduleName);
    } catch (e) {
        devlog(`[LibreSSL] scan: module ${moduleName} not found: ${e}`);
        return null;
    }
    for (const prot of ["r-x", "rwx"]) {
        let ranges: RangeDetails[];
        try {
            ranges = mod.enumerateRanges(prot);
        } catch (_) {
            continue;
        }
        for (const r of ranges) {
            try {
                const matches = Memory.scanSync(r.base, r.size, pattern);
                if (matches.length > 0) return matches[0].address;
            } catch (_) {
                // range became unreadable; keep scanning
            }
        }
    }
    return null;
}

function scanKdf(moduleName: string, kind: KdfKind, userPatterns: any): NativePointer | null {
    for (const pat of resolveKdfPattern(kind, userPatterns)) {
        const m = scanModuleFirst(moduleName, pat);
        if (m) {
            log(`[LibreSSL] located ${kind} via byte pattern @ ${m} in ${moduleName}`);
            return m;
        }
    }
    return null;
}

/**
 * Resolve LibreSSL's KDF function addresses: symbol table first (dynamic/
 * symbol-bearing builds), then byte-pattern scan (stripped static builds).
 *
 * @param moduleName   module to resolve within (the libssl module, or the main
 *                     image for a statically linked host)
 * @param userPatterns optional parsed --patterns object for overrides
 */
export function findLibreSslKdfAddresses(moduleName: string, userPatterns?: any): LibreSslKdfAddrs {
    const nonExported = findNonExportedSymbols(moduleName, [
        "tls13_hkdf_expand_label",
        "tls13_hkdf_expand_label_with_length",
        "tls1_PRF",
    ]);

    const hkdf = nonExported.get("tls13_hkdf_expand_label") ?? null;
    let hkdfWithLen = nonExported.get("tls13_hkdf_expand_label_with_length") ?? null;
    let prf = nonExported.get("tls1_PRF") ?? null;

    // Byte-pattern fallback only for the functions the symbol table missed.
    if (!hkdfWithLen && !hkdf) hkdfWithLen = scanKdf(moduleName, "hkdfWithLen", userPatterns);
    if (!prf) prf = scanKdf(moduleName, "prf", userPatterns);

    return { hkdf, hkdfWithLen, prf };
}

/**
 * Hook tls1_PRF (TLS 1.2) and emit CLIENT_RANDOM lines.
 *
 * Dynamic path: SSL_get_client_random(SSL*) + `masterKey(SSL*)`.
 * Stripped path: the "key expansion" PRF carries the master secret in its
 * register args (secret=arg1, len=arg2, label=arg3); client_random comes from
 * the ClientHello send() capture. No SSL*, symbol or struct offset needed.
 */
export function attachLibreSslPrfHook(
    addr: NativePointer,
    SSL_get_client_random: NativeFunction<any, any> | null | undefined,
    masterKey: (ssl: NativePointer) => string | null,
): void {
    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            this.sslPtr = args[0];
            // Capture here: the args are only valid onEnter.
            try {
                if (args[3].readCString() === "key expansion") {
                    this.kxSecret = args[1];
                    this.kxSecretLen = args[2].toInt32();
                }
            } catch (_) { /* not the key-expansion call */ }
        },
        onLeave: function (_retval: any) {
            try {
                const sslCr = readSslClientRandom(SSL_get_client_random, this.sslPtr);
                const sslMaster = sslCr ? masterKey(this.sslPtr) : null;
                if (sslCr && sslMaster) {
                    devlog("invoking tls1_PRF keylog hook from LibreSSL (dynamic)");
                    sendKeylog(`CLIENT_RANDOM ${sslCr} ${sslMaster}`);
                    return;
                }
                if (this.kxSecret && this.kxSecretLen > 0 && this.kxSecretLen <= 64 &&
                    !this.kxSecret.isNull()) {
                    const clientRandom = getLibreSslClientRandom();
                    if (!clientRandom) return;
                    devlog("invoking tls1_PRF keylog hook from LibreSSL (stripped/args)");
                    sendKeylog(`CLIENT_RANDOM ${clientRandom} ${readHexFromPointer(this.kxSecret, this.kxSecretLen)}`);
                }
            } catch (e) {
                devlog_error(`[LibreSSL] tls1_PRF onLeave error: ${e}`);
            }
        },
    });
}
