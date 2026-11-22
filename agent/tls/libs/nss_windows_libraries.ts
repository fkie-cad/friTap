// agent/tls/libs/nss_windows_libraries.ts
//
// Which Windows module carries which NSS/NSPR symbols. One source for the legacy
// hooker (agent/legacy/tls/platforms/windows/nss_windows.ts), the modern definition
// (createNssWindowsDefinition in agent/tls/definitions/nss.ts) and the Windows/Wine
// platform rows (agent/platforms/windows.ts, agent/platforms/wine.ts).
//
// Two layouts exist on Windows:
//   - folded (MOZ_FOLD_LIBS, Firefox/Thunderbird): NSPR, ssl3, nssutil and smime
//     are linked into nss3.dll, so ONE module exports PR_*, SSL_* and PK11_*;
//   - unfolded (standalone NSS builds, mingw): nspr4.dll / libnspr4.dll export PR_*,
//     ssl3.dll / libssl3.dll export SSL_*, nss3.dll / libnss3.dll export PK11_*.
// The aux patterns are exact suffixes on purpose: a `*ssl*.dll` glob would also
// match OpenSSL's libssl-3-x64.dll / libssl-1_1.dll.

/** NSPR I/O + identity exports the plaintext hooks and the NSS helpers need. */
export const NSPR_IO_SYMBOLS: readonly string[] = [
    "PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName",
    "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType",
];

/** nss3 exports the pre-3.115 keylog path (tier 3) reads secrets with. */
export const NSS_PK11_SYMBOLS: readonly string[] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];

/** ssl3 exports the key-extraction tiers and the session-id path use. */
export const NSS_SSL_SYMBOLS: readonly string[] = [
    "SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback",
    "SSL_GetExperimentalAPI", "NSSSSL_GetVersion",
];

/** nss3 exports the OHTTP hooks (agent/ohttp/definitions/nss_hpke.ts) attach to; NSS >= 3.58. */
export const NSS_HPKE_SYMBOLS: readonly string[] = ["PK11_HPKE_Seal", "PK11_HPKE_Open"];

/** Module names that may export NSPR's PR_Read/PR_Write: (lib)nspr4.dll or a folded (lib)nss3.dll. */
export const NSS_WINDOWS_MODULE_PATTERN = /^(lib)?(nspr[0-9]*|nss3)\.dll$/i;

/**
 * (lib)nss3.dll. Also the module the NSS HPKE (OHTTP) row hooks: PK11_HPKE_* live in it in
 * BOTH layouts (folded or not), so nspr4.dll is never an HPKE host and is not matched.
 */
export const NSS3_MODULE_NAME = /^(lib)?nss3\.dll$/i;

/** True for an nss3.dll name; whether it is really folded is decided by its exports (exportsNsprIo). */
export function isNss3ModuleName(moduleName: string): boolean {
    return NSS3_MODULE_NAME.test(moduleName);
}

/** Symbols resolved in the hooked module itself. A folded nss3.dll carries all of them. */
export function nssWindowsLibrarySymbols(moduleName: string): string[] {
    if (isNss3ModuleName(moduleName)) {
        return [...NSPR_IO_SYMBOLS, ...NSS_PK11_SYMBOLS, ...NSS_SSL_SYMBOLS];
    }
    return [...NSPR_IO_SYMBOLS];
}

/** Sibling modules to resolve from: none for a folded nss3.dll, nss3 + ssl3 for an unfolded NSPR. */
export function nssWindowsAuxiliaryLibraries(moduleName: string): Array<{ pattern: string; symbols: string[] }> {
    if (isNss3ModuleName(moduleName)) return [];
    return [
        { pattern: "*nss3.dll", symbols: [...NSS_PK11_SYMBOLS] },
        { pattern: "*ssl3.dll", symbols: [...NSS_SSL_SYMBOLS] },
    ];
}

/** Legacy-style library_method_mapping for one hooked Windows NSS module (+ the socket library). */
export function nssWindowsMethodMapping(moduleName: string, socketLibrary: string): { [pattern: string]: string[] } {
    const mapping: { [pattern: string]: string[] } = {};
    mapping[`*${moduleName}*`] = nssWindowsLibrarySymbols(moduleName);
    for (const aux of nssWindowsAuxiliaryLibraries(moduleName)) {
        mapping[aux.pattern] = aux.symbols;
    }
    mapping[`*${socketLibrary}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    return mapping;
}

const nsprIoVerdicts = new Map<string, boolean>();

/**
 * Platform-row content filter: an nspr*.dll always qualifies; an nss3.dll only when
 * it exports PR_Read (folded). An unfolded nss3.dll is skipped, so NSS is hooked once,
 * via its nspr4.dll. Cached per module name; never throws.
 */
export function exportsNsprIo(moduleName: string): boolean {
    if (!isNss3ModuleName(moduleName)) return true;
    const cached = nsprIoVerdicts.get(moduleName);
    if (cached !== undefined) return cached;
    try {
        const mod = Process.findModuleByName(moduleName);
        if (mod === null) return false;   // not mapped (yet): do not cache a verdict
        const prRead = mod.findExportByName("PR_Read");
        const verdict = prRead !== null && !prRead.isNull();
        nsprIoVerdicts.set(moduleName, verdict);
        return verdict;
    } catch (_e) {
        return false;
    }
}

/** Test hook: forget cached exportsNsprIo verdicts. */
export function resetNsprIoVerdictsForTest(): void {
    nsprIoVerdicts.clear();
}
