// Pure helpers for the legacy OpenSSL_BoringSSL constructor's
// library_method_mapping (agent/legacy/tls/libs/openssl_boringssl.ts).
//
// Split out so the gate is unit-testable under Node: openssl_boringssl.ts
// itself cannot be imported there (fritap_agent / platform import cycles).

import { isDeepSymbolResolutionEnabled } from "../../../shared/deep_symbol_resolution.js";

export type SslMethodMapping = { [key: string]: Array<string> };

const CORE_SSL_METHODS = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"];
const SOCKET_METHODS = ["getpeername", "getsockname", "ntohs", "ntohl"];

/**
 * A module exposes a usable SSL surface either via enough dynamic exports
 * (.dynsym) or, for deep-resolution opt-ins (e.g. libhttpengine.so, which
 * exports only JNI_OnLoad), via the symbol-table fallback in readAddresses.
 * Shared with the modern agent/tls/libs/openssl_boringssl.ts.
 */
export function hasResolvableSslSurface(moduleName: string, exportCount: number): boolean {
    return exportCount > 2 || isDeepSymbolResolutionEnabled(moduleName);
}

/** The default mapping built when the caller passes none. */
export function buildDefaultSslMethodMapping(moduleName: string, socketLibrary: string, exportCount: number): SslMethodMapping {
    const mapping: SslMethodMapping = {};
    if (hasResolvableSslSurface(moduleName, exportCount)) {
        mapping[`*${moduleName}*`] = [...CORE_SSL_METHODS];
    }
    mapping[`*${socketLibrary}*`] = [...SOCKET_METHODS];
    return mapping;
}

/**
 * Append an optional method to the module's entry. Returns false (and adds
 * nothing) when the mapping has no entry for the module: the gate above
 * decided the module has no resolvable SSL surface, and a bare `.push` on the
 * missing key used to throw a TypeError that aborted the whole install.
 */
export function addModuleMethod(mapping: SslMethodMapping, moduleName: string, method: string): boolean {
    const methods = mapping[`*${moduleName}*`];
    if (!methods) return false;
    methods.push(method);
    return true;
}

/** True when readAddresses/pipeline produced a usable (non-null) address. */
export function isResolvedAddress(address: { isNull(): boolean } | null | undefined): boolean {
    return address !== null && address !== undefined && !address.isNull();
}
