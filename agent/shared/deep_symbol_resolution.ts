// Per-module opt-in for "deep" symbol resolution.
//
// friTap's default symbol lookup (readAddresses / isSymbolAvailable in
// shared_functions.ts) is EXPORTS-ONLY: it consults the dynamic symbol table
// (.dynsym) via Frida's ApiResolver / Module.findGlobalExportByName. Some
// statically-linked BoringSSL hosts (e.g. libhttpengine.so) keep SSL_* in the
// general symbol table (.symtab — visible to Module.enumerateSymbols()) but NOT
// in .dynsym. For those, resolving exports-first then falling back to
// enumerateSymbols() lets the stealthier SSL_CTX_set_keylog_callback (heap
// write) keylog path install instead of dropping to the bssl::ssl_log_secret
// code patch.
//
// This module keeps the lib-specific knowledge OUT of the generic resolvers:
// shared_functions exposes the capability, and a library's executor opts the
// module in (see httpengine_execute / httpengine_execute_modern). That way the
// fallback stays scoped to exactly the modules that asked for it.

const deepModules = new Set<string>();

/** Opt `moduleName` into exports → enumerateSymbols() fallback resolution. */
export function enableDeepSymbolResolution(moduleName: string): void {
    deepModules.add(moduleName);
}

/** True if `moduleName` was opted into symbol-table fallback resolution. */
export function isDeepSymbolResolutionEnabled(moduleName: string): boolean {
    return deepModules.has(moduleName);
}
