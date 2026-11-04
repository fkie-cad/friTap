// Legacy import path for the OpenSSL_BoringSSL method-mapping helpers.
// The implementation moved to agent/tls/shared/ssl_method_mapping.ts so the
// modern tree (agent/tls/**) no longer imports agent/legacy/**; this module
// re-exports it unchanged so legacy importers (and their test) keep working.

export type { SslMethodMapping } from "../../../tls/shared/ssl_method_mapping.js";
export { hasResolvableSslSurface, buildDefaultSslMethodMapping, addModuleMethod, isResolvedAddress } from "../../../tls/shared/ssl_method_mapping.js";
