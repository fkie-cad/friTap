// agent/shared/optional_ssl_fd_session.ts
//
// Binds the per-record SSL helpers. A deep-resolved static BoringSSL (e.g. libhttpengine.so) may
// lack SSL_get_fd / SSL_SESSION_get_id; those get stand-ins: fd -1 (SSL-scoped fd recovery) and
// an empty session id.

import { isResolvedAddress } from "../tls/shared/ssl_method_mapping.js";

/** SSL_get_fd stand-in for a module without one: always take the deferred (SSL-scoped) fd path. */
export const fdLessSslGetFd = (_ssl: NativePointer): number => -1;

/**
 * SSL_SESSION_get_id(session, *outLength) stand-in for a module without one: a
 * zero-length id (writes 0 to *outLength, returns NULL), so the hosts'
 * getSslSessionId hex loop reads nothing and reports "".
 */
export const sessionlessSslSessionGetId = (_session: NativePointer, outLength: NativePointer): NativePointer => {
    outLength.writeU32(0);
    return NULL;
};

/** `new NativeFunction(...)`, injectable so the binding logic is testable without Frida. */
export type NativeFunctionFactory = (address: NativePointer, returnType: string, argTypes: string[]) => any;

const fridaNativeFunction: NativeFunctionFactory =
    (address, returnType, argTypes) => new NativeFunction(address, returnType as any, argTypes as any);

export interface SslFdSessionFunctions {
    SSL_get_fd: any;
    SSL_get_session: any;
    /** sessionlessSslSessionGetId when the module has no SSL_SESSION_get_id (session id reported as ""). */
    SSL_SESSION_get_id: any;
    /** The optional symbols that were unresolved and replaced by a stand-in (empty = unchanged binding). */
    fallbacks: string[];
    /** SSL_get_fd is the fdLessSslGetFd stand-in, so every record is fd-less. */
    fdLess: boolean;
}

/** Bind the helpers from `addresses`; `fdFunctionName` is "SSL_get_fd" or "BIO_get_fd". A missing SSL_get_session still throws. */
export function bindOptionalSslFdAndSession(
    addresses: { [functionName: string]: NativePointer | undefined },
    fdFunctionName: string,
    makeNativeFunction: NativeFunctionFactory = fridaNativeFunction,
): SslFdSessionFunctions {
    const fallbacks: string[] = [];
    const bindOptional = (name: string, returnType: string, argTypes: string[]): any | null => {
        const address = addresses[name];
        if (isResolvedAddress(address)) return makeNativeFunction(address as NativePointer, returnType, argTypes);
        fallbacks.push(name);
        return null;
    };
    const sessionGetId = bindOptional("SSL_SESSION_get_id", "pointer", ["pointer", "pointer"]);
    const getFd = bindOptional(fdFunctionName, "int", ["pointer"]);
    const getSession = makeNativeFunction(addresses["SSL_get_session"] as NativePointer, "pointer", ["pointer"]);
    return {
        SSL_get_fd: getFd ?? fdLessSslGetFd,
        SSL_get_session: getSession,
        SSL_SESSION_get_id: sessionGetId ?? sessionlessSslSessionGetId,
        fallbacks,
        fdLess: getFd === null,
    };
}

/** The one debug line a host logs when it fell back (empty string when nothing fell back). */
export function describeSslFdSessionFallback(moduleName: string, fallbacks: string[]): string {
    if (fallbacks.length === 0) return "";
    return `${moduleName}: ${fallbacks.join(", ")} unresolved; plaintext hooks use ` +
        "SSL-scoped fd attribution (fd -1) and an empty session id";
}
