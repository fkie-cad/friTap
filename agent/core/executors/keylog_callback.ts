// agent/core/executors/keylog_callback.ts
//
// Generic keylog hook executors that dispatch based on KeylogApproach.
// Each installer returns a boolean so the BoringSSL three-tier chain
// (agent/shared/boringssl_hook_chain.ts) can fall through to the next tier
// when a tier cannot install hooks (static failure: symbol unresolved or
// Interceptor.attach failed). Success = at least one Interceptor.attach
// reached on a non-null resolved address.

import { HookDefinition, KeylogApproach, ResolvedFunctions } from "../hook_definition.js";
import { devlog } from "../../util/log.js";

/**
 * Hooks an init function (e.g., gnutls_init) and calls the callback installer
 * in onLeave with the newly created session pointer.
 * Used by GnuTLS pattern: gnutls_init takes a pointer-to-session as arg[0],
 * so we dereference it in onLeave.
 */
function installKeylogCallbackOnInit(
    keylog: Extract<KeylogApproach, { kind: "callback_on_init" }>,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
): boolean {
    const addr = addresses[moduleName]?.[keylog.initSymbol];
    if (!addr || addr.isNull()) return false;

    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            this.session = args[0];
        },
        onLeave: function (_retval: any) {
            devlog(this.session);
            keylog.callbackInstaller(this.session.readPointer(), resolvedFns);
        },
    });
    return true;
}

/**
 * Hooks SSL_new and calls the callback installer in onLeave
 * with the returned SSL pointer.
 * Used by OpenSSL/BoringSSL pattern.
 */
function installKeylogCallbackOnSslNew(
    keylog: Extract<KeylogApproach, { kind: "callback_on_ssl_new" }>,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
): boolean {
    const addr = addresses[moduleName]?.[keylog.sslNewSymbol];
    if (!addr || addr.isNull()) return false;

    Interceptor.attach(addr, {
        onEnter: function (_args: any) {
        },
        onLeave: function (retval: any) {
            keylog.callbackInstaller(retval, resolvedFns);
        },
    });
    return true;
}

/**
 * Hooks a connect function (e.g., wolfSSL_connect) and extracts
 * key material in onLeave after the handshake completes.
 * Used by WolfSSL pattern.
 */
function installManualKeyExtraction(
    keylog: Extract<KeylogApproach, { kind: "manual_on_connect" }>,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
): boolean {
    const addr = addresses[moduleName]?.[keylog.connectSymbol];
    if (!addr || addr.isNull()) return false;

    Interceptor.attach(addr, {
        onEnter: function (args: any) {
            this.ssl = args[0];
        },
        onLeave: function (_retval: any) {
            keylog.extractKeys(this.ssl, resolvedFns);
        },
    });
    return true;
}

/**
 * Dispatch keylog hook installation based on the approach specified in the definition.
 * Returns true iff hooks were actually installed (at least one Interceptor.attach
 * reached on a non-null resolved address). The BoringSSL chain uses this signal
 * to decide whether to fall through to the next tier.
 */
export function installKeylogHook(
    def: HookDefinition,
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
): boolean {
    const keylog = def.keylog;
    switch (keylog.kind) {
        case "callback_on_init":
            return installKeylogCallbackOnInit(keylog, addresses, moduleName, resolvedFns);
        case "callback_on_ssl_new":
            return installKeylogCallbackOnSslNew(keylog, addresses, moduleName, resolvedFns);
        case "manual_on_connect":
            return installManualKeyExtraction(keylog, addresses, moduleName, resolvedFns);
        case "custom":
            return keylog.install(addresses, moduleName, resolvedFns, enableDefaultFd);
        case "none":
            return false;
    }
}
