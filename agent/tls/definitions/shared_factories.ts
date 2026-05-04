// agent/tls/definitions/shared_factories.ts
//
// Shared factory functions for common hook patterns across TLS library definitions.

import { ExtraHookDef, FdDecoder, ClientRandomDecoder, SessionIdDecoder, ResolvedFunctions } from "../../core/hook_definition.js";
import { devlog } from "../../util/log.js";
import { sendConnectionLifecycle } from "../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { readHexFromPointer } from "../decoders/hex_utils.js";

/**
 * Create an ExtraHookDef that hooks a TLS library's session-free/deinit function
 * to emit a "destroyed" lifecycle event with connection metadata.
 *
 * All TLS libraries follow the same pattern on session teardown:
 *   1. Extract fd from the session context
 *   2. Get ports and addresses
 *   3. Extract session_id and client_random
 *   4. Send "destroyed" lifecycle event
 */
export function createLifecycleHook(
    freeSymbol: string,
    fdDecoder: FdDecoder,
    sessionIdDecoder: SessionIdDecoder,
    clientRandomDecoder?: ClientRandomDecoder,
): ExtraHookDef {
    return {
        install: (addresses, modName, resolvedFns, enableDefaultFd) => {
            const freeAddr = addresses[modName]?.[freeSymbol];
            if (!freeAddr || freeAddr.isNull()) return;

            Interceptor.attach(freeAddr, {
                onEnter: function (args: any) {
                    const ctx = args[0];
                    if (ctx.isNull()) return;
                    try {
                        const fd = fdDecoder(ctx, resolvedFns);
                        const message = getPortsAndAddresses(fd, true, addresses[modName], enableDefaultFd);
                        if (message === null) return;
                        message["ssl_session_id"] = sessionIdDecoder(ctx, resolvedFns);
                        message["client_random"] = clientRandomDecoder ? clientRandomDecoder(ctx, resolvedFns) : "";
                        sendConnectionLifecycle("destroyed", message);
                    } catch (e) {
                        devlog(`${freeSymbol} lifecycle hook: context partially torn down: ${e}`);
                    }
                },
            });
        },
    };
}

/**
 * No-op client random decoder for TLS libraries that don't expose a
 * client_random extraction API (e.g. mbedTLS, s2n-tls).
 */
export const noOpClientRandomDecoder: ClientRandomDecoder = () => "";

/**
 * Create a client random decoder that calls a native function with a pre-allocated
 * buffer and returns the hex string. Shared pattern across OpenSSL and WolfSSL.
 *
 * The native function must have the signature:
 *   int get_client_random(SSL *ssl, unsigned char *out, size_t outlen)
 * returning the number of bytes written.
 */
export function createBufferedClientRandomDecoder(
    fnName: string,
): ClientRandomDecoder {
    const buf = Memory.alloc(32);
    return function (ssl: NativePointer, fns: ResolvedFunctions): string {
        if (!fns[fnName]) return "";
        const len = fns[fnName](ssl, buf, 32) as number;
        if (len <= 0) return "";
        return readHexFromPointer(buf, len);
    };
}
