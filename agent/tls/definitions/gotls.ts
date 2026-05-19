// agent/tls/definitions/gotls.ts
//
// Data-driven Go crypto/tls hook definition.
//
// Go is exceptional in two ways that drive this definition's shape:
//   1. Symbols carry their package path verbatim (e.g.
//      "crypto/tls.(*Config).writeKeyLog"), so the loader's
//      ApiResolver "exports:" pattern can't find them. We pre-resolve via
//      `resolveGoSymbols` (see ../shared/go_symbol_resolver.ts) and the
//      loader merges the results into addresses[moduleName] before
//      NativeFunction wrapping.
//   2. Go's ABIInternal passes writeKeyLog params in CPU registers, not
//      the System V slots Frida's args[] exposes. The keylog hook reads
//      the registers directly via extractKeylogFromRegisters
//      (see ../decoders/gotls_registers.ts).
//
// Stripped binaries without enumerable Go symbols continue to route
// through the legacy pattern-based path — see gotls_linux.ts /
// gotls_android.ts wrappers.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { sendKeylog } from "../../shared/shared_structures.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { devlog, devlog_error, log } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";
import {
    GO_SYMBOL_CONN_READ,
    GO_SYMBOL_CONN_WRITE,
    GO_SYMBOL_WRITE_KEYLOG,
    resolveGoSymbols,
} from "../shared/go_symbol_resolver.js";
import { extractKeylogFromRegisters } from "../decoders/gotls_registers.js";

/**
 * Go's crypto/tls doesn't expose an fd accessor for *Conn — keep the
 * synthesized 5-tuple path (enable_default_fd) intact by returning -1.
 */
function goFdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): number {
    return -1;
}

/**
 * Go's crypto/tls doesn't expose a stable session-id accessor either —
 * follow the s2ntls/rustls precedent and return an empty string.
 */
function goSessionIdDecoder(_ctx: NativePointer, _fns: ResolvedFunctions): string {
    return "";
}

/**
 * Install the register-based keylog hook on
 * crypto/tls.(*Config).writeKeyLog. The address is pre-resolved by the
 * symbolResolver and merged into addresses[moduleName] by the loader.
 */
function installGoKeylogHook(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
): boolean {
    const addr = addresses[moduleName]?.[GO_SYMBOL_WRITE_KEYLOG];
    if (!addr || addr.isNull()) {
        devlog(`[gotls] ${GO_SYMBOL_WRITE_KEYLOG} unresolved in ${moduleName}; skipping keylog hook`);
        return false;
    }
    try {
        Interceptor.attach(addr, {
            onEnter: function (_args: any) {
                try {
                    devlog(`invoking writeKeyLog from Go crypto/tls (${moduleName})`);
                    const line = extractKeylogFromRegisters(this.context);
                    if (line !== null) sendKeylog(line);
                } catch (e) {
                    devlog_error(`[gotls keylog] ${e}`);
                }
            },
        });
        log(`[*] ${moduleName}: keylog hooks installed via Go writeKeyLog`);
        return true;
    } catch (e) {
        devlog_error(`[gotls] Interceptor.attach(writeKeyLog) threw: ${e}`);
        return false;
    }
}

/**
 * Custom 5-tuple extractor for Go: writeKeyLog gives us no fd, so we
 * always synthesize via getPortsAndAddresses(-1, ...) when
 * enable_default_fd is true. Mirrors the rustls / s2ntls precedent.
 */
function goCustomAddressExtractor(
    _ctx: NativePointer,
    isRead: boolean,
    _fns: ResolvedFunctions,
    enableDefaultFd: boolean,
): { [key: string]: string | number } | null {
    return getPortsAndAddresses(-1, isRead, {}, enableDefaultFd);
}

export function createGoTlsDefinition(): HookDefinition {
    return {
        libraryId: "gotls",
        offsetKey: "gotls",
        functions: {
            // Every Go crypto/tls symbol is resolved via the symbolResolver
            // because Frida's ApiResolver "exports:" pattern can't match
            // names containing '/' or '(*X)'. Leaving librarySymbols empty
            // keeps the standard resolution path a clean no-op.
            librarySymbols: [],
            socketSymbols: STANDARD_SOCKET_SYMBOLS,
        },
        nativeFunctions: [],
        symbolResolver: resolveGoSymbols,
        fdDecoder: goFdDecoder,
        sessionIdDecoder: goSessionIdDecoder,
        clientRandomDecoder: noOpClientRandomDecoder,
        readHook: {
            symbol: GO_SYMBOL_CONN_READ,
            args: {
                sslCtxArgIndex: 0,
                bufferArgIndex: 1,
                bytesTransferred: "retval",
            },
            functionLabel: "Go_Conn_Read",
        },
        writeHook: {
            symbol: GO_SYMBOL_CONN_WRITE,
            args: {
                sslCtxArgIndex: 0,
                bufferArgIndex: 1,
                lengthArgIndex: 2,
                bytesTransferred: "arg",
            },
            functionLabel: "Go_Conn_Write",
        },
        keylog: {
            kind: "custom",
            install: (addresses, modName, _resolvedFns, _enableDefaultFd) =>
                installGoKeylogHook(addresses, modName),
        },
        customAddressExtractor: goCustomAddressExtractor,
        libraryType: "gotls",
    };
}
