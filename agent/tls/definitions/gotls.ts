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
//      the registers directly (installGoKeyLogHook, ../shared/go_keylog_hook.ts —
//      shared with the legacy symbol- and pattern-based paths).
//   3. Go functions must not get onLeave hooks (goroutines migrate between OS
//      threads across blocking calls; the swapped return address breaks Go's
//      stack unwinder), so the generic readHook/writeHook executors — onLeave,
//      C args[] — cannot be used. The plaintext hooks are onEnter-only probes
//      installed as extraHooks (see ../shared/go_plaintext.ts).
//
// Stripped binaries without enumerable Go symbols: the keylog install scans
// the writeKeyLog byte patterns itself (installGoKeylogByPattern). If the
// whole pipeline fails, the modern platform wrappers (gotls_linux.ts /
// gotls_android.ts) fall back to the class-based GoTLS executor in
// ../libs/gotls.ts — never to the legacy tree.

import { HookDefinition, ResolvedFunctions } from "../../core/hook_definition.js";
import { getPortsAndAddresses } from "../../shared/shared_functions.js";
import { devlog, devlog_error, log } from "../../util/log.js";
import { STANDARD_SOCKET_SYMBOLS } from "./shared_constants.js";
import { noOpClientRandomDecoder } from "./shared_factories.js";
import { GO_SYMBOL_WRITE_KEYLOG, resolveGoSymbols } from "../shared/go_symbol_resolver.js";
import { GO_WRITE_KEYLOG_PATTERNS, installGoKeyLogHook, installGoKeylogByPattern } from "../shared/go_keylog_hook.js";
import { installGoPlaintextHooks } from "../shared/go_plaintext.js";
import { pcap_enabled } from "../../fritap_agent.js";

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
        devlog(`[gotls] ${GO_SYMBOL_WRITE_KEYLOG} unresolved in ${moduleName}; trying the byte patterns (stripped binary)`);
        // Stripped binary: the shared pattern path (go_keylog_hook.ts). The executor's legacy
        // fallback never fires here (an unresolved symbol is not an error), so scan here.
        return installGoKeylogByPattern(moduleName, GO_WRITE_KEYLOG_PATTERNS) !== null;
    }
    try {
        // Shared Go keylog hook (go_keylog_hook.ts): Go registers, onEnter-only.
        installGoKeyLogHook(addr);
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

/**
 * onEnter-only plaintext hooks (go_plaintext.ts, shared with the legacy executors): writes at
 * (*Conn).writeRecordLocked, reads at the plaintext copy inside (*Conn).Read.
 */
function installGoPlaintextHooksFromDefinition(
    addresses: { [key: string]: { [fn: string]: NativePointer } },
    moduleName: string,
    _resolvedFns: ResolvedFunctions,
    enableDefaultFd: boolean,
): void {
    if (!pcap_enabled) return;
    installGoPlaintextHooks(moduleName, addresses[moduleName] || {}, enableDefaultFd);
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
        // No readHook/writeHook: the generic executors attach onLeave and read C
        // args[] — both wrong for Go. See installGoPlaintextHooksFromDefinition (extraHooks).
        keylog: {
            kind: "custom",
            install: (addresses, modName, _resolvedFns, _enableDefaultFd) =>
                installGoKeylogHook(addresses, modName),
        },
        extraHooks: [{ install: installGoPlaintextHooksFromDefinition }],
        customAddressExtractor: goCustomAddressExtractor,
        libraryType: "gotls",
    };
}
