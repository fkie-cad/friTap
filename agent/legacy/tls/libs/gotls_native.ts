// agent/legacy/tls/libs/gotls_native.ts
//
// Legacy (default, no --modern) Go crypto/tls executor for desktop platforms whose Go
// support needs no per-platform quirks — macOS and Windows: the legacy GoTLS class
// (./gotls.ts) for symbol resolution, the shared writeKeyLog byte patterns for stripped
// binaries, the cgo BoringSSL last resort, and (with -p) the shared onEnter-only Go
// plaintext probes. The Linux/Android legacy executors keep their own classes (their 32-bit
// patterns differ) and share only legacyGoPlaintext below.
//
// Go's ABIInternal is OS-independent, so the register decoding (go_abi.ts) and the amd64/arm64
// entry patterns (go_keylog_hook.ts) hold on every OS; validated on darwin and windows builds.

import { GoTLS, symbol_writeKeyLog, GoTlsLogger } from "./gotls.js";
import { keylog_enabled, pcap_enabled, enable_default_fd } from "../../../fritap_agent.js";
import {
    GO_WRITE_KEYLOG_PATTERNS,
    GoKeyLogArchPatterns,
    GoKeyLogPatternHooker,
    installGoKeylogByPattern,
} from "../../../tls/shared/go_keylog_hook.js";
import { installGoPlaintextHooks } from "../../../tls/shared/go_plaintext.js";
import { resolveGoSymbols } from "../../../tls/shared/go_symbol_resolver.js";
import { installBoringSSLSymbolHook, makeBoringSslDumpKeys } from "../../../shared/boringssl_symbol_hook.js";
import { devlog, devlog_error } from "../../../util/log.js";

/** Delay before the cgo BoringSSL last resort: the pattern scan reports its outcome asynchronously. */
const SYMBOL_FALLBACK_DELAY_MS = 1500;

/**
 * Legacy Go plaintext (-p): the shared onEnter-only probes (tls/shared/go_plaintext.ts) on the
 * symbols resolved for `moduleName`. A *tls.Conn has no fd, so records need -ed/--enable_default_fd.
 * Stripped binaries (no symbols) get keys only. Never throws.
 */
export function legacyGoPlaintext(moduleName: string): void {
    if (!pcap_enabled) return;
    try {
        installGoPlaintextHooks(moduleName, resolveGoSymbols(moduleName), enable_default_fd);
    } catch (e) {
        devlog_error(`[GoTLS] plaintext hooks on ${moduleName} failed: ${e}`);
    }
}

export class GoTLS_Native extends GoTLS {
    constructor(moduleName: string, socket_library: string, is_base_hook: boolean,
                private readonly archPatterns: GoKeyLogArchPatterns = GO_WRITE_KEYLOG_PATTERNS) {
        super(moduleName, socket_library, is_base_hook);
    }

    /**
     * writeKeyLog by symbol when resolved, else (stripped binary) by the per-arch entry patterns.
     * Returns a GoTlsLogger (symbol path), the scanning hooker (pattern path) or undefined.
     */
    install_key_extraction_hook(): GoTlsLogger | GoKeyLogPatternHooker | null | undefined {
        if (!keylog_enabled) return undefined;
        const goModule = Process.findModuleByName(this.module_name);
        if (goModule === null) {
            devlog("[-] GoTLS Error: Unable to find module: " + this.module_name);
            return undefined;
        }
        const writeKeyLog = this.addresses[this.module_name]?.[symbol_writeKeyLog];
        if (writeKeyLog === undefined || writeKeyLog === null) {
            return installGoKeylogByPattern(this.module_name, this.archPatterns, { module: goModule });
        }
        devlog("[GoTLS] writeKeyLog symbol available");
        return new GoTlsLogger(goModule, true, this.install_tls_keys_callback_hook());
    }

    /** Last resort when the pattern scan found nothing: cgo-linked C BoringSSL (C ABI). */
    execute_symbol_based_hooking(hooker: any): void {
        if (!keylog_enabled || hooker === undefined || hooker === null) return;
        if (!hooker.no_hooking_success) return;
        installBoringSSLSymbolHook(this.module_name, makeBoringSslDumpKeys(this.module_name));
    }
}

/** Legacy Go executor body shared by the macOS and Windows platform wrappers. */
export function gotls_execute_native(moduleName: string, socketLibrary: string, isBaseHook: boolean,
                                     archPatterns: GoKeyLogArchPatterns = GO_WRITE_KEYLOG_PATTERNS): void {
    const gotls = new GoTLS_Native(moduleName, socketLibrary, isBaseHook, archPatterns);
    try {
        const hooker = gotls.install_key_extraction_hook();
        setTimeout(() => {
            try {
                gotls.execute_symbol_based_hooking(hooker);
            } catch (e) {
                devlog("[-] Error in gotls.execute_symbol_based_hooking: " + e);
            }
        }, SYMBOL_FALLBACK_DELAY_MS);
    } catch (e) {
        devlog(`gotls_execute_native error: ${e}`);
    }
    legacyGoPlaintext(moduleName);
    if (isBaseHook) {
        const initAddresses = gotls.addresses[moduleName];
        if (initAddresses && Object.keys(initAddresses).length > 0) {
            (globalThis as any).init_addresses[moduleName] = initAddresses;
        }
    }
}
