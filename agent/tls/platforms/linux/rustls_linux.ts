// Modern Rustls executor for Linux (--modern). Self-contained in the modern tree:
// symbolized rustls-ffi → the data-driven definition (../../definitions/rustls.ts),
// falling back to the modern class-based executor (../../libs/rustls.ts) if the
// definition fails; stripped builds → the class-based derive_logged_secrets /
// TLS 1.2 PRF byte-pattern hooks below. The legacy executor (default, no --modern)
// is agent/legacy/tls/platforms/linux/rustls_linux.ts.

import { socket_library } from "../../../platforms/linux.js";
import { enable_default_fd, patterns, isPatternReplaced } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createRustlsDefinition } from "../../definitions/rustls.js";
import { RusTLS, dispatchRustlsModern, rustls_execute_class_based } from "../../libs/rustls.js";
import { hasMoreThanFiveExports } from "../../../shared/shared_functions.js";
import { PatternBasedHooking, get_CPU_specific_pattern, hasUsablePatternsFor } from "../../shared/pattern_based_hooking.js";
import { installRustlsStaticPatternHooks } from "../../shared/rustls_static_patterns.js";
import { devlog } from "../../../util/log.js";

type ArchPatterns = { [arch: string]: { primary: string, fallback: string } };

/** rustls::tls13::key_schedule derive_logged_secret (TLS 1.3), x64 only. */
const RUSTLS_LINUX_TLS13_PATTERNS: ArchPatterns = {
    "x64": {
        primary:  "48 81 EC 18 01 00 00 4C 89 4C 24 40 48 89 7C 24 48 88 D0 48 89 7C 24 50 48 8B 94 24 28 01 00 00 48 89 54 24 58 48 8B 94 24 20 01 00 00 48 89",
        fallback: "48 81 EC 18 01 00 00 4C 89 4C 24 40 48 89 7C 24 48 88 D0 48 89 7C 24 50 48 8B 94 24 28 01 00 00 48 89 54 24 58 48 8B 94 24 20 01",
    },
};

/** rustls::tls12 ConnectionSecrets::from_key_exchange (TLS 1.2 PRF), x64 only. */
const RUSTLS_LINUX_TLS12_PATTERNS: ArchPatterns = {
    "x64": {
        primary:  "41 57 41 56 53 48 81 ec c0 04 00 00 4c 89 8c 24 a0 00 00 00 4c 89 44 24 70 48 89 4c 24 78 48 89 bc 24 80 00 00 00 48 89 bc 24 88 00 00 00 48 8b",
        fallback: "41 57 41 56 53 48 81 ec c0 04 00 00 4c 89 8c 24 a0 00 00 00 4c 89 44 24 70 48 89 4c 24 78 48 89 bc 24 80 00 00 00 48 89 bc 24 88",
    },
};

export class Rustls_Linux_Modern extends RusTLS {
    install_key_extraction_hook(): void {
        const module = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(module);
        // --patterns JSON wins; otherwise the shared static-rustls table (0.22/0.23, arm64 +
        // x64) first, the older built-in x64 table only for a TLS version it did not hook.
        const usesJsonPatterns = isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "rustls", "Dump-Keys");
        const shared = usesJsonPatterns ? { tls13: false, tls12: false } : installRustlsStaticPatternHooks(module);
        if (!shared.tls13) this.install_tls13_pattern_hook(hooker);
        if (!shared.tls12) this.install_tls12_pattern_hook(hooker);
    }

    /** Hook by --patterns JSON when supplied for "rustls", else by the built-in table. */
    private hookByPattern(hooker: PatternBasedHooking, builtIn: ArchPatterns,
                          callback: (args: any[], retval?: NativePointer) => void, maxArgs: number): void {
        if (isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, "rustls", "Dump-Keys")) {
            hooker.hook_DumpKeys(this.module_name, "rustls", patterns, callback, true, maxArgs);
        } else {
            hooker.hookModuleByPatternOnReturn(get_CPU_specific_pattern(builtIn), callback, maxArgs);
        }
    }

    private install_tls12_pattern_hook(hooker: PatternBasedHooking): void {
        // retval: | header (8) | client_random (32) | server_random (32) | master_secret (48) |
        this.hookByPattern(hooker, RUSTLS_LINUX_TLS12_PATTERNS, (args, retval) => {
            if (!retval || retval.isNull()) return;
            this.dumpKeysFromPRF(args[6], retval.add(72));
        }, 7);
    }

    private install_tls13_pattern_hook(hooker: PatternBasedHooking): void {
        this.hookByPattern(hooker, RUSTLS_LINUX_TLS13_PATTERNS, (args, retval) => {
            if (!retval) return;
            if (retval.isNull() || Process.arch === "x64") {
                this.dumpKeysFromDeriveLogged(args[7], args[0], args[2].toInt32());
            }
        }, 9);
    }
}

export function rustls_execute_modern(moduleName: string, is_base_hook: boolean): void {
    const symbolized = hasMoreThanFiveExports(moduleName);
    devlog(`[rustls] modern executor on ${moduleName} (symbolized=${symbolized})`);
    dispatchRustlsModern(moduleName, {
        symbolized,
        runDefinition: () => executeFromDefinition(
            createRustlsDefinition(), moduleName, socket_library, is_base_hook, enable_default_fd),
        runClassBased: () => rustls_execute_class_based(
            new Rustls_Linux_Modern(moduleName, socket_library, is_base_hook), moduleName, is_base_hook, symbolized),
    });
}
