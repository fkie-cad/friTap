// Modern Rustls executor for Android (--modern). Same shape as Linux and
// self-contained in the modern tree: symbolized rustls-ffi → the data-driven
// definition, falling back to the modern class-based executor (../../libs/rustls.ts);
// stripped builds (librustls_android_13.so / _ex.so variants) → the class-based
// hkdf/derive_secrets + TLS 1.2 PRF byte-pattern hooks below. The legacy executor
// (default, no --modern) is agent/legacy/tls/platforms/android/rustls_android.ts.

import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd, patterns, isPatternReplaced } from "../../../fritap_agent.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createRustlsDefinition } from "../../definitions/rustls.js";
import { RusTLS, dispatchRustlsModern, rustls_execute_class_based } from "../../libs/rustls.js";
import { hasMoreThanFiveExports } from "../../../shared/shared_functions.js";
import { PatternBasedHooking, get_CPU_specific_pattern, hasUsablePatternsFor } from "../../shared/pattern_based_hooking.js";
import { installRustlsStaticPatternHooks } from "../../shared/rustls_static_patterns.js";
import { devlog } from "../../../util/log.js";

type ArchPatterns = { [arch: string]: { primary: string, fallback: string } };

const TLS13_X64 = {
    primary:  "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C 24 18 49 89 D6 49 89 F4 48 89 FB 0F B6 C1 C1 E0 03 48 8D",
    fallback: "55 41 57 41 56 41 55 41 54 53 48 81 EC C8 00 00 00 4D 89 CD 4C 89 44 24 10 48 89 4C",
};
const TLS13_X86 = {
    primary:  "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60 8B 40 34",
    fallback: "55 53 57 56 83 EC 4C E8 00 00 00 00 5B 81 C3 A9 CB 13 00 8B 44 24 60",
};
const TLS13_ARM = {
    primary:  "2D E9 F0 43 89 B0 04 46 40 6B D0 F8 2C 01 00 28 49 D0",
    fallback: "2D E9 F0 41 86 B0 04 46 40 6B D0 F8 30 01 00 28 53 D0",
};

/** hkdf_expand_label / derive_secrets (TLS 1.3) in librustls_android_13.so and variants. */
const RUSTLS_ANDROID_TLS13_PATTERNS: ArchPatterns = {
    "x64": TLS13_X64,
    "x86": TLS13_X86,
    "arm64": {
        primary:  "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A ?8 0? 00 ?0 08 ?1 ?? 91 C9 1E 40",
        fallback: "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A ?8 0? 00 ?0 08",
    },
    "arm": TLS13_ARM,
};

/** Same function in the librustls_android_13_ex.so variants (pinned arm64 adrp/add). */
const RUSTLS_ANDROID_EX_TLS13_PATTERNS: ArchPatterns = {
    "x64": TLS13_X64,
    "x86": TLS13_X86,
    "arm64": {
        primary:  "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A 88 0C 00 F0 08 E1 3B 91 C9 1E 40",
        fallback: "FF 83 04 D1 FD 7B 0C A9 FC 6F 0D A9 FA 67 0E A9 F8 5F 0F A9 F6 57 10 A9 F4 4F 11 A9 F6 03 03 2A 88 0C 00 F0 08 E1",
    },
    "arm": TLS13_ARM,
};

/** ConnectionSecrets::from_key_exchange (TLS 1.2 PRF); shared by both variants. */
const RUSTLS_ANDROID_TLS12_PATTERNS: ArchPatterns = {
    "x64": {
        primary:  "55 41 57 41 56 41 55 41 54 53 48 81 ec 48 01 00 00 4c 89 c0 49 89 cb 49 89 d6 49 89 f7 48 89 fb 48 8b 8c 24 88 01 00 00 48 8b 94 24 80 01 00",
        fallback: "55 41 57 41 56 41 55 41 54 53 48 81 ec 48 01 00 00 4c 89 c0 49 89 cb 49 89 d6 49 89 f7 48 89 fb 48 8b 8c 24 88 01 00 00 48 8b",
    },
    "arm64": {
        primary:  "FF 03 07 D1 FD 7B 19 A9 F6 57 1A A9 F4 4F 1B A9 A1 08 40 AD 03 E4 00 6F F3 03 08 AA 88 00 40 B9 EB 03 03 AA E9 03 02 AA F4 03 01 AA F5 03 00 AA E1 0B 01 AD A0 04 41 AD F6 43 02 91 E3 8F 03 AD E6 0F 00 F9 E0 03 84 3C E1 8F 02 AD",
        fallback: "FF 03 07 D1 FD 7B 19 A9 F6 57 1A A9 F4 4F 1B A9 A1 08 40 AD 03 E4 00 6F F3 03 08 AA 88 00 40 B9 EB 03 03 AA E9 03 02 AA F4 03 01 AA F5 03 00 AA E1 0B 01 AD A0 04 41 AD F6 43 02 91 E3",
    },
    "arm": {
        primary:  "2D E9 F0 4F D1 B0 0A AD 8A 46 05 F1 44 07 81 46 30 21 1C 46 38 46 93 46 FB F0 A8 F9 5C 9E 28 1D 40 22 31 46 FB F0 2D FA 5B 99 DD F8 74 81 CD",
        fallback: "2D E9 F0 4F D1 B0 0A AD 8A 46 05 F1 44 07 81 46 30 21 1C 46 38 46 93 46 FB F0 A8 F9 5C 9E 28 1D 40 22 31 46 FB F0 2D FA 5B 99",
    },
};

export class Rustls_Android_Modern extends RusTLS {
    private get isEx(): boolean { return this.module_name.includes("_ex"); }
    private get jsonModuleName(): string { return this.isEx ? "librustls_ex.so" : "librustls.so"; }

    private hasJsonPatterns(): boolean {
        return isPatternReplaced() && hasUsablePatternsFor(patterns, this.module_name, this.jsonModuleName, "Dump-Keys");
    }

    install_key_extraction_hook(): void {
        const module = Process.findModuleByName(this.module_name);
        const hooker = new PatternBasedHooking(module);
        // Stripped Android rustls .so: try the shared static-rustls table (rustls 0.22/0.23,
        // arm64 + x64 — the same patterns Linux uses) first, picked by Process.arch inside the
        // helper; the built-in Android tables below (which also cover arm / x86) run only for a
        // TLS version it did not hook. A user --patterns file still wins for TLS 1.3.
        const usesJsonPatterns = this.hasJsonPatterns();
        const shared = usesJsonPatterns ? { tls13: false, tls12: false } : installRustlsStaticPatternHooks(module);
        if (!shared.tls13) this.install_tls13_pattern_hook(hooker);
        // A user pattern file covers Dump-Keys once (TLS 1.3); the built-in TLS 1.2 PRF hook
        // is only added when hooking from the built-in tables (legacy parity).
        if (!shared.tls12 && !usesJsonPatterns) this.install_tls12_pattern_hook(hooker);
    }

    private hookByPattern(hooker: PatternBasedHooking, builtIn: ArchPatterns,
                          callback: (args: any[], retval?: NativePointer) => void, maxArgs: number): void {
        if (this.hasJsonPatterns()) {
            hooker.hook_DumpKeys(this.module_name, this.jsonModuleName, patterns, callback, true, maxArgs);
        } else {
            hooker.hookModuleByPatternOnReturn(get_CPU_specific_pattern(builtIn), callback, maxArgs);
        }
    }

    private install_tls12_pattern_hook(hooker: PatternBasedHooking): void {
        const isX64 = Process.arch === "x64";
        this.hookByPattern(hooker, RUSTLS_ANDROID_TLS12_PATTERNS, (args, retval) => {
            if (!retval || retval.isNull()) return;
            if (Process.arch === "arm64") {
                // args[5] = | client_random | server_random | pad (8) | client_random | server_random | master_secret (48) |
                this.dumpKeysFromPRF(args[5], args[5].add(136));
            } else {
                // retval = | header (8) | client_random | server_random | master_secret (48) |
                this.dumpKeysFromPRF(args[6], retval.add(72));
            }
        }, isX64 ? 7 : 8);
    }

    private install_tls13_pattern_hook(hooker: PatternBasedHooking): void {
        const isEx = this.isEx;
        const dump = (args: any[]) =>
            this.dumpKeysFromDeriveSecrets(args[9], args[0], args[5].toInt32(), args[3].toInt32());
        const builtIn = isEx ? RUSTLS_ANDROID_EX_TLS13_PATTERNS : RUSTLS_ANDROID_TLS13_PATTERNS;
        this.hookByPattern(hooker, builtIn, (args, retval) => {
            if (!retval) return;
            if (isEx) {
                if (!retval.isNull()) dump(args);
            } else if (retval.isNull() || Process.arch === "x64" || Process.arch === "arm64") {
                dump(args);
            }
        }, Process.arch === "x64" ? 7 : 9);
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
            new Rustls_Android_Modern(moduleName, socket_library, is_base_hook), moduleName, is_base_hook, symbolized),
    });
}
