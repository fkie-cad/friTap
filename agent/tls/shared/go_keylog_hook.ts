// agent/tls/shared/go_keylog_hook.ts
//
// The one keylog hook for crypto/tls.(*Config).writeKeyLog(label string, clientRandom,
// secret []byte), shared by every Go path: the modern definition (definitions/gotls.ts),
// both GoTLS hooker copies (symbol-resolved address) and the legacy Linux/Android
// pattern-based fallback for stripped binaries (pattern-located address).
//
//  - Arguments come from the Go ABIInternal registers on amd64/arm64 and from the entry
//    stack words (sp+4..) on 386/arm (go_abi.ts goKeyLogArgs via gotls_registers.ts):
//    Frida's C args[] do not map to Go parameters.
//  - onEnter only, attached via attachGoFunctionEntry (go_attach.ts): on arm64 the hook
//    sits right after the Go stack-guard check (same register state as the entry).

import { sendKeylog } from "../../shared/shared_structures.js";
import { attachGoFunctionEntry } from "../../shared/go_attach.js";
import { extractKeylogFromRegisters } from "../decoders/gotls_registers.js";
import { devlog, devlog_error } from "../../util/log.js";
import { isAndroid } from "../../util/process_infos.js";
import { PatternBasedHooking, get_CPU_specific_pattern, hasUsablePatternsFor } from "./pattern_based_hooking.js";
import { patterns, isPatternReplaced, experimental } from "../../fritap_agent.js";

/**
 * onEnter body of the writeKeyLog hook: decodes the call's registers and emits one
 * SSLKEYLOGFILE line. Returns whether a line was emitted.
 */
export function goKeyLogOnEnter(this: InvocationContext, _args?: InvocationArguments): boolean {
    try {
        const line = extractKeylogFromRegisters(this.context);
        if (line === null) {
            devlog_error(`[GoTLS] writeKeyLog: no plausible key material in the Go arguments (${Process.arch})`);
            return false;
        }
        sendKeylog(line);
        return true;
    } catch (e) {
        devlog_error(`[GoTLS] writeKeyLog hook: ${e}`);
        return false;
    }
}

/** Hook writeKeyLog at `address` (its function entry). Throws when Frida cannot attach. */
export function installGoKeyLogHook(address: NativePointer): InvocationListener {
    return attachGoFunctionEntry(address, { onEnter: goKeyLogOnEnter });
}

/**
 * Byte patterns of crypto/tls.(*Config).writeKeyLog's ENTRY in stripped Go binaries, for the
 * register-ABI architectures (the decoder above reads registers). The match is the function
 * entry, so attachGoFunctionEntry's arm64 after-stack-check placement applies.
 */
export const GO_WRITE_KEYLOG_PATTERNS: { [arch: string]: { primary: string; fallback: string } } = {
    // Go writeKeyLog entry (stack guard: lea r12,[rsp-N]; cmp r12,[r14+0x10]; jbe), then the
    // spills of RBX/RDI/R9 (label, clientRandom, secret) and the KeyLogWriter nil check.
    // Validated on stripped linux builds: primary Go 1.21-1.26 (push rbp frame), fallback 1.18/1.20.
    "x64": {
        primary: "4C 8D 64 24 ?? 4D 3B 66 10 0F 86 ?? ?? 00 00 55 48 89 E5 48 81 EC ?? ?? 00 00 48 89 9C 24 ?? ?? 00 00 48 89 BC 24 ?? ?? 00 00 4C 89 8C 24 ?? ?? 00 00 48 83 B8 ?? ?? 00 00 00",
        fallback: "4C 8D 64 24 ?? 4D 3B 66 10 0F 86 ?? ?? 00 00 48 81 EC ?? ?? 00 00 48 89 AC 24 ?? ?? 00 00 48 8D AC 24 ?? ?? 00 00 48 89 9C 24 ?? ?? 00 00 48 89 BC 24 ?? ?? 00 00 4C 89 8C 24 ?? ?? 00 00 48 83 B8 ?? ?? 00 00 00",
    },
    // Go writeKeyLog entry (stack guard ldr x16,[x28,#0x10] ... b.ls), the spills of
    // x1/x3/x6 (label, clientRandom, secret), then ldr x9,[x0,#KeyLogWriter]; cbz x9.
    // Frame size/offsets wildcarded. Validated on stripped linux builds of Go 1.18-1.26.
    "arm64": {
        primary: "90 0B 40 F9 F1 ?3 ?? D1 3F 02 10 EB ?9 ?? ?? 54 FE ?F ?? F8 FD 83 1F F8 FD 23 00 D1 E1 ?? ?? F9 E3 ?? ?? F9 E6 ?? ?? F9 09 ?? 4? F9 ?9 ?? ?? B4",
        fallback: "",
    },
};

/** Per-architecture writeKeyLog entry patterns (get_CPU_specific_pattern keys). */
export type GoKeyLogArchPatterns = { [arch: string]: { primary: string; fallback: string; second_fallback?: string } };

/** The PatternBasedHooking surface used here (both the tls/ and legacy/ copies). */
export interface GoKeyLogPatternHooker {
    hookModuleByPattern(patterns: { primary: string; fallback: string } | null | undefined, onMatch: (args: any[]) => void): void;
    hook_DumpKeys(moduleName: string, jsonModuleName: string, jsonPatterns: string, onMatch: (args: any[]) => void): void;
}

export interface GoKeyLogPatternOptions {
    /** The name the module is loaded under, when it differs from `moduleName` (a path). */
    soName?: string;
    /** The module to scan (default: looked up by `soName`). */
    module?: Module | null;
    /** Which PatternBasedHooking copy scans (default: tls/shared). */
    newHooker?: (module: Module) => GoKeyLogPatternHooker;
}

/** Android keeps the --experimental gate for Go pattern hooking (instability seen there). */
function goPatternHookingAllowed(): boolean {
    if (!isAndroid() || experimental) return true;
    devlog("[!] Pattern-based hooking for GoTLS may cause instability or crashes. To proceed anyway, rerun friTap with the --experimental flag.");
    return false;
}

/**
 * Pattern-based fallback for stripped Go binaries, shared by the modern definition and the
 * legacy Linux/Android classes: scan for writeKeyLog's entry (user JSON "Dump-Keys" patterns
 * when given, else `archPatterns` for this CPU) and install the same register-based hook as
 * the symbol path (PatternBasedHooking attaches it via go_attach.ts). Returns the scanning
 * hooker, or null when gated (Android without --experimental) or the module is not loaded.
 */
export function installGoKeylogByPattern(moduleName: string, archPatterns: GoKeyLogArchPatterns,
                                         options: GoKeyLogPatternOptions = {}): GoKeyLogPatternHooker | null {
    if (!goPatternHookingAllowed()) return null;
    const soName = options.soName ?? moduleName;
    const module = options.module !== undefined ? options.module : Process.findModuleByName(soName);
    if (module === null) return null;
    const hooker = (options.newHooker ?? ((m: Module) => new PatternBasedHooking(m)))(module);
    if (isPatternReplaced() && hasUsablePatternsFor(patterns, moduleName, soName, "Dump-Keys")) {
        devlog("Hooking GoTLS functions by patterns from JSON file");
        hooker.hook_DumpKeys(moduleName, soName, patterns, goKeyLogOnEnter);
    } else {
        hooker.hookModuleByPattern(get_CPU_specific_pattern(archPatterns), goKeyLogOnEnter);
    }
    return hooker;
}
