import { log } from "./log.js";

/**
 * Anti-tamper / app-integrity awareness.
 *
 * Some Android apps ship a native integrity-protection runtime that actively
 * scans the process for instrumentation and **deliberately crashes** when it
 * detects one. The motivating case is Google PairIP (`libpairipcore.so`): a
 * VM-based Play-integrity protection that checksums loaded code (linker / libc
 * included) and runs a watchdog over `/proc/self/maps`. friTap installs an
 * inline `Interceptor.attach` trampoline on `android_dlopen_ext` to learn when
 * TLS libraries load; PairIP observes that modified linker prologue and tears
 * the process down with a SIGSEGV (see fkie-cad/friTap#64).
 *
 * There is no in-tool bypass: 
 * Capturing from a PairIP-protected app requires neutralizing PairIP
 * first, which is out of scope. The most useful thing friTap can do is
 *   1. warn the user clearly *before* the likely crash, and
 *   2. never hand such a library to a Memory.scan / hook executor itself.
 *
 * This module owns both: {@link warnAntiTamper} (detect + warn, throttled) and
 * {@link matchAntiTamper} (pure predicate used to skip hooking/scanning).
 */

interface AntiTamperLib {
    /** Matches the module name (base name or full path). */
    pattern: RegExp;
    /** Human-readable name shown to the user. */
    name: string;
    /** One-line description of what the protection does. */
    note: string;
}

const ANTI_TAMPER_LIBS: ReadonlyArray<AntiTamperLib> = [
    {
        pattern: /libpairipcore\.so$/,
        name: "Google PairIP (libpairipcore.so)",
        note: "VM-based Play-integrity / anti-tamper; checksums loaded code and self-terminates (SIGSEGV) when it detects an inline hook.",
    },
];

/** Per-library throttle so the warning is emitted at most once each. */
const _warnedAntiTamper = new Set<string>();

/**
 * Return the matching anti-tamper library descriptor for a module name, or
 * null. Pure predicate — no side effects — safe to call on the hot path to
 * decide whether to skip hooking/scanning a module.
 */
export function matchAntiTamper(moduleName: string | undefined | null): AntiTamperLib | null {
    if (!moduleName) return null;
    for (const lib of ANTI_TAMPER_LIBS) {
        if (lib.pattern.test(moduleName)) return lib;
    }
    return null;
}

/**
 * If `moduleName` is a known anti-tamper library, emit a one-time user-facing
 * warning and return true (so callers can `continue`/`return` and avoid
 * hooking or scanning it). Returns false otherwise.
 */
export function warnAntiTamper(moduleName: string | undefined | null): boolean {
    const lib = matchAntiTamper(moduleName);
    if (!lib) return false;
    if (!_warnedAntiTamper.has(lib.name)) {
        _warnedAntiTamper.add(lib.name);
        log(`[!] Anti-tamper protection detected: ${lib.name}.`);
        log(`[!] ${lib.note}`);
        log(`[!] friTap's inline hooks are likely to be detected and the app may crash (SIGSEGV). See fkie-cad/friTap#64.`);
        log(`[!] Capturing from a PairIP-protected app is not supported and requires a separate PairIP bypass.`);
        // Structured signal for programmatic/API consumers (ignored by the
        // console path, which already printed the lines above).
        send({ contentType: "anti_tamper_detected", library: moduleName, name: lib.name });
    }
    return true;
}

/**
 * Freshly enumerate loaded modules and warn for any anti-tamper library
 * present. Called right before installing the dynamic-loader trampoline so the
 * warning is surfaced *before* the protection has a chance to crash the
 * process — `getModuleNames()` captured at agent load is stale for spawned
 * apps, so a fresh enumeration is required here.
 */
export function scanForAntiTamper(): void {
    try {
        for (const mod of Process.enumerateModules()) {
            warnAntiTamper(mod.name);
        }
    } catch (_) {
        // Enumeration can race process teardown; a miss here is non-fatal.
    }
}
