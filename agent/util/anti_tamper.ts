/**
 * Anti-tamper / app-integrity awareness.
 *
 * Some Android apps ship a native integrity-protection runtime that actively
 * scans the process for instrumentation and **deliberately crashes** when it
 * detects one. The motivating case is Google PairIP (`libpairipcore.so`): a
 * VM-based Play-integrity protection that scans the process at startup *and* on
 * a continuous watchdog. friTap installs an inline `Interceptor.attach`
 * trampoline on `android_dlopen_ext` (in the linker) to learn when TLS
 * libraries load; when that foreign linker patch is resident during PairIP's
 * startup scan (i.e. in spawn mode), PairIP reacts and tears the process down
 * with a SIGSEGV. Late attach survives because it lands after that scan window;
 * plain Frida (no hooks) survives because it patches nothing.
 *
 * The exact trigger is not provable from public sources — candidates are
 * `/proc/self/maps` name-matching, a read-only-page write-probe, and timing,
 * rather than a confirmed linker-prologue checksum. See fkie-cad/friTap#64.
 *
 * There is no in-tool bypass: capturing from a PairIP-protected app requires
 * neutralizing PairIP first, which is out of scope. The most useful things
 * friTap can do are:
 *   1. warn the user *loudly* before the likely crash,
 *   2. skip the linker (`android_dlopen_ext`) hook in spawn so the app is not
 *      crashed on the way in (see android.ts loader-hook gating), and
 *   3. never hand such a library to a Memory.scan / hook executor itself.
 *
 * This module owns: {@link warnAntiTamper} (detect + warn, throttled),
 * {@link matchAntiTamper} (pure predicate used to skip hooking/scanning),
 * {@link scanForAntiTamper} (fresh enumerate + warn, returns whether any was
 * found) and {@link bannerAntiTamper} (un-throttled, unmissable user banner).
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
 * If `moduleName` is a known anti-tamper library, emit a one-time structured
 * `anti_tamper_detected` event and return true (so callers can `continue` /
 * `return` and avoid hooking or scanning it). Returns false otherwise.
 *
 * The event carries everything the host needs; the Python side renders ONE
 * clear, blank-line-padded, red banner from it (see
 * `message_router._emit_anti_tamper_detected`). This function deliberately does
 * NOT print human-facing `log()` lines — doing so produced cramped, duplicated
 * output interleaved with hook logs (each line prefixed `[*] [!] …`). Keeping
 * the wire signal here and the presentation on the host side gives a single,
 * readable message and an API event for programmatic consumers.
 */
export function warnAntiTamper(moduleName: string | undefined | null): boolean {
    const lib = matchAntiTamper(moduleName);
    if (!lib) return false;
    if (!_warnedAntiTamper.has(lib.name)) {
        _warnedAntiTamper.add(lib.name);
        send({
            contentType: "anti_tamper_detected",
            library: moduleName,
            name: lib.name,
            note: lib.note,
            skippedLoaderHook: false,
            reason: "detected",
        });
    }
    return true;
}

/**
 * Freshly enumerate loaded modules and warn for any anti-tamper library
 * present. Called right before installing the dynamic-loader trampoline so the
 * warning is surfaced *before* the protection has a chance to crash the
 * process — `getModuleNames()` captured at agent load is stale for spawned
 * apps, so a fresh enumeration is required here.
 *
 * @returns true if at least one known anti-tamper library is loaded, so callers
 *          can gate behaviour (e.g. skip the linker hook in spawn mode).
 */
export function scanForAntiTamper(): boolean {
    let found = false;
    try {
        for (const mod of Process.enumerateModules()) {
            if (matchAntiTamper(mod.name)) {
                found = true;
                warnAntiTamper(mod.name);
            }
        }
    } catch (_) {
        // Enumeration can race process teardown; a miss here is non-fatal.
    }
    return found;
}

/**
 * Announce that friTap changed its loader-hook behaviour (skipped the inline
 * `android_dlopen_ext` hook), emitting a structured `anti_tamper_detected`
 * event. The Python host renders the single, blank-line-padded red banner from
 * this event (see `message_router._emit_anti_tamper_detected`) — this function
 * emits no `log()` lines on purpose, to avoid the duplicated/cramped console
 * output the old multi-line banner produced.
 *
 * @param libName  The matched anti-tamper module name when auto-detected, or
 *                 null/empty when the skip was forced via `--no-loader-hook`
 *                 with nothing (yet) detected. Drives `reason`.
 * @param skippedLoaderHook  Whether the loader hook was skipped.
 */
export function bannerAntiTamper(libName: string | null | undefined, skippedLoaderHook: boolean): void {
    const match = matchAntiTamper(libName);
    send({
        contentType: "anti_tamper_detected",
        library: libName ?? "",
        name: match ? match.name : "",
        note: match ? match.note : "",
        skippedLoaderHook,
        reason: match ? "detected" : "flag",
    });
}
