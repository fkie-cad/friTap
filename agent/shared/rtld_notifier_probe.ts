import { devlog, log } from "../util/log.js";

/*
 * Detects frida-gum's broken linker-notifier hook on 32-bit ARM Android.
 *
 * On attach, frida-gum hooks the linker's debugger rendezvous stub
 * `rtld_db_dlactivity` (r_brk) to learn about module loads. On arm32 that stub is
 * a 2-byte `bx lr`, so gum can only fit a 4-byte Thumb-2 `B.W`. Observed with
 * frida 17.24.3 on a Pixel 5 (Android 14, armeabi-v7a Firefox): the B.W points
 * at an UNMAPPED address. The next first-time dlopen() then faults inside
 * notify_gdb_of_load() while the linker holds its global lock. When that dlopen
 * runs on frida's JS thread (frida-java-bridge loading libopenjdkjvmti.so on the
 * first Java.use()), frida turns the fault into a JS error and the lock is never
 * released: every later dlopen/dlclose blocks and the app freezes.
 *
 * The pure helpers below are unit-tested; isLinkerNotifierHookBroken() is the
 * device glue.
 */

/** Target of a Thumb-2 `B.W` (encoding T4) at `address`, or null if it is not one. */
export function decodeThumbBranchWTarget(address: number, hw1: number, hw2: number): number | null {
    const isBranchW = (hw1 & 0xf800) === 0xf000 && (hw2 & 0xd000) === 0x9000;
    if (!isBranchW) return null;
    const s = (hw1 >> 10) & 1;
    const j1 = (hw2 >> 13) & 1;
    const j2 = (hw2 >> 11) & 1;
    const i1 = (~(j1 ^ s)) & 1;
    const i2 = (~(j2 ^ s)) & 1;
    const imm10 = hw1 & 0x3ff;
    const imm11 = hw2 & 0x7ff;
    let offset = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1);
    if (s) offset -= 1 << 25;
    return (address + 4 + offset) >>> 0;
}

/** True when `address` lies inside one of the ranges of a /proc/<pid>/maps text. */
export function isAddressInMaps(address: number, mapsText: string): boolean {
    for (const line of mapsText.split("\n")) {
        const match = /^([0-9a-f]+)-([0-9a-f]+)\s/.exec(line);
        if (match === null) continue;
        if (address >= parseInt(match[1], 16) && address < parseInt(match[2], 16)) return true;
    }
    return false;
}

/** True when the stub starts with a B.W whose target is not mapped. */
export function isNotifierBranchBroken(stubAddress: number, hw1: number, hw2: number, mapsText: string): boolean {
    const target = decodeThumbBranchWTarget(stubAddress, hw1, hw2);
    return target !== null && !isAddressInMaps(target, mapsText);
}

function findNotifierStub(): NativePointer | null {
    const linker = Process.findModuleByName("linker");
    if (linker === null) return null;
    for (const symbol of linker.enumerateSymbols()) {
        if (symbol.name.endsWith("rtld_db_dlactivity")) return symbol.address.and(ptr("0xfffffffe"));
    }
    return null;
}

/**
 * Device glue: true only on 32-bit ARM when gum's r_brk hook branches into
 * unmapped memory. /proc/self/maps is read directly because frida cloaks its own
 * ranges from Process.findRangeByAddress(). Any probe failure returns false.
 */
export function isLinkerNotifierHookBroken(): boolean {
    if (Process.arch !== "arm") return false;
    try {
        const stub = findNotifierStub();
        if (stub === null) return false;
        const maps = File.readAllText("/proc/self/maps");
        return isNotifierBranchBroken(stub.toUInt32(), stub.readU16(), stub.add(2).readU16(), maps);
    } catch (e) {
        devlog(`[rtld-probe] linker notifier probe failed: ${e}`);
        return false;
    }
}

/** The one warning logged when Android TLS Java hooks are skipped because of the broken hook. */
export const LINKER_NOTIFIER_JAVA_SKIP_WARNING =
    "frida's linker hook (rtld_db_dlactivity) branches into unmapped memory in this 32-bit process: skipping Android TLS Java hooks, whose first Java.use() would load libopenjdkjvmti.so and freeze the app. Any library the app loads from now on may also crash it. This is a frida-gum bug on 32-bit ARM Android (present up to at least frida 17.27.4): the Thumb hook on rtld_db_dlactivity falls back to a NULL trampoline when SELinux denies patching the linker header cave. Capture 64-bit processes where possible.";

let javaGateVerdict: boolean | null = null;

/**
 * Gate for every Android TLS Java-hook installer (Java.perform / Java.use). Runs the
 * probe once per agent, caches the verdict, and logs LINKER_NOTIFIER_JAVA_SKIP_WARNING
 * once on the first broken verdict, however many callers (the legacy "java" phase, the
 * modern conscrypt ProviderInstaller block) ask. True means: do not touch Java.
 */
export function isJavaBlockedByBrokenLinkerNotifier(
    probe: () => boolean = isLinkerNotifierHookBroken,
    warn: (message: string) => void = log,
): boolean {
    if (javaGateVerdict === null) {
        javaGateVerdict = probe();
        if (javaGateVerdict) warn(LINKER_NOTIFIER_JAVA_SKIP_WARNING);
    }
    return javaGateVerdict;
}

/** Test hook: forget the cached verdict. */
export function resetJavaGateForTests(): void {
    javaGateVerdict = null;
}
