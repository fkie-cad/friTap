// Guard for frida-java-bridge 7.1.0 loading ART's JVMTI plugin into the target.
//
// On Android the bridge loads libopenjdkjvmti.so lazily, on the first Java.use()
// (tryGetEnvJvmti in lib/android.js). Unlike every other ART call the bridge
// makes, that NativeFunction has no `exceptions: "propagate"`, so a fault inside
// it is caught by Frida instead of ART's own fault handler. ART raises SIGSEGV on
// purpose during normal execution (implicit null and suspend checks in managed
// code), and those faults must reach ART. Measured on Pixel 5 / Android 14 /
// Chrome 158: attaching within ~10 s of launch, the plugin load faults on frida's
// JS thread (pc in boot.oat managed code, "access violation accessing 0x0") in
// about 1 of 3 runs. Frida unwinds the thread out of ART mid-call, so ART still
// thinks it is running Java code: Chrome wedges (0 keys) and aborts on detach.
//
// The bridge needs JVMTI here: without it, its class models fall back to a
// java/lang/Thread layout probe that fails on this device ("Unable to find copied
// methods in java/lang/Thread"), which breaks every Java hook. So instead of
// hiding the plugin, the guard loads it once ITSELF, at the moment the bridge
// looks the loader up, through a NativeFunction that lets faults propagate to
// ART. ART's Runtime::EnsurePluginLoaded returns early for an already loaded
// plugin, so the bridge's own unprotected call that follows runs no Java code.
//
// The guard logic is pure (no frida globals at import time) so it is unit-testable.

/** The ART symbol the bridge resolves to load the JVMTI plugin. */
export const ENSURE_PLUGIN_LOADED_SYMBOL =
    "_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE";

const GUARD_MARKER = Symbol.for("fritap.jvmtiPluginGuard");

export type JvmtiGuardResult = "installed" | "already-installed" | "unavailable";

/** Loads the plugin through EnsurePluginLoaded at `address`; true on success. */
export type PluginLoader = (address: any, artRuntime: any) => boolean;

/**
 * Wrap a bridge api object's find() so the first lookup of the JVMTI plugin
 * loader first loads the plugin through `loadPlugin`. The real address is always
 * returned, so the bridge keeps its normal JVMTI path.
 */
export function guardApiFind(api: any, loadPlugin: PluginLoader, report: (msg: string) => void): JvmtiGuardResult {
    if (!api || typeof api.find !== "function") return "unavailable";
    if (api[GUARD_MARKER] === true) return "already-installed";
    const originalFind = api.find;
    let attempted = false;
    api.find = function (this: any, name: string) {
        const address = originalFind.call(this, name);
        if (name === ENSURE_PLUGIN_LOADED_SYMBOL && address !== null && !attempted) {
            attempted = true;
            report(preloadOutcome(() => loadPlugin(address, api.artRuntime)));
        }
        return address;
    };
    api[GUARD_MARKER] = true;
    return "installed";
}

function preloadOutcome(load: () => boolean): string {
    try {
        return load() ? "JVMTI plugin preloaded" : "JVMTI plugin preload returned false";
    } catch (e) {
        return `JVMTI plugin preload failed: ${e}`;
    }
}

/**
 * Install the guard on the bridge's api object. Call before any
 * Java.use()/Java.perform(). Never throws: an unexpected bridge shape yields
 * "unavailable" and the bridge behaves as before.
 */
export function installJvmtiPluginGuard(java: any, report: (msg: string) => void,
                                        loadPlugin: PluginLoader = loadJvmtiPluginWithFaultsPropagated): JvmtiGuardResult {
    try {
        return guardApiFind(java?.api, loadPlugin, report);
    } catch (_e) {
        return "unavailable";
    }
}

const FINISH_SETUP_SYMBOL = "_ZN12openjdkjvmti12DeoptManager11FinishSetupEv";

/**
 * The bridge's own plugin load, with `exceptions: "propagate"`. Like the bridge
 * (withoutDebuggableTransition), it skips DeoptManager::FinishSetup so loading
 * the plugin does not switch the runtime to debuggable.
 */
export function loadJvmtiPluginWithFaultsPropagated(address: any, artRuntime: any): boolean {
    const ensurePluginLoaded = new NativeFunction(address, "bool", ["pointer", "pointer", "pointer"],
        { exceptions: "propagate" } as any);
    const errorMessage = Memory.alloc(32); // std::string* (libc++: 24 bytes, all-zero = empty)
    errorMessage.writeByteArray(new Array(32).fill(0));
    return withFinishSetupSkipped(() =>
        Boolean(ensurePluginLoaded(artRuntime, Memory.allocUtf8String("libopenjdkjvmti.so"), errorMessage)));
}

function withFinishSetupSkipped(loadPlugin: () => boolean): boolean {
    let finishSetup: NativePointer | null = null;
    const skipFinishSetup = new NativeCallback(() => {}, "void", ["pointer"]);
    const dlsymListener = Interceptor.attach(Process.getModuleByName("libdl.so").getExportByName("dlsym"), {
        onEnter(args) {
            (this as any).isPluginInitializer = args[1].readCString() === "ArtPlugin_Initialize";
        },
        onLeave() {
            if (!(this as any).isPluginInitializer) return;
            finishSetup = Process.getModuleByName("libopenjdkjvmti.so").findExportByName(FINISH_SETUP_SYMBOL);
            if (finishSetup !== null) Interceptor.replace(finishSetup, skipFinishSetup);
        },
    });
    try {
        return loadPlugin();
    } finally {
        dlsymListener.detach();
        if (finishSetup !== null) Interceptor.revert(finishSetup);
        Interceptor.flush();
    }
}
