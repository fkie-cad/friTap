// Guard for frida-java-bridge 7.1.0's class-initialisation probe on ARRAY classes.
//
// Since a342d5e ("android: Restore class init on Java.use()"), the bridge's
// ensureClassInitialized() runs `env.getFieldId(classRef, "x", "Z")` for EVERY
// class wrapper it builds, relying on the field lookup to make ART initialise
// the class. That includes array classes: any Java.use("[B"), and every method
// whose argument or return type is an object array (e.g. Security.getProviders()
// -> "[Ljava.security.Provider;"). On the Pixel 5 / Android 14 ART, JNI
// GetFieldID on an array class SIGSEGVs inside
// art::mirror::Class::FindInstanceField (fault addr 0x10: array classes have no
// DexCache). Measured with a plain frida script and no friTap code: bridge
// 7.1.0 + Java.use("[B") kills 64-bit Firefox; bridge b38a5b6 (which only read
// the class name) survives.
//
// Array classes never need the probe: they have no <clinit> and no declared
// fields, so ART treats them as initialised from creation. The guard therefore
// skips exactly the probe for array classes and forwards everything else
// unchanged, keeping 7.1.0's class-init behaviour for ordinary classes.
//
// Pure module (no frida globals at import time) so it is unit-testable in node.

/** Field name/signature frida-java-bridge's ensureClassInitialized() looks up. */
const CLASS_INIT_PROBE_FIELD = "x";
const CLASS_INIT_PROBE_SIGNATURE = "Z";

const GUARD_MARKER = Symbol.for("fritap.arrayClassInitGuard");

export type ArrayClassInitGuardResult = "installed" | "already-installed" | "unavailable";

/** True for the (name, signature) pair the bridge uses as its class-init probe. */
export function isClassInitProbe(name: string, signature: string): boolean {
    return name === CLASS_INIT_PROBE_FIELD && signature === CLASS_INIT_PROBE_SIGNATURE;
}

/** True for a JVM binary class name of an array type ("[B", "[Ljava.lang.String;"). */
export function isArrayClassName(className: string | null | undefined): boolean {
    return typeof className === "string" && className.startsWith("[");
}

/**
 * Decide whether a getFieldId(klass, name, sig) call must be skipped.
 * `resolveClassName` is only called for the probe pair, so ordinary field
 * lookups cost nothing extra. A name that cannot be resolved is not skipped.
 */
export function shouldSkipClassInitProbe(
    name: string,
    signature: string,
    resolveClassName: () => string | null,
): boolean {
    if (!isClassInitProbe(name, signature)) return false;
    let className: string | null = null;
    try {
        className = resolveClassName();
    } catch (_e) {
        return false;
    }
    return isArrayClassName(className);
}

/** Wrap an Env prototype's getFieldId so the class-init probe skips array classes. */
export function guardEnvPrototype(envPrototype: any, nullPointer: unknown): ArrayClassInitGuardResult {
    if (!envPrototype || typeof envPrototype.getFieldId !== "function") return "unavailable";
    if (envPrototype[GUARD_MARKER] === true) return "already-installed";
    if (typeof envPrototype.getClassName !== "function") return "unavailable";

    const originalGetFieldId = envPrototype.getFieldId;
    envPrototype.getFieldId = function (this: any, klass: unknown, name: string, signature: string) {
        if (shouldSkipClassInitProbe(name, signature, () => this.getClassName(klass))) {
            return nullPointer;
        }
        return originalGetFieldId.call(this, klass, name, signature);
    };
    envPrototype[GUARD_MARKER] = true;
    return "installed";
}

/**
 * Install the guard on the bridge's Env prototype. Call once the Java runtime
 * is known to be available (Android), before any Java.use()/Java.perform().
 * Never throws: an unexpected bridge shape yields "unavailable".
 */
export function installArrayClassInitGuard(java: any, nullPointer: unknown): ArrayClassInitGuardResult {
    try {
        const vm = java?.vm;
        if (!vm || typeof vm.perform !== "function") return "unavailable";
        const envPrototype = vm.perform((env: any) => (env ? Object.getPrototypeOf(env) : null));
        return guardEnvPrototype(envPrototype, nullPointer);
    } catch (_e) {
        return "unavailable";
    }
}
