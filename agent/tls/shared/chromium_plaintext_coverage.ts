// agent/tls/shared/chromium_plaintext_coverage.ts
//
// Which modules the supplementary "BoringSSL plaintext" rows of
// agent/platforms/android.ts and agent/platforms/macos.ts cover. Dependency-free
// so the Cronet hooker can ask without importing the platform registry.

/** Module-name pattern of the "BoringSSL plaintext (Cronet)" row. */
export const CRONET_PLAINTEXT_MODULE_PATTERN = /^libcronet([_.].*)?\.so$/;

/**
 * libsignal_jni (Rust `boring` links BoringSSL statically): shared by the
 * "Cronet (Signal)" keylog row and the "BoringSSL plaintext (Signal)" row so both match the same modules.
 * Broader than SIGNAL_LIBRARY_REGEX: ABI-suffixed builds (libsignal_jni_arm64.so) match too.
 */
export const SIGNAL_MODULE_PATTERN = /libsignal_jni(?!_testing).*\.so/;
/** excludePattern of both Signal rows: no _testing build, whatever its prefix. */
export const SIGNAL_MODULE_EXCLUDE_PATTERN = /_testing\.so$/;

/** True when the Signal rows cover `moduleName`. */
function matchesSignalRows(moduleName: string): boolean {
    return SIGNAL_MODULE_PATTERN.test(moduleName) && !SIGNAL_MODULE_EXCLUDE_PATTERN.test(moduleName);
}

/** True when a plaintext row covers `moduleName`, a module whose keys come from the Cronet hooker. */
export function matchesCronetHookerPlaintextRow(moduleName: string): boolean {
    return CRONET_PLAINTEXT_MODULE_PATTERN.test(moduleName) || matchesSignalRows(moduleName);
}

/** Module-name pattern of the "BoringSSL plaintext (Flutter)" row. */
export const FLUTTER_PLAINTEXT_MODULE_PATTERN = /^libflutter\.so$/;

/**
 * macOS Chrome / Electron: the framework binary inside "<Name> Framework.framework"
 * links BoringSSL and QUICHE statically. Shared by the keylog, plaintext and QUICHE rows.
 */
export const CHROMIUM_FRAMEWORK_MODULE_PATTERN = /^(Google Chrome|Electron) Framework$/;

/** True when the ssl_lib.cc error-site locator can run on `arch` (it decodes arm64 only). */
export function plaintextLocatorRunsOn(arch: string = Process.arch): boolean {
    return arch === "arm64";
}

/** True when the Cronet plaintext row hooks `moduleName` (its locator is arm64-only). */
export function cronetPlaintextRowCovers(moduleName: string, arch: string = Process.arch): boolean {
    return plaintextLocatorRunsOn(arch) && CRONET_PLAINTEXT_MODULE_PATTERN.test(moduleName);
}

/** True when the Flutter plaintext row hooks `moduleName` (its locator is arm64-only). */
export function flutterPlaintextRowCovers(moduleName: string, arch: string = Process.arch): boolean {
    return plaintextLocatorRunsOn(arch) && FLUTTER_PLAINTEXT_MODULE_PATTERN.test(moduleName);
}
