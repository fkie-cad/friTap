import { devlog } from "../../util/log.js";

// Platform-specific excludes for known non-TLS modules (JNI wrappers, etc.)
const ANDROID_EXCLUDES = [/libjavacrypto\.so/];

// Minimum number of exports for a module to be considered a real TLS implementation
const MIN_EXPORT_COUNT = 5;

export function findModulesWithSSLKeyLogCallback(): string[] {
    const modules = Process.enumerateModules();
    const matchedModules: string[] = [];

    for (const mod of modules) {
        // Skip modules we are already hooking
        if (/.*libssl_sb\.so/.test(mod.name) || /.*libssl\.so/.test(mod.name) || /ibconscrypt_jni.so/.test(mod.name) || /libconscrypt_gmscore_jni.so/.test(mod.name)) {
            continue;
        }

        // Skip known non-TLS modules per platform (fast path)
        if (Process.platform === "linux") {
            if (ANDROID_EXCLUDES.some(re => re.test(mod.name))) {
                devlog(`Skipping known non-TLS module: ${mod.name}`);
                continue;
            }
        }

        // Targeted lookup first (cheap), then validate export count (expensive)
        if (mod.findExportByName("SSL_CTX_set_keylog_callback") !== null) {
            const exportCount = mod.enumerateExports().length;
            if (exportCount < MIN_EXPORT_COUNT) {
                devlog(`Skipping ${mod.name}: only ${exportCount} exports (minimum ${MIN_EXPORT_COUNT})`);
                continue;
            }
            matchedModules.push(mod.name);
        }
    }

    return matchedModules;
}

