import { socket_library } from "../../../platforms/android.js";
import { enable_default_fd } from "../../../fritap_agent.js";
import { devlog_error } from "../../../util/log.js";
import { executeFromDefinition } from "../../../core/loader.js";
import { createOpenSslDefinition, createBoringSSLKeylogApproach } from "../../definitions/openssl.js";
import { Java } from "../../../shared/javalib.js";

export function conscrypt_execute_modern(moduleName: string, is_base_hook: boolean) {
    const def = createOpenSslDefinition({ includeExSymbols: true });

    // Use shared BoringSSL keylog approach (SSL_new + SSL_CTX_new + SSL_CTX_set_keylog_callback)
    def.keylog = createBoringSSLKeylogApproach();

    // Java interop as extraHook: block ProviderInstaller updates
    def.extraHooks = [
        {
            install: () => {
                try {
                    blockProviderInstaller();
                } catch (e) {
                    devlog_error(`[modern] Java interop error: ${e}`);
                }
            },
        },
    ];

    executeFromDefinition(def, moduleName, socket_library, is_base_hook, enable_default_fd);
}

// Re-export the legacy execute for bouncycastle provider blocking
export { execute } from "../../../legacy/tls/platforms/android/conscrypt.js";

/**
 * Block ProviderInstallerImpl.insertProvider() and ProviderInstaller.installIfNeeded()
 * to prevent the Conscrypt provider from being updated at runtime.
 */
function blockProviderInstaller(): void {
    Java.perform(function () {
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
            providerInstaller.installIfNeeded.implementation = function (context: any) {
                // blocked
            };
            providerInstaller.installIfNeededAsync.implementation = function (context: any, callback: any) {
                callback.onProviderInstalled();
            };
        } catch (error) {
            // ProviderInstaller not available, skip
        }
    });
}
