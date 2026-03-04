import { hookRegistry } from "../shared/registry.js";
import { selected_protocol } from "../fritap_agent.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, invokeHookingFunction } from "../shared/shared_functions.js";
import { load_linux_hooking_agent } from "./linux.js";

// Import Windows-style TLS library hooks (reuse existing implementations)
import { boring_execute as boring_execute_windows } from "../tls/platforms/windows/openssl_boringssl_windows.js";
import { gnutls_execute as gnutls_execute_windows } from "../tls/platforms/windows/gnutls_windows.js";
import { mbedTLS_execute as mbedTLS_execute_windows } from "../tls/platforms/windows/mbedTLS_windows.js";
import { nss_execute as nss_execute_windows } from "../tls/platforms/windows/nss_windows.js";
import { wolfssl_execute as wolfssl_execute_windows } from "../tls/platforms/windows/wolfssl_windows.js";
import { cronet_execute as cronet_execute_windows } from "../tls/platforms/windows/cronet_windows.js";

var platform_name = "wine";
var moduleNames: Array<string> = getModuleNames();

// Wine uses Linux sockets (libc), not Windows sockets (WS2_32.dll)
export const socket_library = "libc";

/**
 * Hook Wine's LdrLoadDll function to intercept Windows DLL loading.
 * Wine loads DLLs through ntdll.dll.so's LdrLoadDll export.
 *
 * LdrLoadDll signature (Wine/Windows):
 * NTSTATUS LdrLoadDll(LPCWSTR path_name, DWORD flags, UNICODE_STRING* libname, HMODULE* hModule)
 *
 * UNICODE_STRING structure:
 * struct {
 *     USHORT Length;        // Length of the string in bytes (not including null terminator)
 *     USHORT MaximumLength; // Total size of the buffer in bytes
 *     PWSTR  Buffer;        // Pointer to UTF-16 string
 * }
 */
function hook_Wine_LdrLoadDll(is_base_hook: boolean): void {
    try {
        // Find Wine's ntdll implementation (ntdll.dll.so or similar)
        const ntdllModule = moduleNames.find(m =>
            m.toLowerCase().includes("ntdll") &&
            (m.includes(".so") || m.includes(".dll.so"))
        );

        if (!ntdllModule) {
            devlog("[Wine] ntdll.dll.so not found, skipping DLL hooking");
            return;
        }

        devlog(`[Wine] Found ntdll module: ${ntdllModule}`);

        // Try to find LdrLoadDll export
        let ldrLoadDll: NativePointer | null = null;
        try {
            const ntdll = Process.getModuleByName(ntdllModule);
            ldrLoadDll = ntdll.findExportByName("LdrLoadDll");
        } catch (e) {
            devlog(`[Wine] Error finding LdrLoadDll: ${e}`);
        }

        if (!ldrLoadDll || ldrLoadDll.isNull()) {
            devlog("[Wine] LdrLoadDll not found in " + ntdllModule);
            return;
        }

        devlog(`[Wine] Found LdrLoadDll at ${ldrLoadDll}`);

        Interceptor.attach(ldrLoadDll, {
            onEnter: function(args) {
                // args[2] is UNICODE_STRING* containing the DLL name
                try {
                    const unicodeStr = args[2];
                    if (!unicodeStr.isNull()) {
                        // UNICODE_STRING layout:
                        // offset 0: USHORT Length (2 bytes)
                        // offset 2: USHORT MaximumLength (2 bytes)
                        // offset 4/8: PWSTR Buffer (pointer, 4 or 8 bytes depending on arch)
                        const length = unicodeStr.readU16();
                        if (length > 0 && length < 1024) { // Sanity check
                            const bufferOffset = Process.pointerSize === 8 ? 8 : 4;
                            const bufferPtr = unicodeStr.add(bufferOffset).readPointer();
                            if (!bufferPtr.isNull()) {
                                this.dllName = bufferPtr.readUtf16String(length / 2);
                            }
                        }
                    }
                } catch (e) {
                    devlog(`[Wine] Error reading DLL name in onEnter: ${e}`);
                }
            },
            onLeave: function(retval) {
                // NTSTATUS success is >= 0
                if (this.dllName && retval.toInt32() >= 0) {
                    const dllName = this.dllName as string;
                    const dllBaseName = dllName.split(/[/\\]/).pop() || dllName;

                    const matches = hookRegistry.findAllMatches("wine", dllBaseName, undefined, selected_protocol);
                    for (const match of matches) {
                        log(`[Wine] ${dllBaseName} loaded & will be hooked (${match.library})!`);
                        try {
                            match.hookFn(dllBaseName, is_base_hook);
                        } catch (error) {
                            devlog(`[Wine] DLL hook error for ${dllBaseName}: ${error}`);
                        }
                        break; // Only hook first matching registration per DLL
                    }
                }
            }
        });

        log("[*] Wine LdrLoadDll hooked for DLL interception");
    } catch (error) {
        devlog(`[Wine] Loader hook error: ${error}`);
        log("[Wine] Could not hook LdrLoadDll - DLL hooking disabled");
    }
}

/**
 * Check already-loaded modules for Windows DLLs that should be hooked.
 * This handles cases where the DLL was loaded before we attached.
 */
function hook_Wine_Existing_DLLs(is_base_hook: boolean): void {
    const modules = Process.enumerateModules();

    for (const mod of modules) {
        // Skip non-DLL modules
        if (!mod.name.toLowerCase().endsWith('.dll')) {
            continue;
        }

        const matches = hookRegistry.findAllMatches("wine", mod.name, mod.path, selected_protocol);
        if (matches.length > 0) {
            const match = matches[0];
            log(`[Wine] Found pre-loaded DLL ${mod.name} (${match.library}), hooking...`);
            try {
                match.hookFn(mod.name, is_base_hook);
            } catch (error) {
                devlog(`[Wine] Pre-loaded DLL hook error for ${mod.name}: ${error}`);
            }
        }
    }
}

/**
 * Main Wine hooking agent loader.
 *
 * Strategy:
 * 1. Load the standard Linux agent to hook native .so TLS libraries
 *    (Wine applications often use Wine's built-in GnuTLS/OpenSSL)
 * 2. Hook Wine's LdrLoadDll to intercept Windows DLL loading
 *    (for applications that bundle their own Windows TLS libraries)
 */
export function load_wine_hooking_agent(): void {
    log("Running Script on Wine (Linux + Windows DLLs)");

    // First, load the standard Linux agent for .so libraries
    // Wine apps may use native Linux TLS libs (GnuTLS, OpenSSL as .so)
    log("[Wine] Loading Linux agent for native .so libraries...");
    load_linux_hooking_agent();

    // Then add Wine-specific DLL hooking
    hookRegistry.registerAll([
        { platform: platform_name, pattern: /^(libssl|LIBSSL)-[0-9]+(_[0-9]+)?\.dll$/i, hookFn: invokeHookingFunction(boring_execute_windows), library: "OpenSSL/BoringSSL" },
        { platform: platform_name, pattern: /^.*libssl.*\.dll$/i, hookFn: invokeHookingFunction(boring_execute_windows), library: "OpenSSL/BoringSSL" },
        { platform: platform_name, pattern: /^.*(wolfssl|WOLFSSL).*\.dll$/i, hookFn: invokeHookingFunction(wolfssl_execute_windows), library: "WolfSSL" },
        { platform: platform_name, pattern: /^.*(libgnutls|LIBGNUTLS)-[0-9]+\.dll$/i, hookFn: invokeHookingFunction(gnutls_execute_windows), library: "GnuTLS" },
        { platform: platform_name, pattern: /^(nspr|NSPR)[0-9]*\.dll/i, hookFn: invokeHookingFunction(nss_execute_windows), library: "NSS" },
        { platform: platform_name, pattern: /mbedTLS\.dll/i, hookFn: invokeHookingFunction(mbedTLS_execute_windows), library: "mbedTLS" },
        { platform: platform_name, pattern: /^.*(cronet|CRONET).*\.dll/i, hookFn: invokeHookingFunction(cronet_execute_windows), library: "Cronet" },
    ]);

    // Hook existing Windows DLLs that are already loaded
    log("[Wine] Checking for pre-loaded Windows DLLs...");
    hook_Wine_Existing_DLLs(true);

    // Hook future DLL loads via LdrLoadDll
    log("[Wine] Setting up LdrLoadDll hook for future DLL loads...");
    hook_Wine_LdrLoadDll(false);
}