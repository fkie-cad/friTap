import { hookRegistry, HookRegistry } from "../shared/registry.js";
import { collectContributedHooks } from "../shared/hook_contributors.js";
import { selected_protocols, use_modern, scan_results } from "../fritap_agent.js";
import { processScanResults } from "../shared/library_scanner.js";
import { log, devlog } from "../util/log.js";
import { getModuleNames, ssl_library_loader, hookDynamicLoader, runInstallPhases } from "../shared/shared_functions.js";
import { Platform, PLATFORM_DARWIN } from "../shared/shared_structures.js";
import { boring_execute, openssl_execute } from "../legacy/tls/platforms/ios/openssl_boringssl_ios.js";
import { boring_execute_modern, openssl_execute_modern } from "../tls/platforms/ios/openssl_boringssl_ios.js";
import { libressl_execute } from "../legacy/tls/platforms/ios/libressl_ios.js";
import { libressl_execute_modern } from "../tls/platforms/ios/libressl_ios.js";
import { VERSIONED_LIBSSL_DYLIB, SYSTEM_LIBRESSL_PATH, ANY_LIBSSL_DYLIB } from "../shared/darwin_library_patterns.js";
import { cronet_execute } from "../legacy/tls/platforms/ios/cronet_ios.js";
import { cronet_execute_modern } from "../tls/platforms/ios/cronet_ios.js";
import { flutter_execute, flutter_execute_modern } from "../tls/platforms/ios/flutter_ios.js"


var plattform_name: Platform = PLATFORM_DARWIN;

export const socket_library = "libSystem.B.dylib"


function hook_iOS_SSL_Libs(hookRegistry: HookRegistry, is_base_hook: boolean) {
    ssl_library_loader(plattform_name, hookRegistry, getModuleNames(), "iOS", is_base_hook, selected_protocols)
}



export function load_ios_hooking_agent() {
    hookRegistry.registerAll([
        // TLS libraries (TLS protocol family)
        { platform: plattform_name, pattern: /.*libboringssl\.dylib/, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "BoringSSL", libraryType: "boringssl", protocol: "tls" },
        // ── The libssl*.dylib name space, partitioned exactly as macos.ts ─────
        // iOS ships LibreSSL in the shared cache at /usr/lib/libssl.<n>.dylib,
        // and an app may bundle genuine OpenSSL as a versioned dylib; neither had
        // any entry here before, so both went entirely unhooked. See
        // agent/shared/darwin_library_patterns.ts for why these three predicates
        // must stay shared objects rather than inlined literals.
        //
        // NOTE: ios.ts and macos.ts both register under PLATFORM_DARWIN into the
        // same registry singleton, and ssl_library_loader invokes EVERY match. The
        // either/or selection in fritap_agent.ts (only one platform agent loads
        // per run) is therefore a load-bearing invariant now, not just a tidiness
        // choice — registering both would double every hook below.
        { platform: plattform_name, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: (use_modern ? libressl_execute_modern : libressl_execute), library: "LibreSSL", pathFilter: SYSTEM_LIBRESSL_PATH, priority: 150, libraryType: "libressl", protocol: "tls" },
        { platform: plattform_name, pattern: VERSIONED_LIBSSL_DYLIB, hookFn: (use_modern ? openssl_execute_modern : openssl_execute), library: "OpenSSL", excludePathFilter: SYSTEM_LIBRESSL_PATH, priority: 120, libraryType: "openssl", protocol: "tls" },
        { platform: plattform_name, pattern: ANY_LIBSSL_DYLIB, hookFn: (use_modern ? boring_execute_modern : boring_execute), library: "OpenSSL/BoringSSL", excludePattern: VERSIONED_LIBSSL_DYLIB, libraryType: "openssl", protocol: "tls" },
        // Cronet on Apple: pinned to legacy on both paths — Apple's Cronet build
        // omits SSL_CTX_set_keylog_callback, so only legacy's ssl_log_secret
        // byte-pattern works. cronet_execute_modern kept imported for a future fix.
        { platform: plattform_name, pattern: /.*cronet.*\.dylib/, hookFn: cronet_execute, library: "Cronet", libraryType: "boringssl", protocol: "tls" },
        { platform: plattform_name, pattern: /.*flutter.*\.dylib/, hookFn: (use_modern ? flutter_execute_modern : flutter_execute), library: "Flutter BoringSSL", libraryType: "boringssl", protocol: "tls" },
        // Hooks contributed by optional units (e.g. the public RC4 key-capture
        // unit under `--protocol rc4`). Empty when no unit registered.
        ...collectContributedHooks(),
    ]);

    const iosLoaderConfig = {
        platform: plattform_name,
        platformLabel: "iOS",
        loaderLibrary: /libSystem.B.dylib/,
        functionName: "dlopen",
        // Required now that the libssl entries above are path-filtered: without a
        // resolved modulePath, _isExcluded fails closed for the LibreSSL entry, so
        // a libssl that appears only after attach would never be routed. Same
        // rationale as macos.ts. The lookup is try/catch-guarded, so an
        // unresolvable module degrades to "no path" rather than throwing.
        extractModulePath: true,
    };

    // Contained + breadcrumbed + yielded, matching Android/macOS. Phase 0 stays
    // synchronous so the BoringSSL keylog hook is live before the host resumes a
    // spawned app — the case that matters most on iOS.
    runInstallPhases("iOS", [
        { label: "ssl-libs",     fn: () => hook_iOS_SSL_Libs(hookRegistry, true) },
        { label: "scan-results", fn: () => processScanResults(scan_results, plattform_name, true, selected_protocols) },
        { label: "loader",       fn: () => hookDynamicLoader(iosLoaderConfig, hookRegistry, getModuleNames(), false, selected_protocols) },
    ]);
}