import { load_android_hooking_agent } from "./platforms/android.js";
import { load_ios_hooking_agent } from "./platforms/ios.js";
import { load_macos_hooking_agent } from "./platforms/macos.js";
import { load_linux_hooking_agent } from "./platforms/linux.js";
import { load_windows_hooking_agent, load_windows_lsass_agent } from "./platforms/windows.js";
import { load_wine_hooking_agent } from "./platforms/wine.js";
// PUBLIC RC4 key-capture unit. Side-effecting import: registers the RC4 hook
// contributors (protocol "rc4", no TLS implication) at module-load time, before
// the platform loaders call collectContributedHooks() during platform-load. RC4
// is a first-class public protocol, so it is wired into the public entry here
// (unlike the private Signal unit, which is wired only into fritap_agent_full).
import "./rc4/index.js";
import { isWindows, isLinux, isWine, isAndroid, isiOS, isMacOS, getDetailedPlatformInfo } from "./util/process_infos.js";
import { anti_root_execute } from "./util/anti_root.js";
import { socket_trace_execute } from "./misc/socket_tracer.js"
import { devlog, log, hookBreadcrumb } from "./util/log.js";
import { initializePipeline } from "./shared/pipeline_utils.js";
import { AGENT_ABI_VERSION } from "./shared/generated_constants.js";
// Process-wide runtime state lives in the side-effect-free shared_structures
// module so that optional protocol units (e.g. agent/signal/) can read these
// flags without importing this entry (which would run the top-level install).
// We import them + their setters here, set them during config parsing, and
// re-export them so the many modules that read these from `fritap_agent` keep
// working unchanged.
import {
    setSelectedProtocol,
    offsets, pcap_enabled, keylog_enabled, _isShuttingDown, ohttp_enabled, selected_protocol, selected_protocols, config_extensions,
    setOffsets, setPcapEnabled, setKeylogEnabled, setIsShuttingDown, setOhttpEnabled, setConfigExtensions,
} from "./shared/shared_structures.js";
export { offsets, pcap_enabled, keylog_enabled, _isShuttingDown, ohttp_enabled, selected_protocol, selected_protocols, config_extensions };
import { maybeRunRegionScan } from "./shared/scan/scan_engine.js";
import { stopBlink } from "./shared/pairip_blink.js";
import { restoreAnchorLocatorKeylogFields } from "./shared/boringssl_anchor_locator.js";
import { restoreTrackedKeylogCallbacks } from "./shared/keylog_callback_tracker.js";

// global address which stores the addresses of the hooked modules which aren't loaded via the dynamic loader
(globalThis as any).init_addresses = {};

/**
 * Run one named startup stage, emitting a breadcrumb BEFORE it executes.
 *
 * The breadcrumb is what survives a NATIVE death. When the agent kills the target
 * during startup there is no JS exception for Frida to report — the host just sees
 * "the connection is closed" and has no idea how far the agent got (this is exactly
 * what fkie-cad/friTap#65 reported on iOS, and it reproduces in spawn mode on
 * macOS). Because the host records every breadcrumb as it arrives
 * (ssl_logger_core: _on_hook_breadcrumb) and prints the last one in its crash
 * message, sending the stage name up-front turns "it died somewhere" into "it died
 * in platform-detect".
 *
 * `fatal: false` contains a stage failure: the error is reported and startup
 * continues, so one broken subsystem cannot cost the user every other hook.
 */
function initStage<T>(stage: string, fn: () => T, fatal: boolean = true): T | undefined {
    hookBreadcrumb(`agent-init: ${stage}`);
    devlog(`[init] stage: ${stage}`);
    try {
        return fn();
    } catch (e: any) {
        hookBreadcrumb(`agent-init-FAILED: ${stage}`);
        log(`[-] friTap agent init failed in stage '${stage}': ${e && e.stack ? e.stack : e}`);
        if (fatal) throw e;
        return undefined;
    }
}

/**
 * Shared teardown for the gracefulDetach RPC and Frida's `dispose` hook.
 * Idempotent: every step is a flag set, a detach, or a restore that clears
 * its own bookkeeping, so running it twice (graceful_detach then unload) is safe.
 */
function releaseAgentHooks(): void {
    // Set the shutdown flag BEFORE Interceptor.detachAll so any callback
    // already mid-execution (or queued on the JS message loop) sees the
    // flag at sendDatalog/emit and short-circuits. Order matters: if we
    // detached first and then set the flag, callbacks already queued
    // between the two statements would still pay the full IPC cost.
    setIsShuttingDown(true);
    try { stopBlink(); } catch (_e) { /* blink not active */ }
    // BEFORE detachAll, on purpose: the callback tier's SSL_CTX_free hook must
    // still be live so a CTX being freed right now blocks in its onEnter (we
    // hold the script lock) instead of being written after release. The
    // registry is sealed first, so the SSL_new/SSL_CTX_new hooks that are
    // still attached can no longer re-install the callback behind the restore.
    try { restoreTrackedKeylogCallbacks(); } catch (_e) { /* best effort */ }
    try {
        Interceptor.detachAll();
    } catch (e) {
        try {
            log(`[gracefulDetach] Interceptor.detachAll threw: ${e}`);
        } catch (_e2) { /* host already gone */ }
    }
    // After detachAll (so no hook can re-install it): NULL the SSL_CTX
    // keylog_callback fields tier 4 filled with a script-owned callback,
    // which would otherwise dangle once the script unloads.
    try { restoreAnchorLocatorKeylogFields(); } catch (_e) { /* best effort */ }
}

// Declared BEFORE anything that can throw or kill the target, so the host's
// agent_abi_version() / graceful_detach() calls keep working even when startup
// fails. Previously this sat at the very end of the module, so any init failure
// left the host with no RPC surface and an obscure error instead of a diagnosis.
// Safe this early: agentAbiVersion returns a compile-time constant, and every
// gracefulDetach step is either a plain setter on the already-initialised
// shared_structures module or a no-op that is individually try/catch-wrapped.
rpc.exports = {
    //@ts-ignore
    agentAbiVersion(): number {
        // Reports the ABI this bundle was compiled against so the Python host
        // can detect a stale / mismatched bundle (see AGENT_ABI_VERSION in
        // friTap/constants.py, mirrored here via generated_constants). Frida 17+
        // maps this to Python `script.exports_sync.agent_abi_version()`.
        return AGENT_ABI_VERSION;
    },
    //@ts-ignore
    gracefulDetach(): void {
        releaseAgentHooks();
    },
    //@ts-ignore
    dispose(): void {
        // frida-core calls the `dispose` RPC export on EVERY script unload
        // (lib/payload/script-engine.vala: ensure_dispose_called ->
        // rpc_client.call("dispose", [reason]) from close() and
        // prepare_for_termination()), including the unclean paths where the
        // host never reached graceful_detach: host killed, connection drop,
        // graceful_detach failure followed by a plain unload. Without this,
        // tier 4's SSL_CTX->keylog_callback write would dangle after unload
        // and SIGSEGV the target on its next handshake.
        try { releaseAgentHooks(); } catch (_e) { /* never block unload */ }
    }
};

interface IAddress{
    address: string,
    absolute: boolean
}


interface IOffsets {
    openssl?: {
        SSL_read?: IAddress,
        SSL_write?: IAddress,
        SSL_SESSION_get_id?: IAddress,
        BIO_get_fd?: IAddress,
        SSL_get_session?: IAddress,
        ssl_get_fd?: IAddress,
        SSL_new?: IAddress,
        SSL_CTX_set_keylog_callback?: IAddress
    },
    wolfssl?: {
        wolfSSL_read?: IAddress,
        wolfSSL_write?: IAddress,
        wolfSSL_get_fd?: IAddress,
        wolfSSL_get_session?: IAddress,
        wolfSSL_connect?: IAddress,
        wolfSSL_KeepArrays?: IAddress,
        wolfSSL_SESSION_get_master_key?: IAddress,
        wolfSSL_get_client_random?: IAddress,
        wolfSSL_get_server_random?: IAddress,

    }
    nss?: {
        SSL_GetSessionID?: IAddress,
        PR_GetSockName?: IAddress,
        PR_GetPeerName?: IAddress
        PR_Write?: IAddress,
        PR_Read?: IAddress,
        PR_FileDesc2NativeHandle?: IAddress,
        PR_GetNameForIdentity?: IAddress,
        PR_GetDescType?: IAddress
    },
    mbedtls?: {
        mbedtls_ssl_read?: IAddress,
        mbedtls_ssl_write?: IAddress
    },
    matrixssl?: {
        matrixSslReceivedData?: IAddress,
        matrixSslGetWritebuf?: IAddress,
        matrixSslGetSid?: IAddress,
        matrixSslEncodeWritebuf?: IAddress
    },
    gnutls?: {
        gnutls_record_recv?: IAddress,
        gnutls_record_send?: IAddress,
        gnutls_session_set_keylog_function?: IAddress,
        gnutls_transport_get_int?: IAddress,
        gnutls_session_get_id?: IAddress,
        gnutls_init?: IAddress,
        gnutls_handshake?: IAddress,
        gnutls_session_get_keylog_function?: IAddress,
        gnutls_session_get_random?: IAddress
    },
    sspi?:{
        EncryptMessage: IAddress,
        DecryptMessage: IAddress
    },
    s2n?:{
        s2n_send: IAddress;
        s2n_recv: IAddress;
    },
    rustls?:{
        rustls_connection_write_tls: IAddress;
        rustls_connection_read_tls: IAddress;
        rustls_client_config_builder_new: IAddress;
        rustls_client_config_builder_new_custom: IAddress;
        rustls_client_config_builder_set_key_log: IAddress;
    },
    gotls?:{
        "crypto/tls.(*Conn).Read": IAddress;
        "crypto/tls.(*Conn).Write": IAddress;
        "crypto/tls.(*Conn).Handshake": IAddress;
        "crypto/tls.(*Config).writeKeyLog": IAddress;
        "crypto/tls.(*Conn).makeClientKeyExchange": IAddress;
        "crypto/tls.(*Conn).exportKeyingMaterial": IAddress;
        "crypto/tls.(*Conn).updateTrafficSecret": IAddress;
        "crypto/tls.(*Conn).nextTrafficSecret": IAddress;
        "crypto/tls.hkdfExpand": IAddress;
        "crypto/tls.hkdfExtract": IAddress;
        "crypto/tls.(*Conn).writeRecordLocked": IAddress;
        "crypto/tls.(*Conn).readRecord": IAddress;
        "crypto/tls.(*Conn).connectionStateLocked": IAddress;
        "runtime.buildVersion": IAddress;
    }

    google_quiche?:{
        QuicSpdyStream_Readv?: IAddress,
        QuicStream_Readv?: IAddress,
        QuicStreamSequencer_Readv?: IAddress,
        QuicSpdyStream_OnDataFramePayload?: IAddress,
        QuicSpdyStream_WriteOrBufferBody?: IAddress,
        QuicStream_WriteOrBufferData?: IAddress,
        QuicStreamSequencer_OnStreamFrame?: IAddress,
        QuicSpdyStream_OnBodyAvailable?: IAddress,
        QuicSpdyStream_OnHeadersDecoded?: IAddress,
        QuicSpdyStream_WriteHeaders?: IAddress
    }

    sockets?:{
        getpeername?: IAddress,
        getsockname?: IAddress,
        ntohs?: IAddress,
        ntohl?: IAddress
    },
    // Signal's native HKDF stack (libsignal_jni.so). Same per-library schema as
    // every other entry; consumed by the Signal path via offsets["libsignal_jni"].
    libsignal_jni?:{
        HKDF_Extract?: IAddress,
        HKDF_Expand?: IAddress
    }
}

//@ts-ignore
export let experimental: boolean = false;
//@ts-ignore
export let enable_socket_tracing: boolean = false;
//@ts-ignore
export let anti_root: boolean = false;
//@ts-ignore
export let enable_default_fd: boolean = false;
//@ts-ignore
export let use_modern: boolean = false;
//@ts-ignore
export let install_lsass_hook: boolean = true;
// Sentinel detected at the handshake boundary; renaming this literal
// no longer changes gate behavior the way the previous `length > 10`
// heuristic did.
const PATTERNS_PLACEHOLDER = "{PATTERNS}";
//@ts-ignore
export let patterns: string = PATTERNS_PLACEHOLDER;
let parsedPatterns: any = null;
//@ts-ignore
export let scan_results: string = "{SCAN_RESULTS}";
//@ts-ignore
export let library_scan_enabled: boolean = false;
//@ts-ignore
export let quic_capture_mode: string = "stream";
// Force-mode override for the HTTP/3 egress-headers chain. "auto" keeps the
// winner-takes-all fallback chain (quiche-internal preferred, chrome-shim as
// fallback, session-level as last resort). Any other value installs exactly
// that layer and skips the others — useful for chain-validation testing on
// builds where the primary layer would otherwise always win. Only effective
// in app-api capture mode. See agent/quic/definitions/google_quiche.ts.
//@ts-ignore
export let quic_egress_headers_layer: string = "auto";
// Mirrors the -do / --debugoutput CLI flag. Used by paths that emit expensive
// diagnostic output (e.g. enumerating every dynsym/pattern candidate for the
// QUIC chain labels) so the agent can skip the work entirely when the user
// did not ask for debug output. Cheap per-call devlog_debug() calls do NOT
// need this gate — they're filtered Python-side based on the same flag.
//@ts-ignore
export let debug_output: boolean = false;
// Shutdown gate. Set to true by the gracefulDetach RPC (called by Python's
// detach_with_timeout before script.unload()). Hot data emission paths
// (sendDatalog / emit) check this flag FIRST and bail immediately — so any
// callback that was already queued on the single JS message loop drains in
// microseconds (just the gate check) instead of seconds (full IPC). Without
// this, Interceptor.detachAll() alone is insufficient: it removes the
// trampolines for FUTURE calls, but the queue of already-scheduled callbacks
// still has to drain through Python IPC before script.unload() can return,
// and under heavy Chrome HTTP/3 traffic that drain takes >30s. Per Frida's
// own design (single-threaded JS message loop, unbounded queue), this is the
// canonical user-level workaround documented in frida-gum#474 and related.
// (declared in ./shared/shared_structures.ts; imported + re-exported above.)
// When --quic-only is set, install ONLY the Google QUICHE hooks and skip every TLS-
// library hook + Java hooks + OHTTP + keylog scan-result hooks. Useful when the
// user only wants HTTP/3 capture: the attach is much lighter (no multi-megabyte
// pattern scans, no Java VM safepoint sync), which also reduces the risk of stalling
// an already-busy target during attach.
//@ts-ignore
export let quic_only: boolean = false;

// --no-loader-hook: skip the inline android_dlopen_ext loader trampoline. Set
// automatically (spawn + anti-tamper) or forced via the flag. Avoids the PairIP
// SIGSEGV in spawn mode; only already-loaded / explicitly-selected TLS libs are
// hooked. See agent/platforms/android.ts loader-hook gating and friTap#64.
//@ts-ignore
export let no_loader_hook: boolean = false;

// True when friTap spawned the target (-s) rather than attaching. The
// android_dlopen_ext loader hook only trips PairIP when resident during the
// spawn-time integrity scan, so the anti-tamper auto-skip is gated on this.
//@ts-ignore
export let spawned: boolean = false;

// EXPERIMENTAL (--experimental-stealth-loader, Part C / friTap#64). When true,
// the Android loader is watched via a hardware breakpoint (ARM64 debug
// registers, no linker code patch) instead of the inline android_dlopen_ext
// trampoline, so late-loaded TLS libs can be hooked on PairIP-protected apps
// without tripping the anti-tamper scan. Unvalidated on-device; defaults OFF.
//@ts-ignore
export let stealth_loader: boolean = false;

// --pairip-safe (friTap#64): minimal, scan-free capture mode for PairIP-
// protected apps (works with both attach and spawn). PairIP runs a PERIODIC
// code-integrity check that SIGSEGVs the
// process when it finds inline hooks. Empirically (on com.blizzard.arc) the
// trigger is friTap's broad footprint — the dynamic-loader hook AND the
// pattern-scan/hooking of the WebView/Chromium (Cronet) libs. A minimal
// symbol-only keylog on the exported-symbol BoringSSL libs (libssl.so,
// libjavacrypto.so, libconscrypt*) survives the check's window and captures
// keys. When true the android agent restricts the hook registry to those libs
// and runs ONLY the ssl-libs phase (no loader hook, no pattern scan, no Java,
// no OHTTP, no library-scan). Attach mode only.
//@ts-ignore
export let pairip_safe: boolean = false;

// --probe (friTap#65): dry-run diagnostic. The agent detects the platform,
// reports which branch it WOULD take via the "platform_report" message, and
// then returns WITHOUT installing a single hook and without any other
// target-mutating step (no anti-root, no socket tracing, no region scan).
// It exists because the iOS crash in friTap#65 kills the target during
// instrumentation, leaving no way to learn how far the agent got — probe mode
// separates "platform detection works" from "hook installation kills it".
//@ts-ignore
export let probe: boolean = false;

// --boringssl-anchor-only (debugging aid, fkie-cad/friTap#... Chrome/libhttpengine):
// force the last-resort BoringSSL anchor locator (tier 4) by SKIPPING the pattern
// tier so a total-miss is reported straight to onAllKeylogTiersMissed, which runs
// tier 4. Lets the anchor locator be exercised on-device even where a pattern
// would otherwise win. arm64 only; still honours --pairip-safe (tier 4 is a scan).
//@ts-ignore
export let force_anchor_locator: boolean = false;

/**
 * Perform a send/recv handshake with the Python host to receive a configuration value.
 * @param sendChannel Channel name to send on
 * @param defaultValue Default value if no payload received
 * @param recvChannel Channel name to receive on (defaults to sendChannel)
 */
function recvHandshake<T>(sendChannel: string, defaultValue: T, recvChannel?: string): T {
    let result = defaultValue;
    send(sendChannel);
    recv(recvChannel || sendChannel, (value: any) => {
        if (value.payload !== null && value.payload !== undefined) {
            result = value.payload;
        }
    }).wait();
    return result;
}

/* Batch config handshake: receive all config values in a single IPC round-trip */
const config_batch = initStage("config-handshake",
    () => recvHandshake<Record<string, any>>("config_batch", {})) as Record<string, any>;
setOffsets(config_batch.offsets ?? offsets);
// `--offsets` is delivered over config_batch as the raw JSON *string* (the file
// contents / json argument), so parse it once here into the object that
// resolveOffsets() and the Signal path index by library name. Legacy builds
// that string-replace the "{OFFSETS}" placeholder already deliver an object
// (typeof !== "string"), and the un-replaced placeholder sentinel is left as-is
// so resolveOffsets()'s `offsets == "{OFFSETS}"` short-circuit still fires.
if (typeof offsets === "string" && offsets !== "{OFFSETS}" && (offsets as string).length > 0) {
    try {
        setOffsets(JSON.parse(offsets as unknown as string) as IOffsets);
    } catch (e: any) {
        log(`[offsets] handshake delivered invalid JSON: ${e && e.message ? e.message : e} - ignoring offsets`);
        setOffsets("{OFFSETS}" as any);
    }
}
// Parse pattern data once at the boundary. On failure, `patterns` stays
// at the placeholder so isPatternReplaced() and the raw string export
// remain consistent.
if (typeof config_batch.patterns === "string"
    && config_batch.patterns !== PATTERNS_PLACEHOLDER
    && config_batch.patterns.length > 0) {
    try {
        parsedPatterns = JSON.parse(config_batch.patterns);
        patterns = config_batch.patterns;
    } catch (e: any) {
        log(`[patterns] handshake delivered invalid JSON: ${e && e.message ? e.message : e} - disabling patterns`);
        parsedPatterns = null;
    }
}
enable_socket_tracing = config_batch.socket_tracing ?? enable_socket_tracing;
enable_default_fd = config_batch.defaultFD ?? enable_default_fd;
setPcapEnabled(config_batch.pcap_enabled ?? pcap_enabled);
setKeylogEnabled(config_batch.keylog_enabled ?? keylog_enabled);
experimental = config_batch.experimental ?? experimental;
setSelectedProtocol(config_batch.protocol_select ?? selected_protocol);
install_lsass_hook = config_batch.install_lsass_hook ?? install_lsass_hook;
use_modern = config_batch.use_modern ?? use_modern;
scan_results = config_batch.library_scan ?? scan_results;
library_scan_enabled = config_batch.library_scan_enabled ?? library_scan_enabled;
setOhttpEnabled(config_batch.ohttp_enabled ?? ohttp_enabled);
quic_capture_mode = config_batch.quic_capture_mode ?? quic_capture_mode;
quic_only = config_batch.quic_only ?? quic_only;
no_loader_hook = config_batch.no_loader_hook ?? no_loader_hook;
spawned = config_batch.spawned ?? spawned;
stealth_loader = config_batch.stealth_loader ?? stealth_loader;
pairip_safe = config_batch.pairip_safe ?? pairip_safe;
quic_egress_headers_layer = config_batch.quic_egress_headers_layer ?? quic_egress_headers_layer;
debug_output = config_batch.debug_output ?? debug_output;
probe = config_batch.probe ?? probe;
force_anchor_locator = config_batch.force_anchor_locator ?? force_anchor_locator;
// Generic feature-config passthrough (e.g. { scan_region } for the public
// memory-scan engine). Protocol-agnostic: the public core never inspects a
// private sub-key; private units read their own keys from config_extensions.
setConfigExtensions(config_batch.extensions ?? {});

// "anti" handshake must be LAST in the startup sequence to prevent deadlock
anti_root = initStage("anti-handshake", () => recvHandshake("anti", anti_root, "antiroot")) as boolean;

// Initialize the hooking pipeline centrally so it is ready before any library constructor runs.
initStage("pipeline-init", () => initializePipeline(parsedPatterns ?? undefined, experimental));



/*

create the TLS library for your first prototpye as a lib in ./ssl_lib and than extend this class for the OS where this new lib was tested.

Further keep in mind, that properties of an class only visible inside the Interceptor-onEnter/onLeave scope when they are static. 
As an alternative you could make a local variable inside the calling functions which holds an reference to the class property.

*/


export function getOffsets(){
    return offsets;
}

export function isPatternReplaced(): boolean {
    return parsedPatterns !== null;
}

export function getParsedPatterns(): any {
    return parsedPatterns;
}


/**
 * Which platform's hooks to install.
 *
 * Split out from the dispatch below so platform DETECTION is its own named init
 * stage: on Apple platforms these predicates make live Objective-C calls, and in
 * spawn mode they run inside a still-suspended process whose Foundation may not be
 * initialised yet — so this is a place the agent can die, and the breadcrumb has to
 * be able to say so.
 *
 * Order is load-bearing: Wine processes ARE Linux processes, so isWine() must be
 * asked before isLinux().
 */
type TargetKind = "windows" | "android" | "wine" | "linux" | "ios" | "macos" | "unknown";

function detectTarget(): TargetKind {
    if (isWindows()) return "windows";
    if (isAndroid()) return "android";
    if (isWine()) return "wine";
    if (isLinux()) return "linux";
    if (isiOS()) return "ios";
    if (isMacOS()) return "macos";
    return "unknown";
}

/**
 * What the agent decided to do, split from actually doing it.
 *
 * `label` is the human-readable platform name that gets logged AND reported to
 * the host; `install()` is everything that touches the target. The split is what
 * makes `--probe` honest: probe mode reports the label and never calls the thunk,
 * so a report can never be produced by code that already mutated the process.
 *
 * Consequence for maintainers: pure logging may live in planForTarget(), but
 * ANY target interaction (hook installation, anti-root patching, socket tracing)
 * MUST live inside install().
 */
interface PlatformPlan {
    label: string;
    install: () => void;
}

/**
 * Optional socket tracing, shared by every platform that supports it.
 *
 * Enabled on android / wine / linux / ios / macos — deliberately NOT on windows
 * (the Windows branch has never called it) and not on the unknown-platform
 * branch (nothing gets hooked there anyway).
 */
function maybe_trace_sockets(): void {
    if (enable_socket_tracing) {
        socket_trace_execute();
    }
}

function planForTarget(target: TargetKind): PlatformPlan {
    switch (target) {
        case "windows":
            return {
                label: 'Windows',
                install: () => {
                    if (install_lsass_hook) {
                        load_windows_lsass_agent();
                    } else {
                        log('Skipping LSASS hooking as per configuration');
                    }
                    load_windows_hooking_agent();
                }
            };
        case "android":
            return {
                label: 'Android',
                install: () => {
                    if (anti_root) {
                        log('Applying anti root checks');
                        anti_root_execute();
                    }
                    maybe_trace_sockets();
                    load_android_hooking_agent();
                }
            };
        case "wine":
            // Wine must be checked BEFORE isLinux() since Wine processes are Linux
            // processes — see detectTarget(). Without --experimental we fall back to
            // the plain Linux agent, and the label follows the branch actually taken
            // so a probe report never claims a Wine run that did not happen.
            if (experimental) {
                return {
                    label: 'Wine (experimental)',
                    install: () => {
                        maybe_trace_sockets();
                        load_wine_hooking_agent();
                    }
                };
            }
            log('[!] Wine process detected. Wine support is experimental and requires the --experimental flag.')
            log('[!] Falling back to standard Linux agent.')
            return {
                label: 'Linux',
                install: () => {
                    maybe_trace_sockets();
                    load_linux_hooking_agent();
                }
            };
        case "linux":
            return {
                label: 'Linux',
                install: () => {
                    maybe_trace_sockets();
                    load_linux_hooking_agent();
                }
            };
        case "ios":
            return {
                label: 'iOS',
                install: () => {
                    maybe_trace_sockets();
                    // devlog(`[iOS Detection] Architecture: ${Process.arch}, Platform: ${Process.platform}`); // uncomment for debugging
                    load_ios_hooking_agent();
                }
            };
        case "macos":
            return {
                label: 'MacOS',
                install: () => {
                    maybe_trace_sockets();
                    // devlog(`[macOS Detection] Architecture: ${Process.arch}, Platform: ${Process.platform}`); // uncomment for debugging
                    load_macos_hooking_agent();
                }
            };
        default:
            return {
                label: 'unknown platform',
                install: () => {
                    log(`Platform: ${Process.platform}, Architecture: ${Process.arch}`)
                    log("Error: not supported platform!\nIf you want to have support for this platform please make an issue at our github page.")
                    // Only place the detailed (ObjC-messaging) dump is still worth its risk:
                    // we have no idea what this platform is, and we are not going to hook it.
                    try {
                        devlog(`[Unknown Platform] Full detection info: ${JSON.stringify(getDetailedPlatformInfo(), null, 2)}`);
                    } catch (e) {
                        devlog(`[Unknown Platform] detailed info unavailable: ${e}`);
                    }
                }
            };
    }
}

function load_os_specific_agent() {
    // NOTE: getDetailedPlatformInfo() is deliberately NOT called here.
    // It is a debug-only dump, but it performs live ObjC messaging
    // (+[NSProcessInfo processInfo], -operatingSystemVersionString, and six
    // -[NSFileManager fileExistsAtPath:] calls). Running that unconditionally
    // before platform dispatch killed spawned Apple targets outright — measured
    // on macOS: the agent died 14ms after pipeline init and before the platform
    // branch logged anything (fkie-cad/friTap#65). Its only consumer was a
    // commented-out devlog; it now runs only for an unknown platform, and behind
    // debug_output on a deferred tick.
    const target = initStage("platform-detect", () => detectTarget()) as TargetKind;

    const plan = planForTarget(target);
    log(`Running Script on ${plan.label}`);
    // Reported BEFORE anything is installed, so the host learns which branch was
    // selected even if install() then kills the target (friTap#65).
    send({ contentType: "platform_report", platform: plan.label, target: target, probe: probe, abi: AGENT_ABI_VERSION });

    if (probe) {
        log('--probe: platform reported, no hooks installed');
        return;
    }

    plan.install();

    // Deferred debug dump: same detail as before, but on a later tick and fully
    // contained, so an ObjC call into a not-yet-initialised Foundation can neither
    // block script.load() nor abort startup.
    if (debug_output) {
        setTimeout(() => {
            try {
                devlog(`[Platform Detection] ${JSON.stringify(getDetailedPlatformInfo(), null, 2)}`);
            } catch (e) {
                devlog(`[Platform Detection] detailed info unavailable: ${e}`);
            }
        }, 0);
    }
}

initStage("platform-load", () => load_os_specific_agent(), /* fatal */ false);

// Optional generic memory-region key scan (PUBLIC engine, agent/shared/scan/).
// Runs only when the host passed --scan-keys-region (carried via
// config_batch.extensions) and/or a private scan provider registered. Async and
// fire-and-forget so it never blocks hook installation; emission is gated by
// keylog_enabled inside sendKeyMaterial (so the host must also pass -k).
// Skipped entirely under --probe: scanning the target's memory regions is exactly
// the kind of expensive target interaction a dry-run diagnostic must avoid.
initStage("region-scan",
    () => {
        if (!probe) {
            maybeRunRegionScan(config_extensions).catch((e) => log(`[scan] failed: ${e}`));
        }
    }, /* fatal */ false);

// Best-effort graceful detach. Python calls this from
// ssl_logger_core.detach_with_timeout() BEFORE script.unload() /
// session.detach() so the JS thread isn't held draining in-flight
// Interceptor callbacks — which is what was making detach hang for
// >5s on processes with many hot hooks (e.g. Chrome with the QUIC
// capture stack installed across libmainlinecronet + libmonochrome:
// dozens of stream-level hooks, each potentially firing thousands of
// times per second under traffic).
//
// Interceptor.detachAll() is synchronous: it pulls all attached
// probes out of the trampoline table at once. New invocations of
// those functions immediately bypass our handlers from this point
// on, so the queue of pending callbacks stops growing. Frida then
// drains whatever is already mid-flight (bounded by single-handler
// runtime, NOT by the rate at which the target keeps calling the
// hooked function), and returns. The Python timeout (30s by default)
// is the safety net for any handler still in flight.
//
// Wrapped in try/catch so a probe-table issue can't make detach
// itself throw — we'd rather log and let the host continue tearing
// down. The Python side is also defensive about missing/old RPCs
// (older standalone-agent integrations won't have this export, and
// that's fine — detach just falls back to the slower path).
// IMPORTANT — RPC naming convention: Frida 17+ maps Python's snake_case
// (`script.exports.graceful_detach()`) to JS-side camelCase
// (`rpc.exports.gracefulDetach`). The Python side MUST call `graceful_detach`,
// and the JS side MUST declare `gracefulDetach`. Don't write the snake_case
// name in JS — Frida won't find it and you'll see
// "unable to find method 'gracefulDetach'" at detach time.
//
// The rpc.exports assignment itself now lives near the TOP of this module (right
// after init_addresses) so it survives a startup failure — see the comment there.

hookBreadcrumb("agent-init: complete");