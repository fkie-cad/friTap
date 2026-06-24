import { load_android_hooking_agent } from "./platforms/android.js";
import { load_ios_hooking_agent } from "./platforms/ios.js";
import { load_macos_hooking_agent } from "./platforms/macos.js";
import { load_linux_hooking_agent } from "./platforms/linux.js";
import { load_windows_hooking_agent, load_windows_lsass_agent } from "./platforms/windows.js";
import { load_wine_hooking_agent } from "./platforms/wine.js";
import { isWindows, isLinux, isWine, isAndroid, isiOS, isMacOS, getDetailedPlatformInfo } from "./util/process_infos.js";
import { anti_root_execute } from "./util/anti_root.js";
import { socket_trace_execute } from "./misc/socket_tracer.js"
import { devlog, log } from "./util/log.js";
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
    offsets, pcap_enabled, keylog_enabled, _isShuttingDown, ohttp_enabled, selected_protocol, config_extensions,
    setOffsets, setPcapEnabled, setKeylogEnabled, setIsShuttingDown, setOhttpEnabled, setConfigExtensions,
} from "./shared/shared_structures.js";
export { offsets, pcap_enabled, keylog_enabled, _isShuttingDown, ohttp_enabled, selected_protocol, config_extensions };
import { maybeRunRegionScan } from "./shared/scan/scan_engine.js";

// global address which stores the addresses of the hooked modules which aren't loaded via the dynamic loader
(globalThis as any).init_addresses = {};

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

// Telegram (Secret-Chat E2E + tgnet/mtproto transport) capture. Gated under
// `--protocol telegram`. When true the android hook table installs the Telegram
// Secret-Chat Java hooks (and, via registry.protocolMatches, the tgnet/mtproto
// transport hooks). Selection is keyed off `selected_protocol`/`keylog_enabled`.
//@ts-ignore
export let telegram_enabled: boolean = false;

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
const config_batch = recvHandshake<Record<string, any>>("config_batch", {});
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
quic_egress_headers_layer = config_batch.quic_egress_headers_layer ?? quic_egress_headers_layer;
debug_output = config_batch.debug_output ?? debug_output;
telegram_enabled = config_batch.telegram_enabled ?? telegram_enabled;
// Generic feature-config passthrough (e.g. { scan_region } for the public
// memory-scan engine). Protocol-agnostic: the public core never inspects a
// private sub-key; private units read their own keys from config_extensions.
setConfigExtensions(config_batch.extensions ?? {});

// "anti" handshake must be LAST in the startup sequence to prevent deadlock
anti_root = recvHandshake("anti", anti_root, "antiroot");

// Initialize the hooking pipeline centrally so it is ready before any library constructor runs.
initializePipeline(parsedPatterns ?? undefined, experimental);



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


function load_os_specific_agent() {
    // Log detailed platform information for debugging
     const platformInfo = getDetailedPlatformInfo();
    // devlog(`[Platform Detection] Detailed info: ${JSON.stringify(platformInfo, null, 2)}`); // uncomment for debugging
    
    if(isWindows()){
        log('Running Script on Windows')
        if(install_lsass_hook){
            load_windows_lsass_agent();
        }else{
            log('Skipping LSASS hooking as per configuration');
        }
        load_windows_hooking_agent()
    }else if(isAndroid()){
        log('Running Script on Android')
        if(anti_root){
            log('Applying anti root checks');
            anti_root_execute();
        }
        if(enable_socket_tracing){
            socket_trace_execute();
        }
        load_android_hooking_agent()
    }else if(isWine()){
        // Wine must be checked BEFORE isLinux() since Wine processes are Linux processes
        if(experimental){
            log('Running Script on Wine (experimental)')
            if(enable_socket_tracing){
                socket_trace_execute();
            }
            load_wine_hooking_agent()
        }else{
            log('[!] Wine process detected. Wine support is experimental and requires the --experimental flag.')
            log('[!] Falling back to standard Linux agent.')
            if(enable_socket_tracing){
                socket_trace_execute();
            }
            load_linux_hooking_agent()
        }
    }else if(isLinux()){
        if(enable_socket_tracing){
            socket_trace_execute();
        }
        log('Running Script on Linux')
        load_linux_hooking_agent()
    }else if(isiOS()){
        if(enable_socket_tracing){
            socket_trace_execute();
        }
        log('Running Script on iOS')
        // devlog(`[iOS Detection] Architecture: ${Process.arch}, Platform: ${Process.platform}`); // uncomment for debugging
        load_ios_hooking_agent()
    }else if(isMacOS()){
        if(enable_socket_tracing){
            socket_trace_execute();
        }
        log('Running Script on MacOS')
        // devlog(`[macOS Detection] Architecture: ${Process.arch}, Platform: ${Process.platform}`); // uncomment for debugging
        load_macos_hooking_agent()
    }else{
        log('Running Script on unknown platform')
        log(`Platform: ${Process.platform}, Architecture: ${Process.arch}`)
        log("Error: not supported platform!\nIf you want to have support for this platform please make an issue at our github page.")
        devlog(`[Unknown Platform] Full detection info: ${JSON.stringify(platformInfo, null, 2)}`);
    }

}

load_os_specific_agent();

// Optional generic memory-region key scan (PUBLIC engine, agent/shared/scan/).
// Runs only when the host passed --scan-keys-region (carried via
// config_batch.extensions) and/or a private scan provider registered. Async and
// fire-and-forget so it never blocks hook installation; emission is gated by
// keylog_enabled inside sendKeyMaterial (so the host must also pass -k).
maybeRunRegionScan(config_extensions).catch((e) => log(`[scan] failed: ${e}`));

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
        // Set the shutdown flag BEFORE Interceptor.detachAll so any callback
        // already mid-execution (or queued on the JS message loop) sees the
        // flag at sendDatalog/emit and short-circuits. Order matters: if we
        // detached first and then set the flag, callbacks already queued
        // between the two statements would still pay the full IPC cost.
        setIsShuttingDown(true);
        try {
            Interceptor.detachAll();
        } catch (e) {
            try {
                log(`[gracefulDetach] Interceptor.detachAll threw: ${e}`);
            } catch (_e2) { /* host already gone */ }
        }
    }
};