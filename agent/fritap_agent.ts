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
import { setSelectedProtocol } from "./shared/shared_structures.js";
import { initializePipeline } from "./shared/pipeline_utils.js";

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

    sockets?:{
        getpeername?: IAddress,
        getsockname?: IAddress,
        ntohs?: IAddress,
        ntohl?: IAddress
    }
}

//@ts-ignore
export let offsets: IOffsets = "{OFFSETS}";
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
//@ts-ignore
export let selected_protocol: string = "tls";
//@ts-ignore
export let patterns: string = "{PATTERNS}";
//@ts-ignore
export let scan_results: string = "{SCAN_RESULTS}";
//@ts-ignore
export let library_scan_enabled: boolean = false;

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
offsets = config_batch.offsets ?? offsets;
patterns = config_batch.patterns ?? patterns;
enable_socket_tracing = config_batch.socket_tracing ?? enable_socket_tracing;
enable_default_fd = config_batch.defaultFD ?? enable_default_fd;
experimental = config_batch.experimental ?? experimental;
selected_protocol = config_batch.protocol_select ?? selected_protocol;
setSelectedProtocol(selected_protocol);
install_lsass_hook = config_batch.install_lsass_hook ?? install_lsass_hook;
use_modern = config_batch.use_modern ?? use_modern;
scan_results = config_batch.library_scan ?? scan_results;
library_scan_enabled = config_batch.library_scan_enabled ?? library_scan_enabled;

// "anti" handshake must be LAST in the startup sequence to prevent deadlock
anti_root = recvHandshake("anti", anti_root, "antiroot");

// Initialize the hooking pipeline centrally so it is ready before any library constructor runs.
// Existing per-platform OpenSSL_BoringSSL.initializePipeline() calls become no-ops (idempotent guard).
initializePipeline(isPatternReplaced() ? JSON.parse(patterns) : undefined, experimental);



/*

create the TLS library for your first prototpye as a lib in ./ssl_lib and than extend this class for the OS where this new lib was tested.

Further keep in mind, that properties of an class only visible inside the Interceptor-onEnter/onLeave scope when they are static. 
As an alternative you could make a local variable inside the calling functions which holds an reference to the class property.

*/


export function getOffsets(){
    return offsets;
}

// Function to check if the patterns have been replaced
export function isPatternReplaced(): boolean {
    if(patterns === null){
        return false;
    }
    // The default placeholder is quite short, so if the length exceeds a certain threshold, we assume it's replaced
    return patterns.length > 10;
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

load_os_specific_agent()











