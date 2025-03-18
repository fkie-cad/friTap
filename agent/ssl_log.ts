import { load_android_hooking_agent } from "./android/android_agent.js";
import { load_ios_hooking_agent } from "./ios/ios_agent.js";
import { load_macos_hooking_agent } from "./macos/macos_agent.js";
import { load_linux_hooking_agent } from "./linux/linux_agent.js";
import { load_windows_hooking_agent } from "./windows/windows_agent.js";
import { isWindows, isLinux, isAndroid, isiOS, isMacOS } from "./util/process_infos.js";
import { anti_root_execute } from "./util/anti_root.js";
import { socket_trace_execute } from "./misc/socket_tracer.js"
import { devlog, log } from "./util/log.js";

// global address which stores the addresses of the hooked modules which aren't loaded via the dynamic loader
(global as any).init_addresses = {};
(global as any).global_counter = 0;

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
export let patterns: string = "{PATTERNS}";

/* 
Our way to get the JSON strings into the loaded frida script 
*/
send("offset_hooking")
const enable_offset_based_hooking_state = recv('offset_hooking', value => {
    if (value.payload !== null && value.payload !== undefined) {
        offsets = value.payload;
    }
});
enable_offset_based_hooking_state.wait();

send("pattern_hooking")
const enable_pattern_based_hooking_state = recv('pattern_hooking', value => {
    if (value.payload !== null && value.payload !== undefined) {
        patterns = value.payload;
    }
});
enable_pattern_based_hooking_state.wait();


/*
This way we are providing boolean values from the commandline directly to our frida script
*/
send("socket_tracing")
const enable_socket_tracing_state = recv('socket_tracing', value => {
    enable_socket_tracing = value.payload;
});
enable_socket_tracing_state.wait();


send("defaultFD")
const enable_default_fd_state = recv('defaultFD', value => {
    enable_default_fd = value.payload;
});
enable_default_fd_state.wait();


send("experimental")
const exp_recv_state = recv('experimental', value => {
    experimental = value.payload;
});
exp_recv_state.wait();

send("anti")
const antiroot_recv_state = recv('antiroot', value => {
    anti_root = value.payload;
});
antiroot_recv_state.wait();/* */



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
    if(isWindows()){
        log('Running Script on Windows')
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
        load_ios_hooking_agent()
    }else if(isMacOS()){
        if(enable_socket_tracing){
            socket_trace_execute();
        }
        log('Running Script on MacOS')
        load_macos_hooking_agent()
    }else{
        log('Running Script on unknown plattform')
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }

}

load_os_specific_agent()












