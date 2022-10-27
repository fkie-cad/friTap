import { load_android_hooking_agent } from "./android/android_agent";
import { load_ios_hooking_agent } from "./ios/ios_agent";
import { load_macos_hooking_agent } from "./macos/macos_agent";
import { load_linux_hooking_agent } from "./linux/linux_agent";
import { load_windows_hooking_agent } from "./windows/windows_agent";
import { isWindows, isLinux, isAndroid, isiOS, isMacOS } from "./util/process_infos";
import { log } from "./util/log"

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

    sockets?:{
        getpeername?: IAddress,
        getsockname?: IAddress,
        ntohs?: IAddress,
        ntohl?: IAddress
    }
}

//@ts-ignore
export let offsets: IOffsets = "{OFFSETS}";

/*

create the TLS library for your first prototpye as a lib in ./ssl_lib and than extend this class for the OS where this new lib was tested.

Further keep in mind, that properties of an class only visible inside the Interceptor-onEnter/onLeave scope when they are static. 
As an alternative you could make a local variable inside the calling functions which holds an reference to the class property.

*/

export function getOffsets(){
    return offsets;
}


function load_os_specific_agent() {
    if(isWindows()){
        load_windows_hooking_agent()
    }else if(isAndroid()){
        load_android_hooking_agent()
    }else if(isLinux()){
        load_linux_hooking_agent()
    }else if(isiOS()){
        load_ios_hooking_agent()
    }else if(isMacOS()){
        load_macos_hooking_agent()
    }else{
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }
}


load_os_specific_agent()













