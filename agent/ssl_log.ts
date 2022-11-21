import { load_android_hooking_agent } from "./android/android_agent.js";
import { load_ios_hooking_agent } from "./ios/ios_agent.js";
import { load_macos_hooking_agent } from "./macos/macos_agent.js";
import { load_linux_hooking_agent } from "./linux/linux_agent.js";
import { load_windows_hooking_agent } from "./windows/windows_agent.js";
import { isWindows, isLinux, isAndroid, isiOS, isMacOS } from "./util/process_infos.js";
import { log } from "./util/log.js"

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
    sspi?:{
        EncryptMessage: IAddress,
        DecryptMessage: IAddress
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
//@ts-ignore
export let experimental: boolean = "{EXPERIMENTAL}"
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
        log('Running Script on Windows')
        load_windows_hooking_agent()
    }else if(isAndroid()){
        log('Running Script on Android')
        load_android_hooking_agent()
    }else if(isLinux()){
        log('Running Script on Linux')
        load_linux_hooking_agent()
    }else if(isiOS()){
        log('Running Script on iOS')
        load_ios_hooking_agent()
    }else if(isMacOS()){
        log('Running Script on MacOS')
        load_macos_hooking_agent()
    }else{
        log('Running Script on unknown plattform')
        log("Error: not supported plattform!\nIf you want to have support for this plattform please make an issue at our github page.")
    }

}

load_os_specific_agent()












