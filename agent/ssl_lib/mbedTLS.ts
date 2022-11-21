import { readAddresses, getPortsAndAddresses, getBaseAddress} from "../shared/shared_functions.js"
import { offsets } from "../ssl_log.js";
import { log } from "../util/log.js"

/**
 * 
 * ToDO
 *  - Implement interface so that the structs can be used
 *  - implement library for Linux and Android at least
 *  - Implement key extraction
 */

interface mbedtls_ssl_context {
    //TODO: Implement all structs
    conf: NativePointer,
    state: number,
    renego_status: number,
    renego_records_seen: number,
    major_ver: number,
    minor_ver: number,
    badmac_seen: number,
    f_send: NativePointer,
    f_recv: NativePointer,
    f_recv_timeout: NativePointer,
    p_bio: NativePointer,
    session_in: NativePointer,
    session_out: NativePointer,
    session: {
        start: NativePointer, //FIXME: Rewrite with real struct
        ciphersuite: number,
        compression: number,
        id_len: number,
        id: string, //len = 32
        master: string //len = 48
        peer_cert: NativePointer,
        verify_result: number,
        ticket: NativePointer,
        ticket_len: number,
        ticket_lifetime: number,
        mfl_code: string, // Char
        trunc_hmac: number,
        encrypt_then_mac: number
    },
    session_negotiate: NativePointer,
    handshake: NativePointer,
    transform_in: NativePointer,
    transform_out: NativePointer,
    transform: NativePointer,
    transform_negotiate: NativePointer,
    p_timer: NativePointer,
    f_set_timer: NativePointer,
    f_get_timer: NativePointer,
    in_buf: NativePointer,
    in_ctr: NativePointer,
    in_hdr: NativePointer,
    in_len: NativePointer,
    in_iv: NativePointer,
    in_msg: NativePointer,
    in_offt: NativePointer,
    in_msgtype: number,
    in_msglen: number,
    in_left: number,
    in_epoch: number,
    next_record_offset: number,
    in_window_top: number,
    in_window: number,
    in_hslen: number,
    nb_zero: number,
    keep_current_message: number,
    disable_datagram_packing: number,
    out_buf: NativePointer,
    out_ctr: NativePointer,
    out_hdr: NativePointer,
    out_len: NativePointer,
    out_iv: NativePointer,
    out_msg: NativePointer,
    out_msgtype: number,
    out_msglen: number,
    out_left: number,
    cur_out_ctr: string, //Length = 8
    mtu: number,
    split_done: string, //Character, length = 1
    client_auth: number,
    hostname: NativePointer,
    alpn_chosen: NativePointer,
    cli_id: NativePointer,
    cli_id_len: number,
    secure_renegotiation: number,
    verify_data_len: number,
    own_verify_data: string, //len = MBEDTLS_SSL_VERIFY_DATA_MAX_LEN
    peer_verify_data: string //len = MBEDTLS_SSL_VERIFY_DATA_MAX_LEN
}

export class mbed_TLS {



    // global variables
    library_method_mapping: { [key: string]: Array<String> } = {};
    addresses: { [key: string]: NativePointer };



    constructor(public moduleName: String, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<String> }) {
        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        } else {
            this.library_method_mapping[`*${moduleName}*`] = ["mbedtls_ssl_read", "mbedtls_ssl_write"];
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
        }

        this.addresses = readAddresses(this.library_method_mapping);

        // @ts-ignore
        if(offsets != "{OFFSETS}" && offsets.mbedtls != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            }

            
            for (const method of Object.keys(offsets.mbedtls)){
                //@ts-ignore
                this.addresses[`${method}`] = offsets.mbedtls[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.mbedtls[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.mbedtls[`${method}`].address));
            }


        }



    }

    static parse_mbedtls_ssl_context_struct(sslcontext: NativePointer) {
        return {
            conf: sslcontext.readPointer(),
            state: sslcontext.add(Process.pointerSize).readS32(),
            renego_status: sslcontext.add(Process.pointerSize + 4).readS32(),
            renego_records_seen: sslcontext.add(Process.pointerSize + 4 + 4).readS32(),
            major_ver: sslcontext.add(Process.pointerSize + 4 + 4 + 4).readS32(),
            minor_ver: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4).readS32(),
            badmac_seen: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4).readU32(),
            f_send: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4).readPointer(),
            f_recv: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + Process.pointerSize).readPointer(),
            f_recv_timeout: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 2 * Process.pointerSize).readPointer(),
            p_bio: sslcontext.add(Process.platform == 'windows' ? 48 : 56).readPointer()
            ,
            session_in: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 4 * Process.pointerSize).readPointer(),
            session_out: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 5 * Process.pointerSize).readPointer(),
            session: {
                start: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().readPointer(),
                ciphersuite: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8).readS32(),
                compression: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4).readS32(),
                id_len: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32(),
                id: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4 + 4).readByteArray(sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32())
            }
        }
    }

    static getSocketDescriptor(sslcontext: NativePointer) {
        var ssl_context = mbed_TLS.parse_mbedtls_ssl_context_struct(sslcontext)
        return ssl_context.p_bio.readS32()
    }


    static getSessionId(sslcontext: NativePointer) {
        var ssl_context = mbed_TLS.parse_mbedtls_ssl_context_struct(sslcontext)

        var session_id = ''
        for (var byteCounter = 0; byteCounter < ssl_context.session.id_len; byteCounter++) {

            session_id = `${session_id}${ssl_context.session.id?.unwrap().add(byteCounter).readU8().toString(16).toUpperCase()}`
        }

        return session_id
    }


    install_plaintext_read_hook() {
        var lib_addesses = this.addresses;
        //https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
        Interceptor.attach(this.addresses["mbedtls_ssl_read"], {
            onEnter: function (args) {
                this.buffer = args[1];
                this.len = args[2];
                this.sslContext = args[0];

                var message = getPortsAndAddresses(mbed_TLS.getSocketDescriptor(args[0]) as number, true, lib_addesses)
                message["ssl_session_id"] = mbed_TLS.getSessionId(args[0])
                message["function"] = "mbedtls_ssl_read"
                this.message = message
            },
            onLeave: function (retval: any) {
                retval |= 0 // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return
                }

                var data = this.buffer.readByteArray(retval);
                this.message["contentType"] = "datalog"
                send(this.message, data)


            }

        });

    }


    install_plaintext_write_hook() {
        var lib_addesses = this.addresses;
        //https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
        Interceptor.attach(this.addresses["mbedtls_ssl_write"], {

            onEnter: function (args) {
                var buffer = args[1];
                var len: any = args[2];
                len |= 0 // Cast retval to 32-bit integer.
                if (len <= 0) {
                    return
                }
                var data = buffer.readByteArray(len);
                var message = getPortsAndAddresses(mbed_TLS.getSocketDescriptor(args[0]) as number, false, lib_addesses)
                message["ssl_session_id"] = mbed_TLS.getSessionId(args[0])
                message["function"] = "mbedtls_ssl_write"
                message["contentType"] = "datalog"
                send(message, data)
            }
        });

    }


    install_tls_keys_callback_hook() {
        // TBD
    }


}

