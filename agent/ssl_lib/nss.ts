import { readAddresses, getBaseAddress, dumpMemory } from "../shared/shared_functions.js";
import { pointerSize, AF_INET, AF_INET6 } from "../shared/shared_structures.js";
import { log, devlog } from "../util/log.js";
import { offsets,enable_default_fd } from "../ssl_log.js";


/**
 *  Current Todo:
 *  - Make code more readable
 *  - Fix SessionID-Problems
 *  - Fix issue that the hooks wont get applied when spawning thunderbird on linux --> this is related how frida is spawning thunderbird ...
 *  - Fix PR_Read and PR_Write issue when the decrypted content is send via Pipes
 * 
 * 
 */


/*
https://firefox-source-docs.mozilla.org/nspr/reference/prnetaddr.html

#define PR_AF_INET 2
#define PR_AF_LOCAL 1
#define PR_INADDR_ANY (unsigned long)0x00000000
#define PR_INADDR_LOOPBACK 0x7f000001
#define PR_INADDR_BROADCAST (unsigned long)0xffffffff

#else 

#define PR_AF_INET AF_INET
#define PR_AF_LOCAL AF_UNIX
#define PR_INADDR_ANY INADDR_ANY
#define PR_INADDR_LOOPBACK INADDR_LOOPBACK
#define PR_INADDR_BROADCAST INADDR_BROADCAST

#define PR_AF_UNSPEC 0

*/

/******  NSS data structures and its parsing *********/

// https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
export interface sslSocketStr {
    "crSpec": NativePointer;
    "prSpec": NativePointer,
    "cwSpec": NativePointer,
    "pwSpec": NativePointer,
    "peerRequestedKeyUpdate": number,
    "keyUpdateDeferred": number,
    "deferredKeyUpdateRequest": number,
    "clientCertRequested": number,
    "clientCertificate": NativePointer,
    "clientPrivateKey": NativePointer,
    "clientCertChain": NativePointer,
    "sendEmptyCert": number,
    "policy": number,
    "peerCertArena": NativePointer,
    "peerCertChain": NativePointer,
    "ca_list": NativePointer,
    "hs": { // https://github.com/nss-dev/nss/blob/c277877bd8c01e107b097bbd57df094b34e37aab/lib/ssl/sslimpl.h#L615
        "server_random": NativePointer,
        "client_random": NativePointer,
        "client_inner_random": NativePointer,
        "ws": number,
        "hashType": number,
        "messages": { // sslBuffer
            "data": NativePointer,
            "len": number,
            "space": number,
            "fixed": number,

        },
        "echInnerMessages": { // sslBuffer
            "data": NativePointer,
            "len": number,
            "space": number,
            "fixed": number,

        },
        "md5": NativePointer,
        "sha": NativePointer,
        "shaEchInner": NativePointer,
        "shaPostHandshake": NativePointer,
        "signatureScheme": number,
        "kea_def": NativePointer,
        "cipher_suite": number,
        "suite_def": NativePointer,
        "msg_body": { // sslBuffer
            "data": NativePointer,
            "len": number,
            "space": number,
            "fixed": number,

        },
        "header_bytes": number,
        "msg_type": number,
        "msg_len": number,
        "isResuming": number,
        "sendingSCSV": number,
        "receivedNewSessionTicket": number,
        "newSessionTicket": NativePointer,
        "finishedBytes": number,
        "finishedMsgs": NativePointer,
        "authCertificatePending": number,
        "restartTarget": number,
        "canFalseStart": number,
        "preliminaryInfo": number,
        "remoteExtensions": {
            "next": NativePointer,
            "prev": NativePointer,
        },
        "echOuterExtensions": {
            "next": NativePointer,
            "prev": NativePointer,
        },
        "sendMessageSeq": number,
        "lastMessageFlight": {
            "next": NativePointer,
            "prev": NativePointer,
        },
        "maxMessageSent": number,
        "recvMessageSeq": number,
        "recvdFragments": { // sslBuffer
            "data": NativePointer,
            "len": number,
            "space": number,
            "fixed": number,

        },
        "recvdHighWater": number,
        "cookie": {
            "type": Int64,
            "data": NativePointer,
            "len": number,
        },
        "times_array": number,
        "rtTimer": NativePointer,
        "ackTimer": NativePointer,
        "hdTimer": NativePointer,
        "rtRetries": number,
        "srvVirtName": {
            "type": Int64,
            "data": NativePointer,
            "len": number,
        },
        "currentSecret": NativePointer,
        "resumptionMasterSecret": NativePointer,
        "dheSecret": NativePointer,
        "clientEarlyTrafficSecret": NativePointer,
        "clientHsTrafficSecret": NativePointer,
        "serverHsTrafficSecret": NativePointer,
        "clientTrafficSecret": NativePointer,
        "serverTrafficSecret": NativePointer,
        "earlyExporterSecret": NativePointer,
        "exporterSecret": NativePointer

    }
}



const {
    readU32,
    readU64,
    readPointer,
    writeU32,
    writeU64,
    writePointer
} = NativePointer.prototype;


// https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/ssltyp#1026722
export enum SECStatus { // enum SECStatus
    "SECWouldBlock" = -2,
    "SECFailure" = -1,
    "SECSuccess" = 0
};

export enum PRDescType {
    PR_DESC_FILE = 1,
    PR_DESC_SOCKET_TCP = 2,
    PR_DESC_SOCKET_UDP = 3,
    PR_DESC_LAYERED = 4,
    PR_DESC_PIPE = 5
} PRDescType;

export class NSS {

    // global definitions
    static doTLS13_RTT0 = -1;
    static SSL3_RANDOM_LENGTH = 32;


    // global variables
    library_method_mapping: { [key: string]: Array<string> } = {};
    addresses: { [libraryName: string]: { [functionName: string]: NativePointer } };
    module_name: string;

    static SSL_SESSION_get_id: any;
    static getsockname: any;
    static getpeername: any;
    static getDescType: any;
    static PR_GetNameForIdentity: any;
    static get_SSL_Callback: any;
    static PK11_ExtractKeyValue: any;
    static PK11_GetKeyData: any;
    static SS3_VERSIONS_OFFSET: number; // an offset in the SS3.HS strucht which changes on different NSS versions
    static SS3_VERSIONS_CR_OFFSET: number;


    constructor(public moduleName: string, public socket_library: String, public passed_library_method_mapping?: { [key: string]: Array<string> }) {

        if (typeof passed_library_method_mapping !== 'undefined') {
            this.library_method_mapping = passed_library_method_mapping;
        } else {
            this.library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"]
            this.library_method_mapping[`*libnss.*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"]
            this.library_method_mapping["*libssl*.so"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"]
            this.library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"]
        }

        this.addresses = readAddresses(moduleName,this.library_method_mapping);
        this.module_name = moduleName;

        // @ts-ignore
         if(offsets != "{OFFSETS}" && offsets.nss != null){

            if(offsets.sockets != null){
                const socketBaseAddress = getBaseAddress(socket_library)
                for(const method of Object.keys(offsets.sockets)){
                     //@ts-ignore
                    this.addresses[this.moduleName][`${method}`] = offsets.sockets[`${method}`].absolute || socketBaseAddress == null ? ptr(offsets.sockets[`${method}`].address) : socketBaseAddress.add(ptr(offsets.sockets[`${method}`].address));
                }
            }

            const libraryBaseAddress = getBaseAddress(moduleName)
            
            if(libraryBaseAddress == null){
                log("Unable to find library base address! Given address values will be interpreted as absolute ones!")
            }

            
            for (const method of Object.keys(offsets.nss)){
                //@ts-ignore
                this.addresses[this.moduleName][`${method}`] = offsets.nss[`${method}`].absolute || libraryBaseAddress == null ? ptr(offsets.nss[`${method}`].address) : libraryBaseAddress.add(ptr(offsets.nss[`${method}`].address));
            }


        }

        if(!Java.available){
            NSS.SSL_SESSION_get_id = new NativeFunction(this.addresses[this.moduleName]["SSL_GetSessionID"], "pointer", ["pointer"]);
        }

        NSS.getsockname = new NativeFunction(this.addresses[this.moduleName]["PR_GetSockName"], "int", ["pointer", "pointer"]);
        NSS.getpeername = new NativeFunction(this.addresses[this.moduleName]["PR_GetPeerName"], "int", ["pointer", "pointer"]);

       


    }

    static get_NSS_version(): number{
        var getNSSversion = null;
        var version_string = "0";
        if(!Java.available){
            getNSSversion = new NativeFunction(Module.findExportByName(null,"NSSSSL_GetVersion"), "pointer", []);
        }else{
            // we are on Android
            getNSSversion = new NativeFunction(Module.findExportByName("libnss3.so","NSSSSL_GetVersion"), "pointer", []);
        }
        if(!getNSSversion.isNull()){
            var ptr_version_string = getNSSversion();
            if(!ptr_version_string.isNull()){
                version_string = ptr_version_string.readCString();
            }
        }

        // Extract only the numeric part (e.g., "3.108 BETA" → "3.108")
        var match = version_string.match(/^(\d+)\.(\d+)/);
        if (!match) {
            return 0; // Return 0 if the version string is not valid
        }

        // Convert to a numeric version: major * 1000 + minor (e.g., 3.108 → 3108)
        var major = parseInt(match[1], 10);
        var minor = parseInt(match[2], 10);

        return major * 1000 + minor;
    }

    /* PARSING functions */

    static parse_struct_SECItem(secitem: NativePointer) {
        /*
         * struct SECItemStr {
         * SECItemType type;
         * unsigned char *data;
         * unsigned int len;
         * }; --> size = 20
        */
        return {
            "type": secitem.readU64(),
            "data": secitem.add(pointerSize).readPointer(),
            "len": secitem.add(pointerSize * 2).readU32()
        }
    }


    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L971
    static parse_struct_sslSocketStr(sslSocketFD: NativePointer) {
        return {
            "fd": sslSocketFD.readPointer(),
            "version": sslSocketFD.add(160),
            "handshakeCallback": sslSocketFD.add(464),
            "secretCallback": sslSocketFD.add(568),
            "ssl3": sslSocketFD.add(1432)
        }
    }

    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
    static parse_struct_ssl3Str(ssl3_struct: NativePointer): sslSocketStr {
        NSS.SS3_VERSIONS_OFFSET = 0; // defaulting offset to 0
        NSS.SS3_VERSIONS_CR_OFFSET = 0;
        var nss_version = NSS.get_NSS_version();
        //console.log("nss_version:"+nss_version);
        if(nss_version >= 3107){
            devlog("setting offsets for NSS version "+nss_version);
            NSS.SS3_VERSIONS_OFFSET = 96; // offset currentSecret
            NSS.SS3_VERSIONS_CR_OFFSET = 8; // offset for CLIENT_RANDOM
        }

        // version 3.108 beta
        // https://github.com/nss-dev/nss/blob/c277877bd8c01e107b097bbd57df094b34e37aab/lib/ssl/sslimpl.h#L615
        //console.log("[!] inspecing SSL3HandshakeStateStr at: "+ssl3_struct.add(pointerSize * 10 + 24));
        //dumpMemory(ssl3_struct.add(pointerSize * 10 + 24+NSS.SS3_VERSIONS_CR_OFFSET),820);
        //                                           80+ 24 + 8 = 112
        //                         pointerSize * 33 + 440 + 0
        //                                         264+ 440 = 704
        // 432 first ptr
        /*
        struct ssl3StateStr {
    
        ssl3CipherSpec *crSpec; // current read spec. 
        ssl3CipherSpec *prSpec; // pending read spec. 
        ssl3CipherSpec *cwSpec; // current write spec. 
        ssl3CipherSpec *pwSpec; // pending write spec. 
        
        PRBool peerRequestedKeyUpdate;                     --> enum type
        
        PRBool keyUpdateDeferred;                          --> enum type
        tls13KeyUpdateRequest deferredKeyUpdateRequest;    --> enum type
       
        PRBool clientCertRequested;                        --> enum type
    
        CERTCertificate *clientCertificate;   
        SECKEYPrivateKey *clientPrivateKey;   
        CERTCertificateList *clientCertChain; 
        PRBool sendEmptyCert;                 
    
        PRUint8 policy;
        PLArenaPool *peerCertArena;
        
        void *peerCertChain;
        
        CERTDistNames *ca_list;
        
        SSL3HandshakeState hs;
        ...
        }
        */
        return {
            "crSpec": ssl3_struct.readPointer(),
            "prSpec": ssl3_struct.add(pointerSize).readPointer(),
            "cwSpec": ssl3_struct.add(pointerSize * 2).readPointer(),
            "pwSpec": ssl3_struct.add(pointerSize * 3).readPointer(),
            "peerRequestedKeyUpdate": ssl3_struct.add(pointerSize * 4).readU32(),
            "keyUpdateDeferred": ssl3_struct.add(pointerSize * 4 + 4).readU32(),
            "deferredKeyUpdateRequest": ssl3_struct.add(pointerSize * 4 + 8).readU32(),
            "clientCertRequested": ssl3_struct.add(pointerSize * 4 + 12).readU32(),
            "clientCertificate": ssl3_struct.add(pointerSize * 4 + 16).readPointer(),
            "clientPrivateKey": ssl3_struct.add(pointerSize * 5 + 16).readPointer(),
            "clientCertChain": ssl3_struct.add(pointerSize * 6 + 16).readPointer(),
            "sendEmptyCert": ssl3_struct.add(pointerSize * 7 + 16).readU32(),
            "policy": ssl3_struct.add(pointerSize * 7 + 20).readU32(),
            "peerCertArena": ssl3_struct.add(pointerSize * 7 + 24).readPointer(),
            "peerCertChain": ssl3_struct.add(pointerSize * 8 + 24).readPointer(),
            "ca_list": ssl3_struct.add(pointerSize * 9 + 24).readPointer(),
            "hs": { // https://github.com/nss-dev/nss/blob/c277877bd8c01e107b097bbd57df094b34e37aab/lib/ssl/sslimpl.h#L615
                "server_random": ssl3_struct.add(pointerSize * 10 + 24+ NSS.SS3_VERSIONS_CR_OFFSET),  //SSL3Random --> typedef PRUint8 SSL3Random[SSL3_RANDOM_LENGTH];
                "client_random": ssl3_struct.add(pointerSize * 10 + 56+ NSS.SS3_VERSIONS_CR_OFFSET),
                "client_inner_random": ssl3_struct.add(pointerSize * 10 + 88+ NSS.SS3_VERSIONS_CR_OFFSET),
                "ws": ssl3_struct.add(pointerSize * 10 + 120+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "hashType": ssl3_struct.add(pointerSize * 10 + 124+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "messages": { // sslBuffer
                    "data": ssl3_struct.add(pointerSize * 10 + 128+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 11 + 128+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "space": ssl3_struct.add(pointerSize * 11 + 132+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "fixed": ssl3_struct.add(pointerSize * 11 + 136+ NSS.SS3_VERSIONS_OFFSET).readU32(),

                },
                "echInnerMessages": { // sslBuffer
                    "data": ssl3_struct.add(pointerSize * 11 + 140+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 12 + 140+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "space": ssl3_struct.add(pointerSize * 12 + 144+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "fixed": ssl3_struct.add(pointerSize * 12 + 148+ NSS.SS3_VERSIONS_OFFSET).readU32(),

                },
                "md5": ssl3_struct.add(pointerSize * 12 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "sha": ssl3_struct.add(pointerSize * 13 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "shaEchInner": ssl3_struct.add(pointerSize * 14 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "shaPostHandshake": ssl3_struct.add(pointerSize * 15 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "signatureScheme": ssl3_struct.add(pointerSize * 16 + 152+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "kea_def": ssl3_struct.add(pointerSize * 16 + 156+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "cipher_suite": ssl3_struct.add(pointerSize * 17 + 156+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "suite_def": ssl3_struct.add(pointerSize * 17 + 160+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "msg_body": { // sslBuffer
                    "data": ssl3_struct.add(pointerSize * 18 + 160+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 19 + 160+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "space": ssl3_struct.add(pointerSize * 19 + 164+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "fixed": ssl3_struct.add(pointerSize * 19 + 168+ NSS.SS3_VERSIONS_OFFSET).readU32(),

                },
                "header_bytes": ssl3_struct.add(pointerSize * 19 + 172+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "msg_type": ssl3_struct.add(pointerSize * 19 + 176+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "msg_len": ssl3_struct.add(pointerSize * 19 + 180+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "isResuming": ssl3_struct.add(pointerSize * 19 + 184+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "sendingSCSV": ssl3_struct.add(pointerSize * 19 + 188+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "receivedNewSessionTicket": ssl3_struct.add(pointerSize * 19 + 192+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "newSessionTicket": ssl3_struct.add(pointerSize * 19 + 196+ NSS.SS3_VERSIONS_OFFSET),          // for now we calculate only its offset (44 bytes); detailes at https://github.com/nss-dev/nss/blob/master/lib/ssl/ssl3prot.h#L162
                "finishedBytes": ssl3_struct.add(pointerSize * 19 + 240+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "finishedMsgs": ssl3_struct.add(pointerSize * 19 + 244+ NSS.SS3_VERSIONS_OFFSET),
                "authCertificatePending": ssl3_struct.add(pointerSize * 18 + 316+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "restartTarget": ssl3_struct.add(pointerSize * 19 + 320+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "canFalseStart": ssl3_struct.add(pointerSize * 19 + 324+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "preliminaryInfo": ssl3_struct.add(pointerSize * 19 + 328+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "remoteExtensions": {
                    "next": ssl3_struct.add(pointerSize * 19 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "prev": ssl3_struct.add(pointerSize * 20 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                },
                "echOuterExtensions": {
                    "next": ssl3_struct.add(pointerSize * 21 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "prev": ssl3_struct.add(pointerSize * 22 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                },
                "sendMessageSeq": ssl3_struct.add(pointerSize * 23 + 332+ NSS.SS3_VERSIONS_OFFSET).readU32(),  //u16 but through alignment  U32
                "lastMessageFlight": {
                    "next": ssl3_struct.add(pointerSize * 23 + 336+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "prev": ssl3_struct.add(pointerSize * 24 + 336+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                },
                "maxMessageSent": ssl3_struct.add(pointerSize * 25 + 336+ NSS.SS3_VERSIONS_OFFSET).readU16(),  //u16
                "recvMessageSeq": ssl3_struct.add(pointerSize * 25 + 338+ NSS.SS3_VERSIONS_OFFSET).readU16(),
                "recvdFragments": { // sslBuffer
                    "data": ssl3_struct.add(pointerSize * 25 + 340+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 26 + 340+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "space": ssl3_struct.add(pointerSize * 26 + 344+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                    "fixed": ssl3_struct.add(pointerSize * 26 + 348+ NSS.SS3_VERSIONS_OFFSET).readU32(),

                },
                "recvdHighWater": ssl3_struct.add(pointerSize * 26 + 352+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "cookie": {
                    "type": ssl3_struct.add(pointerSize * 26 + 356+ NSS.SS3_VERSIONS_OFFSET).readU64(),
                    "data": ssl3_struct.add(pointerSize * 27 + 356+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 28 + 356+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                },
                "times_array": ssl3_struct.add(pointerSize * 28 + 360+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "rtTimer": ssl3_struct.add(pointerSize * 28 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "ackTimer": ssl3_struct.add(pointerSize * 29 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "hdTimer": ssl3_struct.add(pointerSize * 30 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "rtRetries": ssl3_struct.add(pointerSize * 31 + 432+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                "srvVirtName": {
                    "type": ssl3_struct.add(pointerSize * 31 + 436+ NSS.SS3_VERSIONS_OFFSET).readU64(),
                    "data": ssl3_struct.add(pointerSize * 32 + 436+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                    "len": ssl3_struct.add(pointerSize * 33 + 436+ NSS.SS3_VERSIONS_OFFSET).readU32(),
                },
                "currentSecret": ssl3_struct.add(pointerSize * 33 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "resumptionMasterSecret": ssl3_struct.add(pointerSize * 34 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "dheSecret": ssl3_struct.add(pointerSize * 35 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "clientEarlyTrafficSecret": ssl3_struct.add(pointerSize * 36 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "clientHsTrafficSecret": ssl3_struct.add(pointerSize * 37 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "serverHsTrafficSecret": ssl3_struct.add(pointerSize * 38 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "clientTrafficSecret": ssl3_struct.add(pointerSize * 39 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "serverTrafficSecret": ssl3_struct.add(pointerSize * 40 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "earlyExporterSecret": ssl3_struct.add(pointerSize * 41 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(),
                "exporterSecret": ssl3_struct.add(pointerSize * 42 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer()

            } // end of hs struct

            /*
            typedef struct SSL3HandshakeStateStr {
        SSL3Random server_random;
        SSL3Random client_random;
        SSL3Random client_inner_random; 
        SSL3WaitState ws;                       --> enum type      
    
        
        SSL3HandshakeHashType hashType;         --> enum type      
        sslBuffer messages;                     --> struct of 20 bytes (1 ptr + 12 bytes;see lib/ssl/sslencode.h)
        sslBuffer echInnerMessages; 
        
        PK11Context *md5;
        PK11Context *sha;
        PK11Context *shaEchInner;
        PK11Context *shaPostHandshake;
        SSLSignatureScheme signatureScheme;     --> enum type( see lib/ssl/sslt.h)
        const ssl3KEADef *kea_def;
        ssl3CipherSuite cipher_suite;           --> typedef PRUint16 ssl3CipherSuite (see lib/ssl/ssl3prot.h)
        const ssl3CipherSuiteDef *suite_def;
        sslBuffer msg_body; 
                            
        unsigned int header_bytes;
        
        SSLHandshakeType msg_type;
        unsigned long msg_len;
        PRBool isResuming;  
        PRBool sendingSCSV; 
    
        
        PRBool receivedNewSessionTicket;
        NewSessionTicket newSessionTicket;      --> (see lib/ssl/ssl3prot.h)
    
        PRUint16 finishedBytes; 
        union {
            TLSFinished tFinished[2];           --> 12 bytes
            SSL3Finished sFinished[2];          --> 36 bytes
            PRUint8 data[72];
        } finishedMsgs;                         --> 72
    
        PRBool authCertificatePending;
        
        sslRestartTarget restartTarget;
    
        PRBool canFalseStart; 
        
        PRUint32 preliminaryInfo;
    
        
        PRCList remoteExtensions;  
        PRCList echOuterExtensions;
    
        
        PRUint16 sendMessageSeq;   
        PRCList lastMessageFlight; 
        PRUint16 maxMessageSent;   
        PRUint16 recvMessageSeq;   
        sslBuffer recvdFragments;  
        PRInt32 recvdHighWater;    
        SECItem cookie;            
        dtlsTimer timers[3];       24 * 3
        dtlsTimer *rtTimer;        
        dtlsTimer *ackTimer;       
        dtlsTimer *hdTimer;        
        PRUint32 rtRetries;        
        SECItem srvVirtName;       
                                        
    
        // This group of values is used for TLS 1.3 and above 
        PK11SymKey *currentSecret;            // The secret down the "left hand side"   --> ssl3_struct.add(704)
                                                //of the TLS 1.3 key schedule.          
        PK11SymKey *resumptionMasterSecret;   // The resumption_master_secret.          --> ssl3_struct.add(712)
        PK11SymKey *dheSecret;                // The (EC)DHE shared secret.             --> ssl3_struct.add(720)
        PK11SymKey *clientEarlyTrafficSecret; // The secret we use for 0-RTT.           --> ssl3_struct.add(728)
        PK11SymKey *clientHsTrafficSecret;    // The source keys for handshake          --> ssl3_struct.add(736)
        PK11SymKey *serverHsTrafficSecret;    // traffic keys.                          --> ssl3_struct.add(744)
        PK11SymKey *clientTrafficSecret;      // The source keys for application        --> ssl3_struct.add(752)
        PK11SymKey *serverTrafficSecret;      // traffic keys                           --> ssl3_struct.add(760)
        PK11SymKey *earlyExporterSecret;      // for 0-RTT exporters                    --> ssl3_struct.add(768)
        PK11SymKey *exporterSecret;           // for exporters                          --> ssl3_struct.add(776)
        ...
    
    
        typedef struct {
        const char *label; 8
        DTLSTimerCb cb; 8
        PRIntervalTime started; 4
        PRUint32 timeout; 4
    } dtlsTimer;
    
            */
        }

    }


    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslspec.h#L140 
    static parse_struct_sl3CipherSpecStr(cwSpec: NativePointer) {
        /*
        truct ssl3CipherSpecStr {
            PRCList link;
            PRUint8 refCt;
    
            SSLSecretDirection direction;
            SSL3ProtocolVersion version;
            SSL3ProtocolVersion recordVersion;
    
            const ssl3BulkCipherDef *cipherDef;
            const ssl3MACDef *macDef;
    
            SSLCipher cipher;
            void *cipherContext;
    
            PK11SymKey *masterSecret;
            ...
        */
        return {
            "link": cwSpec.add,
            "refCt": cwSpec.add(pointerSize * 2),
            "direction": cwSpec.add(pointerSize * 2 + 4),
            "version": cwSpec.add(pointerSize * 2 + 8),
            "recordVersion": cwSpec.add(pointerSize * 2 + 12),
            "cipherDef": cwSpec.add(pointerSize * 2 + 16).readPointer(),
            "macDef": cwSpec.add(pointerSize * 3 + 16).readPointer(),
            "cipher": cwSpec.add(pointerSize * 4 + 16),
            "cipherContext": cwSpec.add(pointerSize * 4 + 24).readPointer(),
            "master_secret": cwSpec.add(pointerSize * 5 + 24).readPointer()
        }

    }

    /********* NSS Callbacks ************/

    /*
    This callback gets called whenever a SSL Handshake completed
    
    typedef void (*SSLHandshakeCallback)(
            PRFileDesc *fd,
            void *client_data);
    */
    static keylog_callback = new NativeCallback(function (sslSocketFD, client_data) {
        if (typeof this !== "undefined") {
            NSS.ssl_RecordKeyLog(sslSocketFD);
        } else {
            console.log("[-] Error while installing ssl_RecordKeyLog() callback");
        }
        return 0;
    }, "void", ["pointer", "pointer"]);



    /**   
     * SSL_SetSecretCallback installs a callback that TLS calls when it installs new
     * traffic secrets.
     * 
     * 
     *
     * SSLSecretCallback is called with the current epoch and the corresponding
     * secret; this matches the epoch used in DTLS 1.3, even if the socket is
     * operating in stream mode:
     *
     * - client_early_traffic_secret corresponds to epoch 1
     * - {client|server}_handshake_traffic_secret is epoch 2
     * - {client|server}_application_traffic_secret_{N} is epoch 3+N
     *
     * The callback is invoked separately for read secrets (client secrets on the
     * server; server secrets on the client), and write secrets.
     *
     * This callback is only called if (D)TLS 1.3 is negotiated.
     *
     * typedef void(PR_CALLBACK *SSLSecretCallback)(
     *   PRFileDesc *fd, PRUint16 epoch, SSLSecretDirection dir, PK11SymKey *secret,
     *   void *arg);
     * 
     *  More: https://github.com/nss-dev/nss/blob/master/lib/ssl/sslexp.h#L614                           
     * 
     */
    static secret_callback = new NativeCallback(function (sslSocketFD: NativePointer, epoch: number, dir: number, secret: NativePointer, arg_ptr: NativePointer) {
        if (typeof this !== "undefined") {
            NSS.parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch);
        } else {
            console.log("[-] Error while installing parse_epoch_value_from_SSL_SetSecretCallback()");
        }

        return;
    }, "void", ["pointer", "uint16", "uint16", "pointer", "pointer"]);


    /********* NSS helper functions  ********/

    /**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {pointer} sockfd The file descriptor of the socket to inspect as PRFileDesc.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".

  PRStatus PR_GetPeerName(
PRFileDesc *fd, 
PRNetAddr *addr);

PRStatus PR_GetSockName(
PRFileDesc *fd, 
PRNetAddr *addr);

PRStatus PR_NetAddrToString(
const PRNetAddr *addr, 
char *string, 
PRUint32 size);


union PRNetAddr {
struct {
   PRUint16 family;
   char data[14];
} raw;
struct {
   PRUint16 family;
   PRUint16 port;
   PRUint32 ip;
   char pad[8];
} inet;
#if defined(_PR_INET6)
struct {
   PRUint16 family;
   PRUint16 port;
   PRUint32 flowinfo;
   PRIPv6Addr ip;
} ipv6;
#endif // defined(_PR_INET6) 
};

typedef union PRNetAddr PRNetAddr;

*/
    static getPortsAndAddressesFromNSS(sockfd: NativePointer | null, isRead: boolean, methodAddresses: { [key: string]: NativePointer }, enable_default_fd: boolean): { [key: string]: string | number } {

        var message: { [key: string]: string | number } = {}
        if (enable_default_fd && sockfd === null){
        
            message["src" + "_port"] = 1234
            message["src" + "_addr"] = "127.0.0.1"
            message["dst" + "_port"] = 2345
            message["dst" + "_addr"] = "127.0.0.1"
            message["ss_family"] = "AF_INET"
    
            return message
        }    
        var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"])
        var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"])
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"])
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"])

        var addrType = Memory.alloc(2) // PRUint16 is a 2 byte (16 bit) value on all plattforms


        //var prNetAddr = Memory.alloc(Process.pointerSize)
        var addrlen = Memory.alloc(4)
        var addr = Memory.alloc(128)
        var src_dst = ["src", "dst"]
        for (var i = 0; i < src_dst.length; i++) {
            addrlen.writeU32(128)
            if ((src_dst[i] == "src") !== isRead) {
                getsockname(sockfd as NativePointer, addr)
            }
            else {
                getpeername(sockfd as NativePointer, addr)
            }

            if (addr.readU16() == AF_INET) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16()) as number
                message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32()) as number
                message["ss_family"] = "AF_INET"
            } else if (addr.readU16() == AF_INET6) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16()) as number
                message[src_dst[i] + "_addr"] = ""
                var ipv6_addr = addr.add(8)
                for (var offset = 0; offset < 16; offset += 1) {
                    message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2)
                }
                if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                    message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32()) as number
                    message["ss_family"] = "AF_INET"
                }
                else {
                    message["ss_family"] = "AF_INET6"
                }
            } else {
                devlog("[-] PIPE descriptor error: Only supporting IPv4/6: "+addr.readU16());
                //FIXME: Sometimes addr.readU16() will be 0 when a PIPE Read oder Write gets interpcepted, thus this error will be thrown.
                throw "Only supporting IPv4/6";
            }

        }
        return message
    }






    /**
    * This functions tests if a given address is a readable pointer
    * 
    * @param {*} ptr_addr is a pointer to the memory location where we want to check if there is already an address
    * @returns 1 to indicate that there is a ptr at 
    */
    static is_ptr_at_mem_location(ptr_addr: NativePointer) {
        try {
            // an exception is thrown if there isn't a readable address
            ptr_addr.readPointer();
            return 1;
        } catch (error) {
            return -1;
        }
    }

    /**
    * 
    * typedef struct PRFileDesc {
    *       const struct PRIOMethods *methods;
    *       PRFilePrivate *secret;
    *       PRFileDesc *lower;
    *       PRFileDesc *higher;
    *       void (*dtor) (PRFileDesc *);
    *       PRDescIdentity identity;
    *  } PRFileDesc;
    * 
    * @param {*} pRFileDesc 
    * @param {*} layer_name 
    * @returns 
    */
    static NSS_FindIdentityForName(pRFileDesc: NativePointer, layer_name: string): NativePointer {
        var lower_ptr = pRFileDesc.add(pointerSize * 2).readPointer();
        var higher_ptr = pRFileDesc.add(pointerSize * 3).readPointer();
        var identity = pRFileDesc.add(pointerSize * 5).readPointer();

        if (!identity.isNull()) {
            var nameptr = (<NativePointer>NSS.PR_GetNameForIdentity(identity)).readCString();
            if (nameptr == layer_name) {
                return pRFileDesc;
            }
        }

        if (!lower_ptr.isNull()) {
            return this.NSS_FindIdentityForName(lower_ptr, layer_name);
        }

        if (!higher_ptr.isNull()) {
            devlog('Have upper')
        }


        // when we reach this we have some sort of error 
        devlog("[-] error while getting SSL layer");
        return NULL;

    }



    static getSessionIdString(session_id_ptr: NativePointer, len: number): string {
        var session_id = "";


        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.

            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }

        return session_id
    }

    static getSSL_Layer(pRFileDesc: NativePointer) {

        var ssl_layer_id = 3 // SSL has the Layer ID 3 normally.
        var getIdentitiesLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetIdentitiesLayer'), "pointer", ["pointer", "int"])

        var ssl_layer = getIdentitiesLayer(pRFileDesc, ssl_layer_id);
        if (ptr(ssl_layer.toString()).isNull()) {
            devlog("PR_BAD_DESCRIPTOR_ERROR: " + ssl_layer);

            return -1;
        }
        return ssl_layer;


    }





    /**
    * 
    * @param {*} readAddr is the address where we start reading the bytes
    * @param {*} len is the length of bytes we want to convert to a hex string
    * @returns a hex string with the length of len
    */
    static getHexString(readAddr: NativePointer, len: number) {
        var secret_str = "";

        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xab ==> "ab"), and append
            // it to secret_str.

            secret_str +=
                ("0" + readAddr.add(i).readU8().toString(16).toLowerCase()).substr(-2)
        }

        return secret_str;
    }








    /**
 * Get the session_id of SSL object and return it as a hex string.
 * @param {!NativePointer} ssl A pointer to an SSL object.
 * @return {dict} A string representing the session_id of the SSL object's
 *     SSL_SESSION. For example,
 *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
 *
 * On NSS the return type of SSL_GetSessionID is a SECItem:
      typedef enum {
 * siBuffer = 0,
 * siClearDataBuffer = 1,
 * siCipherDataBuffer = 2,
 * siDERCertBuffer = 3,
 * siEncodedCertBuffer = 4,
 * siDERNameBuffer = 5,
 * siEncodedNameBuffer = 6,
 * siAsciiNameString = 7,
 * siAsciiString = 8,
 * siDEROID = 9,
 * siUnsignedInteger = 10,
 * siUTCTime = 11,
 * siGeneralizedTime = 12,
 * siVisibleString = 13,
 * siUTF8String = 14,
 * siBMPString = 15
 * } SECItemType;
 * 
 * typedef struct SECItemStr SECItem;
 * 
 * struct SECItemStr {
 * SECItemType type;
 * unsigned char *data;
 * unsigned int len;
 * }; --> size = 20
 * 
 *
 */


    static getSslSessionIdFromFD(pRFileDesc: NativePointer): string {
        var dummySSL_SessionID = "3E8ABF58649A1A1C58824D704173BA9AAFA2DA33B45FFEA341D218B29BBACF8F";
        var fdType = NSS.getDescType(pRFileDesc)
        //log("pRFileDescType: "+ fdType)
        /*if(fdType == 4){ // LAYERED 
            pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString())
            if(pRFileDesc.toString() == "-1"){
                log("error")
        
            }
        }*/
        var layer = NSS.NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!layer || Java.available) { // on Android is no SSL_SESSION_get_id available
            return dummySSL_SessionID;
        }

        var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(layer).toString())


        if (sslSessionIdSECItem == null || sslSessionIdSECItem.isNull()) {
            try {
                devlog("---- getSslSessionIdFromFD -----")
                devlog("ERROR")
                devlog("pRFileDescType: " + NSS.getDescType(pRFileDesc))
                if (fdType == 2) {
                    var c = Memory.dup(pRFileDesc, 32)
                    //log(hexdump(c))
                    var getLayersIdentity = null;
                    var getNameOfIdentityLayer;
                    try {
                        getLayersIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetLayersIdentity'), "uint32", ["pointer"])
                        getNameOfIdentityLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["uint32"])
                    }catch(e){
                        getLayersIdentity = new NativeFunction(Module.getExportByName('libnss3.so', 'PR_GetLayersIdentity'), "uint32", ["pointer"])
                        getNameOfIdentityLayer = new NativeFunction(Module.getExportByName('libnss3.so', 'PR_GetNameForIdentity'), "pointer", ["uint32"])
                    }
                    var layerID = getLayersIdentity(pRFileDesc);
                    devlog("LayerID: " + layerID);
                    var nameIDentity = getNameOfIdentityLayer(layerID)
                    devlog("name address: " + nameIDentity)
                    devlog("name: " + ptr(nameIDentity.toString()).readCString())


                    var sslSessionIdSECItem2 = ptr(NSS.getSSL_Layer(pRFileDesc).toString())
                    devlog("sslSessionIdSECItem2 =" + sslSessionIdSECItem2)

                    if (sslSessionIdSECItem2.toString().startsWith("0x7f")) {
                        var aa = Memory.dup(sslSessionIdSECItem2, 32)
                        //log(hexdump(aa))

                        var sslSessionIdSECItem3 = ptr(NSS.SSL_SESSION_get_id(sslSessionIdSECItem2).toString())
                        devlog("sslSessionIdSECItem3 =" + sslSessionIdSECItem3)
                    }


                    var sslSessionIdSECItem4 = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString())
                    devlog("sslSessionIdSECItem4 =" + sslSessionIdSECItem4)

                    devlog("Using Dummy Session ID")
                    devlog("")
                } else if (fdType == 4) {
                    pRFileDesc = ptr(NSS.getSSL_Layer(pRFileDesc).toString())
                    var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString());

                    devlog("new sessionid_ITEM: " + sslSessionIdSECItem)
                } else {
                    devlog("---- SSL Session Analysis ------------");
                    var c = Memory.dup(sslSessionIdSECItem, 32);
                    devlog(hexdump(c));

                }

                devlog("---- getSslSessionIdFromFD finished -----");
                devlog("");
            } catch (error) {
                devlog("Error:" + error)

            }
            return dummySSL_SessionID;


        }

        var len = sslSessionIdSECItem.add(pointerSize * 2).readU32();

        var session_id_ptr = sslSessionIdSECItem.add(pointerSize).readPointer()

        var session_id = NSS.getSessionIdString(session_id_ptr, len)

        return session_id
    }



    static get_SSL_FD(pRFileDesc: NativePointer): NativePointer {
        var ssl_layer = NSS.NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!ssl_layer) {
            devlog("error: couldn't get SSL Layer from pRFileDesc");
            return NULL;
        }

        var sslSocketFD = NSS.get_SSL_Socket(ssl_layer);
        if (!sslSocketFD) {
            devlog("error: couldn't get sslSocketFD");
            return NULL;
        }

        return sslSocketFD;
    }



    /**
    * 
    * 
    * 
    * 
    * 
    * 
    * /* This function tries to find the SSL layer in the stack.
    * It searches for the first SSL layer at or below the argument fd,
    * and failing that, it searches for the nearest SSL layer above the
    * argument fd.  It returns the private sslSocket from the found layer.
    *
    sslSocket *
    ssl_FindSocket(PRFileDesc *fd)
    {
    PRFileDesc *layer;
    sslSocket *ss;
    
    PORT_Assert(fd != NULL);
    PORT_Assert(ssl_layer_id != 0);
    
    layer = PR_GetIdentitiesLayer(fd, ssl_layer_id);
    if (layer == NULL) {
    PORT_SetError(PR_BAD_DESCRIPTOR_ERROR);
    return NULL;
    }
    
    ss = (sslSocket *)layer->secret;
    /* Set ss->fd lazily. We can't rely on the value of ss->fd set by
    * ssl_PushIOLayer because another PR_PushIOLayer call will switch the
    * contents of the PRFileDesc pointed by ss->fd and the new layer.
    * See bug 807250.
    *
    ss->fd = layer;
    return ss;
    }
    
    * 
    * 
    */


    static get_SSL_Socket(ssl_layer: NativePointer): NativePointer {
        var sslSocket = ssl_layer.add(pointerSize * 1).readPointer();
        return sslSocket;
    }

    /******** NSS Encryption Keys *******/



    /**
     * 
     * ss->ssl3.cwSpec->masterSecret
     * 
     * @param {*} ssl3  the parsed ssl3 struct
     * @returns the client_random as hex string (lower case) 
     */
    static getMasterSecret(ssl3: sslSocketStr) {
        var cwSpec = ssl3.cwSpec;
        var masterSecret_Ptr = NSS.parse_struct_sl3CipherSpecStr(cwSpec).master_secret;

        var master_secret = NSS.get_Secret_As_HexString(masterSecret_Ptr);

        return master_secret;

    }




    /** 
     * ss->ssl3.hs.client_random
     * 
     * @param {*} ssl3 is a ptr to current parsed ssl3 struct
     * @returns the client_random as hex string (lower case)
     */

    static getClientRandom(ssl3: sslSocketStr): string {
        var client_random = NSS.getHexString(ssl3.hs.client_random, NSS.SSL3_RANDOM_LENGTH);

        return client_random;

    }


    /**
    
     
    typedef struct sslSocketStr sslSocket;
     * 
    
        SSL Socket struct (https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L971)
    struct sslSocketStr {
    PRFileDesc *fd;                                                                     +8
    
    /* Pointer to operations vector for this socket *
    const sslSocketOps *ops;                                                            +8
    
    /* SSL socket options *
    sslOptions opt;                                                                     sizeOf(sslOptions) --> 40
    /* Enabled version range *
    SSLVersionRange vrange;                                                             + 4
    
    /* A function that returns the current time. *
    SSLTimeFunc now;                                                                    +8
    void *nowArg;                                                                       +8
    
    /* State flags *
    unsigned long clientAuthRequested;                                                  +8
    unsigned long delayDisabled;     /* Nagle delay disabled *                          +8
    unsigned long firstHsDone;       /* first handshake is complete. *                  +8
    unsigned long enoughFirstHsDone; /* enough of the first handshake is                +8
                                      * done for callbacks to be able to
                                      * retrieve channel security
                                      * parameters from the SSL socket. *
    unsigned long handshakeBegun;                                                       +8
    unsigned long lastWriteBlocked;                                                     +8
    unsigned long recvdCloseNotify; /* received SSL EOF. *                              +8
    unsigned long TCPconnected;                                                         +8
    unsigned long appDataBuffered;                                                      +8
    unsigned long peerRequestedProtection; /* from old renegotiation *                  +8
    
    /* version of the protocol to use *
    SSL3ProtocolVersion version;                                                        +4
    SSL3ProtocolVersion clientHelloVersion; /* version sent in client hello. *          --> at offset 160
     */


    static get_SSL_Version(pRFileDesc: NativePointer): number {
        var ssl_version_internal_Code = -1;

        var sslSocket = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocket.isNull()) {
            return -1;
        }


        var sslVersion_pointerSize = 160;

        ssl_version_internal_Code = sslSocket.add((sslVersion_pointerSize)).readU16();


        return ssl_version_internal_Code;

    }




    static get_Secret_As_HexString(secret_key_Ptr: NativePointer): string {
        var secret_as_hexString = "";



        var rv = NSS.PK11_ExtractKeyValue(secret_key_Ptr);
        if (rv != SECStatus.SECSuccess) {
            devlog("ERROR access the secret key: "+secret_key_Ptr+ " return value: "+rv);
            /*
            // debug output
            try{
                
                console.log("\n[!] dumping secret key: ")
                dumpMemory(secret_key_Ptr, 0x80);

                if(!secret_key_Ptr.isNull()){
                    var keyData1 = NSS.PK11_GetKeyData(secret_key_Ptr);
                    console.log("[!] dumping key data at: "+keyData1);
                    dumpMemory(keyData1, 0x80);
                    var keyData_SECITem1 = NSS.parse_struct_SECItem(keyData1 as NativePointer);

                    console.log("Looking at the value of keyData_SECITem1 (len: "+keyData_SECITem1.len+"): ")
                    dumpMemory(keyData_SECITem1.data, 0x80);
                    console.log("--------------------------------------------------\n");
                }

                


            }catch(e){

            }*/

            return "";
        }
        var keyData = NSS.PK11_GetKeyData(secret_key_Ptr);  // return value is a SECItem

        var keyData_SECITem = NSS.parse_struct_SECItem(keyData as NativePointer);

        try{
            if(keyData_SECITem.len > 64){
                devlog("[!] error in identifiying the real key_len: "+keyData_SECITem.len);
                secret_as_hexString = NSS.getHexString(keyData_SECITem.data, 32);
            }else{
                secret_as_hexString = NSS.getHexString(keyData_SECITem.data, keyData_SECITem.len);
            }
        }catch(e){
            devlog("[-] Error in extracting key from: "+keyData_SECITem.data+ " with length: "+keyData_SECITem.len+ " derived from secret_key_Ptr: "+secret_key_Ptr);
            dumpMemory(keyData_SECITem.data,0x80);
        }

        return secret_as_hexString;
    }


    /**
     * 
     * @param {*} ssl_version_internal_Code 
     * @returns 
     * 
     *      https://github.com/nss-dev/nss/blob/c989bde00fe64c1b37df13c773adf3e91cc258c7/lib/ssl/sslproto.h#L16
     *      #define SSL_LIBRARY_VERSION_TLS_1_2             0x0303
     *      #define SSL_LIBRARY_VERSION_TLS_1_3             0x0304
     *
     *      0x0303 -->  771
     *      0x0304 -->  772
     * 
     */

    static is_TLS_1_3(ssl_version_internal_Code: number) {
        if (ssl_version_internal_Code > 771) {
            return true;
        } else {
            return false;
        }
    }

    //see nss/lib/ssl/sslinfo.c for details */

    static get_Keylog_Dump(type: string, client_random: string, key: string) {
        // Debug output
        /*
        console.log("[!] CLIENT_RANDOM: "+client_random);
        console.log("[!] KEY: "+key);
        */
        return type + " " + client_random + " " + key;
    }

    /**
     * 
     * @param {*} pRFileDesc 
     * @param {*} dumping_handshake_secrets  a zero indicates an false and that the handshake just completed. A 1 indicates a true so that we are during the handshake itself
     * @returns 
     */

    static getTLS_Keys(pRFileDesc: NativePointer, dumping_handshake_secrets: number) {
        var message: { [key: string]: string | number } = {}
        message["contentType"] = "keylog";
        devlog("trying to log some keying materials ...");


        var sslSocketFD = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            return;
        }



        var sslSocketStr = NSS.parse_struct_sslSocketStr(sslSocketFD);
        var ssl3_struct = sslSocketStr.ssl3;
        var ssl3 = NSS.parse_struct_ssl3Str(ssl3_struct);


        //console.log("[!] inspecting ssl3: ");
        //dumpMemory(ssl3.hs.currentSecret,0x200);




        // the client_random is used to identify the diffrent SSL streams with their corresponding secrets
        var client_random = NSS.getClientRandom(ssl3);

        if (NSS.doTLS13_RTT0 == 1) {
            //var early_exporter_secret = get_Secret_As_HexString(ssl3_struct.add(768).readPointer()); //EARLY_EXPORTER_SECRET
            var early_exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.earlyExporterSecret); //EARLY_EXPORTER_SECRET
            devlog(NSS.get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret));
            message["keylog"] = NSS.get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret);
            send(message);
            NSS.doTLS13_RTT0 = -1;
        }

        if (dumping_handshake_secrets == 1) {
            devlog("exporting TLS 1.3 handshake keying material");
            /*
             * Those keys are computed in the beginning of a handshake
             */
            //var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(736).readPointer()); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            var client_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientHsTrafficSecret); //CLIENT_HANDSHAKE_TRAFFIC_SECRET

            //parse_struct_ssl3Str(ssl3_struct)
            devlog(NSS.get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret);
            send(message);

            //var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(744).readPointer()); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            var server_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverHsTrafficSecret); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            devlog(NSS.get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret));


            message["keylog"] = NSS.get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret);
            send(message);

            return;
        } else if (dumping_handshake_secrets == 2) {
            devlog("exporting TLS 1.3 RTT0 handshake keying material");

            var client_early_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientEarlyTrafficSecret); //CLIENT_EARLY_TRAFFIC_SECRET
            devlog(NSS.get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret);
            send(message);
            NSS.doTLS13_RTT0 = 1; // there is no callback for the EARLY_EXPORTER_SECRET
            return;
        }


        var ssl_version_internal_Code = NSS.get_SSL_Version(pRFileDesc);



        if (NSS.is_TLS_1_3(ssl_version_internal_Code)) {
            devlog("exporting TLS 1.3 keying material");

           
            /*
            Testing offsets via brute force...

            var i = 432;
            try{
                for (; i <= 850; i += 8) {
                    try{
                        var dst_ptr = ssl3_struct.add(i).readPointer();
                        if(!dst_ptr.isNull()){
                            console.log(i);
                            var server_handshake_traffic_secret = NSS.get_Secret_As_HexString(dst_ptr);
                            console.log("[!] server_handshake_traffic_secret (offset: "+i+"): "+server_handshake_traffic_secret);
                        }
                    }catch(innere){}
                    
                }

            }catch(e){

            }*/
            

            



            var client_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientTrafficSecret); //CLIENT_TRAFFIC_SECRET_0
            devlog(NSS.get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret);
            send(message);


            var server_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverTrafficSecret); //SERVER_TRAFFIC_SECRET_0
            devlog(NSS.get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret));
            message["keylog"] = NSS.get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret);
            send(message);

            var exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.exporterSecret); //EXPORTER_SECRET 
            devlog(NSS.get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret));
            message["keylog"] = NSS.get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret);
            send(message);


        } else {
            devlog("exporting TLS 1.2 keying material");

            var master_secret = NSS.getMasterSecret(ssl3);
            devlog(NSS.get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret));
            message["keylog"] = NSS.get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret);
            send(message);

        }


        NSS.doTLS13_RTT0 = -1;
        return;
    }




    static ssl_RecordKeyLog(sslSocketFD: NativePointer) {
        NSS.getTLS_Keys(sslSocketFD, 0);

    }



    /***** Installing the hooks *****/

    install_plaintext_read_hook() {
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;


        Interceptor.attach(this.addresses[this.moduleName]["PR_Read"],
            {
                onEnter: function (args: any) {
                    // ab hier nicht mehr
                    this.fd = ptr(args[0])
                    this.buf = ptr(args[1])
                },
                onLeave: function (retval: any) {
                    
                    if (retval.toInt32() <= 0 || NSS.getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                        return
                    }
                    //devlog("The results of NSS and its PR_Read is likely not the information transmitted over the wire. Better do a full capture and just log the TLS keys")

                    var addr = Memory.alloc(8);
                    var res = NSS.getpeername(this.fd, addr);
                    // peername return -1 this is due to the fact that a PIPE descriptor is used to read from the SSL socket


                    if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                        var message = NSS.getPortsAndAddressesFromNSS(this.fd as NativePointer, true, lib_addesses[current_module_name], enable_default_fd)
                        //devlog("Session ID: " + NSS.getSslSessionIdFromFD(this.fd))
                        message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd)
                        message["function"] = "NSS_read"
                        this.message = message

                        this.message["contentType"] = "datalog"
                        var data = this.buf.readByteArray((new Uint32Array([retval]))[0])
                        send(message, data)
                    } else {
                        /*
                        var message = NSS.getPortsAndAddressesFromNSS( this.fd as NativePointer, true, lib_addesses[current_module_name], enable_default_fd)
                        message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd)
                        message["function"] = "NSS_read"
                        this.message = message

                        this.message["contentType"] = "datalog"
                        var temp = this.buf.readByteArray((new Uint32Array([retval]))[0])
                        devlog(JSON.stringify(temp))
                        send(message, temp)*/
                    }
                }
            })

        

    }


    install_plaintext_write_hook() {
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;

        Interceptor.attach(this.addresses[this.moduleName]["PR_Write"],
            {
                onEnter: function (args: any) {
                    this.fd = ptr(args[0]);
                    this.buf = args[1]
                    this.len = args[2]
                },
                onLeave: function (retval: any) {
                    if (retval.toInt32() <= 0 ){//|| NSS.getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                        return
                    }

                    var addr = Memory.alloc(8);

                    NSS.getsockname(this.fd, addr);

                    if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                        var message = NSS.getPortsAndAddressesFromNSS(this.fd as NativePointer, false, lib_addesses[current_module_name], enable_default_fd)
                        message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd)
                        message["function"] = "NSS_write"
                        message["contentType"] = "datalog"
                        send(message, this.buf.readByteArray((parseInt(this.len))))
                    }else {
                        /*
                        log("The results of NSS and its PR_Write is likely not the information transmitted over the wire. Better do a full capture and just log the TLS keys")
                        var message = NSS.getPortsAndAddressesFromNSS(this.fd as NativePointer, true, lib_addesses[current_module_name], enable_default_fd)
                        message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd)
                        message["function"] = "NSS_write"
                        this.message = message

                        this.message["contentType"] = "datalog"
                        var temp = this.buf.readByteArray((new Uint32Array([retval]))[0])
                        devlog(JSON.stringify(temp))
                        send(message, temp)*/
                    }

                }
            })

    }

    /***** install callbacks for key logging ******/


    /**
 * 
 * This callback gets only called in TLS 1.3 and newer versions
 * 
 * @param {*} pRFileDesc 
 * @param {*} secret_label 
 * @param {*} secret 
 * @returns 
 *
function tls13_RecordKeyLog(pRFileDesc, secret_label, secret){

    var sslSocketFD = get_SSL_FD(pRFileDesc);
    if(sslSocketFD == -1){
        return;
    }

    var sslSocketStr = parse_struct_sslSocketStr(sslSocketFD);

    var ssl3_struct = sslSocketStr.ssl3;
    var ssl3 = parse_struct_ssl3Str(ssl3_struct); 
    

    var secret_as_hexString = get_Secret_As_HexString(secret);
    

    log(get_Keylog_Dump(secret_label,getClientRandom(ssl3),secret_as_hexString));


    return 0;
}

// our old way to get the diffrent secrets from TLS 1.3 and above
*/


    static parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD: NativePointer, epoch: number) {
        if (epoch == 1) { // client_early_traffic_secret
            NSS.getTLS_Keys(sslSocketFD, 2);
        } else if (epoch == 2) { // client|server}_handshake_traffic_secret
            NSS.getTLS_Keys(sslSocketFD, 1);


            /* our old way to get the diffrent secrets from TLS 1.3 and above
    
            per default we assume we are intercepting a TLS client therefore 
            dir == 1 --> SERVER_HANDSHAKE_TRAFFIC_SECRET
            dir == 2 --> CLIENT_HANDSHAKE_TRAFFIC_SECRET
            typedef enum {
                ssl_secret_read = 1,
                ssl_secret_write = 2,
            } SSLSecretDirection;
            
            if(dir == 1){
                tls13_RecordKeyLog(sslSocketFD,"SERVER_HANDSHAKE_TRAFFIC_SECRET",secret);
            }else{
                tls13_RecordKeyLog(sslSocketFD,"CLIENT_HANDSHAKE_TRAFFIC_SECRET",secret);
            }*/
        } else if (epoch >= 3) { // {client|server}_application_traffic_secret_{N}
            return;
            // we intercept this through the handshake_callback
        } else {
            devlog("[-] secret_callback invocation: UNKNOWN");
        }

    }

    static insert_hook_into_secretCallback(addr_of_installed_secretCallback: NativePointer) {
        Interceptor.attach(addr_of_installed_secretCallback,
            {
                onEnter(args: any) {
                    this.sslSocketFD = args[0];
                    this.epoch = args[1];
                    NSS.parse_epoch_value_from_SSL_SetSecretCallback(this.sslSocketFD, this.epoch);
                },
                onLeave(retval: any) {
                }

            });

    }

    /**
         * Registers a secret_callback through inserting the address to our TLS 1.3 callback function at the apprioate offset of the  SSL Socket struct
         * This is neccassy because the computed handshake secrets are already freed after the handshake is completed.
         * 
         * 
         * @param {*} pRFileDesc a file descriptor (NSS PRFileDesc) to a SSL socket
         * @returns 
         */
    static register_secret_callback(pRFileDesc: NativePointer) {
        var sslSocketFD = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            devlog("[-] error while installing secret callback: unable get SSL socket descriptor");
            return;
        }
        var sslSocketStr = NSS.parse_struct_sslSocketStr(sslSocketFD);

        if (NSS.is_ptr_at_mem_location(sslSocketStr.secretCallback.readPointer()) == 1) {
            NSS.insert_hook_into_secretCallback(sslSocketStr.secretCallback.readPointer());
        } else {
            sslSocketStr.secretCallback.writePointer(NSS.secret_callback);
        }


        devlog("secret callback (" + NSS.secret_callback + ") installed to address: " + sslSocketStr.secretCallback);


    }


    install_tls_keys_callback_hook() {

    }
}