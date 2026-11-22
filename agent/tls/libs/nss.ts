import { readAddresses, resolveOffsets, dumpMemory, decodeSockaddr, readSockaddrFamily } from "../../shared/shared_functions.js";
import { pointerSize, sendKeylog, sendDatalog } from "../../shared/shared_structures.js";
import { stampRecordLibrary } from "../../shared/record_message.js";
import { attachPlaintextWriteHook } from "../../shared/write_hooks.js";
import { log, devlog, devlog_debug, devlog_error } from "../../util/log.js";
import { enable_default_fd, pcap_enabled } from "../../fritap_agent.js";
import { Java } from "../../shared/javalib.js";
import { resolveWithPipelineAsync } from "../../shared/pipeline_utils.js";
import { DUMMY_SESSION_ID_NSS } from "../definitions/shared_constants.js";
import { LruMap, FifoSet } from "../../shared/lru.js";
import { nssClientRandomOffset } from "../../shared/nss_keylog_locator.js";
import { registerDetachTeardown } from "../../shared/detach_teardown.js";
import {
    CLIENT_RANDOM_LENGTH, LEARNED_NSS_CLIENT_RANDOM_OFF, NssClientRandomLearner, addressOf, attachGeneratedRandomObserver,
    isPlausibleClientRandomOffset, readClientRandomHex,
} from "../../shared/nss_client_random_learner.js";
import { NssEchRandomRecorder } from "../../shared/nss_ech_random_recorder.js";
import { ALL_ZERO_RE, NssTrackedSockets } from "../../shared/nss_tracked_sockets.js";
import { isCacheableModule, learnedLayout, rejectLearnedLayout, reportLearned } from "../../shared/learned_module_cache.js";
import { copyPointer, isExecutable, isReadable } from "../../util/safe_memory.js";
import { isPeImage } from "../../shared/pe_header.js";

/** Names of modules that may export NSS (nss3) / ssl3 symbols. */
const NSS_MODULE_NAME = /^(lib)?(nss3|ssl3)/i;

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

/** Resolved function addresses of one hooked NSS module (`addresses[moduleName]`). */
export type NssFunctionAddresses = { [fn: string]: NativePointer };

/** An app-registered SSLSecretCallback that friTap's secret_callback replaced and calls through to. */
export interface OriginalSecretCallback {
    cb: NativePointer;
    arg: NativePointer;
    fn: NativeFunction<void, [NativePointer, number, number, NativePointer, NativePointer]>;
}

// copyPointer lives in util/safe_memory (shared with the client_random learner); re-exported here.
export { copyPointer };

/** NSS detach-teardown counts, reported as the `teardown:nss-key-callbacks` step summary. */
export type NssRestoreSummary = {
    owned: number; toApp: number; toNull: number; stale: number; failed: number;
    hsOwned: number; hsCleared: number;
    /** tier-2 secret callbacks emitted for both the inner and the outer client_random (ECH accepted) */
    echDual: number;
};

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

        resolveOffsets(this.addresses, this.moduleName, socket_library, "nss");

        resolveWithPipelineAsync(this.addresses, this.moduleName, "nss", [
            "PR_Write", "PR_Read", "PR_FileDesc2NativeHandle",
            "SSL_ImportFD", "PK11_ExtractKeyValue", "PK11_GetKeyData"
        ]).catch(() => {}); // best-effort pattern gap-fill (these libs ship no byte patterns)

        if(!Java.available && this.addresses[this.moduleName]["SSL_GetSessionID"]){
            NSS.SSL_SESSION_get_id = new NativeFunction(this.addresses[this.moduleName]["SSL_GetSessionID"], "pointer", ["pointer"]);
        }

        NSS.getsockname = new NativeFunction(this.addresses[this.moduleName]["PR_GetSockName"], "int", ["pointer", "pointer"]);
        NSS.getpeername = new NativeFunction(this.addresses[this.moduleName]["PR_GetPeerName"], "int", ["pointer", "pointer"]);
        // The plaintext hooks call getDescType / PR_GetNameForIdentity per record; bind them
        // here so they work even when key extraction is not installed (or not yet).
        NSS.bindNativeHelpers(this.addresses[this.moduleName]);

       


    }

    // SSL_SecretCallback support (resolved via SSL_GetExperimentalAPI)
    static SSL_SecretCallback_fn: NativeFunction<number, [NativePointer, NativePointer, NativePointer]> | null = null;
    static SSL_SecretCallback_ptr: NativePointer | null = null;
    // Cached NSPR/libc wrappers for getPortsAndAddressesFromNSS (built once, reused per packet).
    private static _cachedSocketFns: {
        getpeername: NativeFunction<number, [NativePointer, NativePointer]>;
        getsockname: NativeFunction<number, [NativePointer, NativePointer]>;
        ntohs: NativeFunction<number, [number]>;
        ntohl: NativeFunction<number, [number]>;
    } | null = null;
    static secretCallbackReentryGuard: boolean = false;
    /** The app's own secret callback per sslSocket (key: sslSocket address), called through by secret_callback. */
    static originalSecretCallbacks = new Map<string, OriginalSecretCallback>();
    /** sslSocket address -> PRFileDesc of every live socket on which friTap's secret_callback is registered. */
    static ownedSecretCallbackFds = new Map<string, NativePointer>();
    /** App SSLHandshakeCallback addresses already hooked (dedupe before Interceptor.attach). */
    static hookedAppHandshakeCallbacks = new Set<string>();

    // Version-dependent ssl3 offset
    static SSL3_STATE_OFFSET: number = 1432;

    /** Tier-3 offset table is verified only below this version (major*1000+minor, exclusive). */
    static TABLE_VERIFIED_BELOW = 3115;

    /** Modules searched for NSS exports, in order (set by setExportScope). Never a global dlsym:
     *  Gecko loads libnss3 RTLD_LOCAL, so dlsym(RTLD_DEFAULT) cannot see it (C1). */
    static exportScope: Module[] = [];
    private static cachedVersion: number | null = null;
    private static tableDisabledLogged = false;

    /** Set the modules used for module-scoped export lookup (duplicates and nulls dropped). */
    static setExportScope(modules: Array<Module | null | undefined>): void {
        const seen = new Set<string>();
        NSS.exportScope = [];
        for (const m of modules) {
            if (!m || seen.has(m.base.toString())) continue;
            seen.add(m.base.toString());
            NSS.exportScope.push(m);
        }
        NSS.cachedVersion = null;
    }

    /** Module-scoped export lookup: the export scope, then any loaded libnss3* / libssl3*. */
    static findNssExport(name: string): NativePointer | null {
        return NSS.findExportIn([...NSS.exportScope, ...NSS.loadedModulesMatching(NSS_MODULE_NAME)], name);
    }

    /**
     * findNssExport over ONE loaded-module snapshot: the module list is enumerated lazily, on
     * the first name the export scope does not resolve, and reused for every later lookup.
     * For a burst of lookups (one install) instead of an enumeration per name.
     */
    static nssExportFinder(): (name: string) => NativePointer | null {
        let loaded: Module[] | null = null;
        return (name) => {
            const inScope = NSS.findExportIn(NSS.exportScope, name);
            if (inScope !== null) return inScope;
            if (loaded === null) loaded = NSS.loadedModulesMatching(NSS_MODULE_NAME);
            return NSS.findExportIn(loaded, name);
        };
    }

    /**
     * NSPR export lookup: the export scope, then any loaded NSPR (libnspr4.so, nspr4.dll,
     * libnspr4.dll, libnspr4.dylib) or folded NSS (libnss3.*, nss3.dll). Never a global dlsym.
     */
    static findNsprExport(name: string): NativePointer | null {
        return NSS.findExportIn([...NSS.exportScope, ...NSS.loadedModulesMatching(/^(lib)?(nspr4|nss3)\./i)], name);
    }

    private static findExportIn(modules: Module[], name: string): NativePointer | null {
        for (const m of modules) {
            try {
                const p = m.findExportByName(name);
                if (p !== null && !p.isNull()) return p;
            } catch (_e) { /* next module */ }
        }
        return null;
    }

    private static loadedModulesMatching(namePattern: RegExp): Module[] {
        try {
            return Process.enumerateModules().filter((m) => namePattern.test(m.name));
        } catch (_e) {
            return [];
        }
    }

    /** NSS version as major*1000+minor (3.132 -> 3132), 0 when unknown. Resolved from the detected module. */
    static get_NSS_version(): number {
        if (NSS.cachedVersion !== null) return NSS.cachedVersion;
        var version_string = "0";
        for (const name of ["NSSSSL_GetVersion", "NSS_GetVersion"]) {
            const fnAddr = NSS.findNssExport(name);
            if (fnAddr === null) continue;
            try {
                const text = (new NativeFunction(fnAddr, "pointer", []) as () => NativePointer)();
                if (!text.isNull()) {
                    version_string = text.readCString() ?? "0";
                    break;
                }
            } catch (e) {
                devlog(`NSS: ${name} failed: ${e}`);
            }
        }

        // Extract only the numeric part (e.g., "3.108 BETA" → "3.108")
        var match = version_string.match(/^(\d+)\.(\d+)/);
        // Convert to a numeric version: major * 1000 + minor (e.g., 3.108 → 3108)
        var version = match ? parseInt(match[1], 10) * 1000 + parseInt(match[2], 10) : 0;
        if (version > 0) NSS.cachedVersion = version;
        return version;
    }

    /** Human-readable form of a get_NSS_version() value. */
    static formatNssVersion(version: number): string {
        return version > 0 ? `${Math.floor(version / 1000)}.${version % 1000}` : "unknown";
    }

    /**
     * True iff the sslSocket/ssl3 offset table may be read (tier 3): only for NSS
     * versions inside the verified range. Logs once when the layout is unverified.
     */
    static structReadsAllowed(): boolean {
        const abiProblem = NSS.tableAbiMismatch();
        if (abiProblem !== null) {
            NSS.logTableDisabledOnce(`[!] NSS offset table is verified for LP64 Unix only (${abiProblem}), struct reads disabled`);
            return false;
        }
        const version = NSS.get_NSS_version();
        if (version > 0 && version < NSS.TABLE_VERIFIED_BELOW) return true;
        NSS.logTableDisabledOnce(`[!] NSS ${NSS.formatNssVersion(version)} layout unverified, struct reads disabled`);
        return false;
    }

    /**
     * Why the SSL3_STATE_OFFSET / ssl3 table does not apply to this process, or null when it
     * does. The table was measured on Linux LP64; Win64 is LLP64 (long is 4 bytes) and 32-bit
     * targets change every pointer-sized member, so neither may read through it.
     */
    static tableAbiMismatch(): string | null {
        if (Process.platform === "windows") return "Windows is LLP64";
        if (Process.pointerSize !== 8) return `pointer size ${Process.pointerSize}`;
        // Wine reports "linux" but a PE nss3.dll is still compiled LLP64.
        if (NSS.exportScope.some((m) => isPeImage(m.base))) return "PE module under Wine is LLP64";
        return null;
    }

    private static logTableDisabledOnce(message: string): void {
        if (NSS.tableDisabledLogged) return;
        NSS.tableDisabledLogged = true;
        log(message);
    }

    static detectVersionOffsets() {
        try {
            var nss_version = NSS.get_NSS_version();
            if (nss_version >= 3115) {
                NSS.SSL3_STATE_OFFSET = 1464;
            } else if (nss_version >= 3107) {
                NSS.SSL3_STATE_OFFSET = 1448;
            } else if (nss_version >= 3101) {
                NSS.SSL3_STATE_OFFSET = 1440;
            } else {
                NSS.SSL3_STATE_OFFSET = 1432;
            }
            devlog("NSS version " + nss_version + " — SSL3_STATE_OFFSET=" + NSS.SSL3_STATE_OFFSET);
        } catch (e) {
            devlog("NSS version detection failed, using default ssl3 offset: " + e);
        }
    }

    /**
     * Resolve SSL_SecretCallback through SSL_GetExperimentalAPI.
     * @param getExperimentalApiAddr the module-scoped address of SSL_GetExperimentalAPI
     *        (from the hooked module's resolved addresses); falls back to findNssExport.
     * @returns true when SSL_SecretCallback_fn is available
     */
    static resolveExperimentalAPI(getExperimentalApiAddr?: NativePointer | null): boolean {
        try {
            var getExpApiAddr = getExperimentalApiAddr ?? null;
            if (getExpApiAddr === null || getExpApiAddr.isNull()) {
                getExpApiAddr = NSS.findNssExport("SSL_GetExperimentalAPI");
            }
            if (getExpApiAddr === null || getExpApiAddr.isNull()) {
                devlog("SSL_GetExperimentalAPI not found in the NSS module — SSL_SecretCallback unavailable");
                return false;
            }

            var getExpApiFn = new NativeFunction(getExpApiAddr, "pointer", ["pointer"]);
            var nameStr = Memory.allocUtf8String("SSL_SecretCallback");
            var fnPtr = getExpApiFn(nameStr);
            if (!fnPtr.isNull()) {
                NSS.SSL_SecretCallback_fn = new NativeFunction(fnPtr, "int", ["pointer", "pointer", "pointer"]);
                NSS.SSL_SecretCallback_ptr = fnPtr;
                devlog("SSL_SecretCallback resolved via experimental API at " + fnPtr);
                return true;
            }
            devlog("SSL_GetExperimentalAPI returned NULL for SSL_SecretCallback");
        } catch (e) {
            devlog("SSL_GetExperimentalAPI resolution failed: " + e);
        }
        return false;
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
            "ssl3": sslSocketFD.add(NSS.SSL3_STATE_OFFSET)
        }
    }

    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
    static ssl3OffsetsInitialized: boolean = false;

    static initSsl3Offsets() {
        if (NSS.ssl3OffsetsInitialized) return;
        NSS.SS3_VERSIONS_OFFSET = 0;
        NSS.SS3_VERSIONS_CR_OFFSET = 0;
        var nss_version = NSS.get_NSS_version();
        if (nss_version >= 3107) {
            devlog("setting offsets for NSS version " + nss_version);
            NSS.SS3_VERSIONS_OFFSET = 96;
            NSS.SS3_VERSIONS_CR_OFFSET = 8;
        }
        NSS.ssl3OffsetsInitialized = true;
    }

    /**
     * Lazy view of ssl3StateStr: every field is a getter, so only the fields a caller
     * touches are read. Offsets come from the version table and are only trusted for
     * NSS < 3.115 (see structReadsAllowed()); callers must check that first.
     */
    static parse_struct_ssl3Str(ssl3_struct: NativePointer): sslSocketStr {
        NSS.initSsl3Offsets();

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
            get crSpec() { return ssl3_struct.readPointer(); },
            get prSpec() { return ssl3_struct.add(pointerSize).readPointer(); },
            get cwSpec() { return ssl3_struct.add(pointerSize * 2).readPointer(); },
            get pwSpec() { return ssl3_struct.add(pointerSize * 3).readPointer(); },
            get peerRequestedKeyUpdate() { return ssl3_struct.add(pointerSize * 4).readU32(); },
            get keyUpdateDeferred() { return ssl3_struct.add(pointerSize * 4 + 4).readU32(); },
            get deferredKeyUpdateRequest() { return ssl3_struct.add(pointerSize * 4 + 8).readU32(); },
            get clientCertRequested() { return ssl3_struct.add(pointerSize * 4 + 12).readU32(); },
            get clientCertificate() { return ssl3_struct.add(pointerSize * 4 + 16).readPointer(); },
            get clientPrivateKey() { return ssl3_struct.add(pointerSize * 5 + 16).readPointer(); },
            get clientCertChain() { return ssl3_struct.add(pointerSize * 6 + 16).readPointer(); },
            get sendEmptyCert() { return ssl3_struct.add(pointerSize * 7 + 16).readU32(); },
            get policy() { return ssl3_struct.add(pointerSize * 7 + 20).readU32(); },
            get peerCertArena() { return ssl3_struct.add(pointerSize * 7 + 24).readPointer(); },
            get peerCertChain() { return ssl3_struct.add(pointerSize * 8 + 24).readPointer(); },
            get ca_list() { return ssl3_struct.add(pointerSize * 9 + 24).readPointer(); },
            "hs": { // https://github.com/nss-dev/nss/blob/c277877bd8c01e107b097bbd57df094b34e37aab/lib/ssl/sslimpl.h#L615
                get client_random() { return ssl3_struct.add(pointerSize * 10 + 24+ NSS.SS3_VERSIONS_CR_OFFSET); },  //SSL3Random --> typedef PRUint8 SSL3Random[SSL3_RANDOM_LENGTH];
                get server_random() { return ssl3_struct.add(pointerSize * 10 + 56+ NSS.SS3_VERSIONS_CR_OFFSET); },
                get client_inner_random() { return ssl3_struct.add(pointerSize * 10 + 88+ NSS.SS3_VERSIONS_CR_OFFSET); },
                get ws() { return ssl3_struct.add(pointerSize * 10 + 120+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get hashType() { return ssl3_struct.add(pointerSize * 10 + 124+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                "messages": { // sslBuffer
                    get data() { return ssl3_struct.add(pointerSize * 10 + 128+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 11 + 128+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get space() { return ssl3_struct.add(pointerSize * 11 + 132+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get fixed() { return ssl3_struct.add(pointerSize * 11 + 136+ NSS.SS3_VERSIONS_OFFSET).readU32(); },

                },
                "echInnerMessages": { // sslBuffer
                    get data() { return ssl3_struct.add(pointerSize * 11 + 140+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 12 + 140+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get space() { return ssl3_struct.add(pointerSize * 12 + 144+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get fixed() { return ssl3_struct.add(pointerSize * 12 + 148+ NSS.SS3_VERSIONS_OFFSET).readU32(); },

                },
                get md5() { return ssl3_struct.add(pointerSize * 12 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get sha() { return ssl3_struct.add(pointerSize * 13 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get shaEchInner() { return ssl3_struct.add(pointerSize * 14 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get shaPostHandshake() { return ssl3_struct.add(pointerSize * 15 + 152+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get signatureScheme() { return ssl3_struct.add(pointerSize * 16 + 152+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get kea_def() { return ssl3_struct.add(pointerSize * 16 + 156+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get cipher_suite() { return ssl3_struct.add(pointerSize * 17 + 156+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get suite_def() { return ssl3_struct.add(pointerSize * 17 + 160+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                "msg_body": { // sslBuffer
                    get data() { return ssl3_struct.add(pointerSize * 18 + 160+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 19 + 160+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get space() { return ssl3_struct.add(pointerSize * 19 + 164+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get fixed() { return ssl3_struct.add(pointerSize * 19 + 168+ NSS.SS3_VERSIONS_OFFSET).readU32(); },

                },
                get header_bytes() { return ssl3_struct.add(pointerSize * 19 + 172+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get msg_type() { return ssl3_struct.add(pointerSize * 19 + 176+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get msg_len() { return ssl3_struct.add(pointerSize * 19 + 180+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get isResuming() { return ssl3_struct.add(pointerSize * 19 + 184+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get sendingSCSV() { return ssl3_struct.add(pointerSize * 19 + 188+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get receivedNewSessionTicket() { return ssl3_struct.add(pointerSize * 19 + 192+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get newSessionTicket() { return ssl3_struct.add(pointerSize * 19 + 196+ NSS.SS3_VERSIONS_OFFSET); },          // for now we calculate only its offset (44 bytes); detailes at https://github.com/nss-dev/nss/blob/master/lib/ssl/ssl3prot.h#L162
                get finishedBytes() { return ssl3_struct.add(pointerSize * 19 + 240+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get finishedMsgs() { return ssl3_struct.add(pointerSize * 19 + 244+ NSS.SS3_VERSIONS_OFFSET); },
                get authCertificatePending() { return ssl3_struct.add(pointerSize * 18 + 316+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get restartTarget() { return ssl3_struct.add(pointerSize * 19 + 320+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get canFalseStart() { return ssl3_struct.add(pointerSize * 19 + 324+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get preliminaryInfo() { return ssl3_struct.add(pointerSize * 19 + 328+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                "remoteExtensions": {
                    get next() { return ssl3_struct.add(pointerSize * 19 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get prev() { return ssl3_struct.add(pointerSize * 20 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                },
                "echOuterExtensions": {
                    get next() { return ssl3_struct.add(pointerSize * 21 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get prev() { return ssl3_struct.add(pointerSize * 22 + 332+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                },
                get sendMessageSeq() { return ssl3_struct.add(pointerSize * 23 + 332+ NSS.SS3_VERSIONS_OFFSET).readU32(); },  //u16 but through alignment  U32
                "lastMessageFlight": {
                    get next() { return ssl3_struct.add(pointerSize * 23 + 336+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get prev() { return ssl3_struct.add(pointerSize * 24 + 336+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                },
                get maxMessageSent() { return ssl3_struct.add(pointerSize * 25 + 336+ NSS.SS3_VERSIONS_OFFSET).readU16(); },  //u16
                get recvMessageSeq() { return ssl3_struct.add(pointerSize * 25 + 338+ NSS.SS3_VERSIONS_OFFSET).readU16(); },
                "recvdFragments": { // sslBuffer
                    get data() { return ssl3_struct.add(pointerSize * 25 + 340+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 26 + 340+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get space() { return ssl3_struct.add(pointerSize * 26 + 344+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                    get fixed() { return ssl3_struct.add(pointerSize * 26 + 348+ NSS.SS3_VERSIONS_OFFSET).readU32(); },

                },
                get recvdHighWater() { return ssl3_struct.add(pointerSize * 26 + 352+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                "cookie": {
                    get type() { return ssl3_struct.add(pointerSize * 26 + 356+ NSS.SS3_VERSIONS_OFFSET).readU64(); },
                    get data() { return ssl3_struct.add(pointerSize * 27 + 356+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 28 + 356+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                },
                get times_array() { return ssl3_struct.add(pointerSize * 28 + 360+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                get rtTimer() { return ssl3_struct.add(pointerSize * 28 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get ackTimer() { return ssl3_struct.add(pointerSize * 29 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get hdTimer() { return ssl3_struct.add(pointerSize * 30 + 432+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get rtRetries() { return ssl3_struct.add(pointerSize * 31 + 432+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                "srvVirtName": {
                    get type() { return ssl3_struct.add(pointerSize * 31 + 436+ NSS.SS3_VERSIONS_OFFSET).readU64(); },
                    get data() { return ssl3_struct.add(pointerSize * 32 + 436+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                    get len() { return ssl3_struct.add(pointerSize * 33 + 436+ NSS.SS3_VERSIONS_OFFSET).readU32(); },
                },
                get currentSecret() { return ssl3_struct.add(pointerSize * 33 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get resumptionMasterSecret() { return ssl3_struct.add(pointerSize * 34 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get dheSecret() { return ssl3_struct.add(pointerSize * 35 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get clientEarlyTrafficSecret() { return ssl3_struct.add(pointerSize * 36 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get clientHsTrafficSecret() { return ssl3_struct.add(pointerSize * 37 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get serverHsTrafficSecret() { return ssl3_struct.add(pointerSize * 38 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get clientTrafficSecret() { return ssl3_struct.add(pointerSize * 39 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get serverTrafficSecret() { return ssl3_struct.add(pointerSize * 40 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get earlyExporterSecret() { return ssl3_struct.add(pointerSize * 41 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },
                get exporterSecret() { return ssl3_struct.add(pointerSize * 42 + 440+ NSS.SS3_VERSIONS_OFFSET).readPointer(); },

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
            devlog_error("[-] Error while installing ssl_RecordKeyLog() callback");
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
    static SECRET_LABEL_MAP: { [key: string]: string } = {
        "1:2": "CLIENT_EARLY_TRAFFIC_SECRET",
        "2:2": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "2:1": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "3:2": "CLIENT_TRAFFIC_SECRET_0",
        "3:1": "SERVER_TRAFFIC_SECRET_0"
    };

    static secret_callback = new NativeCallback(function (fd: NativePointer, epoch: number, dir: number, secret: NativePointer, arg_ptr: NativePointer) {
        NSS.onSecretCallback(fd, epoch, dir, secret);
    }, "void", ["pointer", "uint16", "int", "pointer", "pointer"]);

    /** Body of secret_callback: log the secret, then ALWAYS call through to the app's original. */
    static onSecretCallback(fd: NativePointer, epoch: number, dir: number, secret: NativePointer): void {
        var sslSocketFD: NativePointer = NULL;
        try {
            // NSS passes ss->fd, i.e. the SSL layer itself: its PRFileDesc.secret is the sslSocket.
            sslSocketFD = NSS.get_SSL_Socket(fd);
            NSS.logSecret(sslSocketFD, epoch, dir, secret);
        } catch (e) {
            devlog_error("secret_callback error: " + e);
        } finally {
            // Always hand the secret on to the app's own callback (e.g. Neqo needs it for QUIC).
            NSS.callOriginalSecretCallback(sslSocketFD, fd, epoch, dir, secret);
        }
    }

    /** Emit one keylog line for an SSLSecretCallback invocation (read-only). */
    static logSecret(sslSocketFD: NativePointer, epoch: number, dir: number, secret: NativePointer): void {
        var label = NSS.SECRET_LABEL_MAP[epoch + ":" + dir];
        if (!label || secret.isNull() || sslSocketFD.isNull()) return;

        var client_random = NSS.clientRandomHexFromSocket(sslSocketFD, true);
        if (!client_random) return;

        // Extract key directly from PK11SymKey* parameter
        var secretHex = NSS.get_Secret_As_HexString(secret);
        if (!secretHex || secretHex.length === 0) return;

        devlog("invoking keylog from NSS (SSL_SecretCallback)");
        var randoms = NSS.keylogRandomsFor(sslSocketFD, client_random);
        if (randoms.length === 1) {
            sendKeylog(NSS.get_Keylog_Dump(label, client_random, secretHex));
            return;
        }
        var sentAny = false;
        for (var random of randoms) {
            if (NSS.sendEchDualLine(NSS.get_Keylog_Dump(label, random, secretHex))) sentAny = true;
        }
        if (sentAny) NSS.echDualEmissions++;
    }

    /**
     * client_randoms one tier-2 secret line is keyed with: [inner, outer] when the ECH
     * recorder saw this socket accept ECH (NSS copied the inner random over client_random;
     * Wireshark without ECH_SECRET only knows the outer one), else [live]. Never throws.
     */
    static keylogRandomsFor(sslSocketFD: NativePointer, liveHex: string): string[] {
        var recorder = NSS.echRecorder;
        if (recorder === null) return [liveHex];
        try {
            var offset = NSS.clientRandomOffsetFor(sslSocketFD, false);
            if (offset === null) return [liveHex];
            return recorder.keylogRandoms(addressOf(sslSocketFD), offset, liveHex);
        } catch (_e) {
            return [liveHex];
        }
    }

    /**
     * ECH-dual lines are deduplicated (bounded), so a repeated callback never doubles them.
     * @returns true iff the line was sent (not a duplicate)
     */
    private static sendEchDualLine(line: string): boolean {
        if (NSS.echDualLinesSent.has(line)) return false;
        NSS.echDualLinesSent.add(line);
        sendKeylog(line);
        return true;
    }

    static callOriginalSecretCallback(sslSocketFD: NativePointer, fd: NativePointer, epoch: number, dir: number, secret: NativePointer): void {
        if (sslSocketFD.isNull()) return;
        var orig = NSS.originalSecretCallbacks.get(sslSocketFD.toString());
        if (!orig || orig.cb.isNull() || orig.cb.equals(NSS.secret_callback)) return;
        try {
            orig.fn(fd, epoch, dir, secret, orig.arg);
        } catch (e) {
            devlog("secret_callback: original callback call-through failed: " + e);
        }
    }


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
        if (!NSS._cachedSocketFns) {
            NSS._cachedSocketFns = {
                getpeername: new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"]),
                getsockname: new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"]),
                ntohs: new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]),
                ntohl: new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]),
            }
        }
        var getpeername = NSS._cachedSocketFns.getpeername
        var getsockname = NSS._cachedSocketFns.getsockname
        var ntohs = NSS._cachedSocketFns.ntohs
        var ntohl = NSS._cachedSocketFns.ntohl

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

            // PRNetAddr shares the sockaddr field layout, so the shared decoder applies.
            // A PE NSPR under Wine stores PR_AF_INET6 as 23; readSockaddrFamily maps it.
            const decoded = decodeSockaddr(addr, false, { ntohs, ntohl }, false);
            if (!decoded) {
                devlog("[-] PIPE descriptor error: Only supporting IPv4/6: "+addr.readU16());
                //FIXME: Sometimes addr.readU16() will be 0 when a PIPE Read oder Write gets interpcepted, thus this error will be thrown.
                throw "Only supporting IPv4/6";
            }
            message[src_dst[i] + "_port"] = decoded.port;
            message[src_dst[i] + "_addr"] = decoded.addr;
            message["ss_family"] = decoded.family;

        }
        return message
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
    /**
     * Cache of PRFileDesc pointers known to have no SSL layer in their stack
     * (e.g. Firefox IPC sockets over localhost). Skipping the layer traversal
     * for these avoids repeated expensive recursion and silences noisy
     * "error while getting SSL layer" logs for fds that will never resolve.
     */
    static noSslLayerFDs = new FifoSet<string>(1024);

    /** PR_GetDescType(fd), or -1 when PR_GetDescType was not resolved (never throws on a missing binding). */
    static descTypeOf(pRFileDesc: NativePointer): number {
        return typeof NSS.getDescType === "function" ? NSS.getDescType(pRFileDesc) : -1;
    }

    static NSS_FindIdentityForName(pRFileDesc: NativePointer, layer_name: string): NativePointer {
        if (typeof NSS.PR_GetNameForIdentity !== "function") return NULL;   // PR_GetNameForIdentity unresolved
        const fdKey = pRFileDesc.toString();
        if (NSS.noSslLayerFDs.has(fdKey)) {
            return NULL;
        }
        const result = NSS._findIdentityForNameRecursive(pRFileDesc, layer_name);
        if (result.isNull()) {
            NSS.noSslLayerFDs.add(fdKey);
            devlog_debug("NSS: no SSL layer in NSPR stack (likely non-TLS fd)");
        }
        return result;
    }

    private static _findIdentityForNameRecursive(
        pRFileDesc: NativePointer, layer_name: string,
    ): NativePointer {
        const lower_ptr = pRFileDesc.add(pointerSize * 2).readPointer();
        const identity = pRFileDesc.add(pointerSize * 5).readPointer();

        if (!identity.isNull()) {
            const nameptr = (<NativePointer>NSS.PR_GetNameForIdentity(identity)).readCString();
            if (nameptr == layer_name) {
                return pRFileDesc;
            }
        }

        if (!lower_ptr.isNull()) {
            return NSS._findIdentityForNameRecursive(lower_ptr, layer_name);
        }

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
        var getIdentitiesLayerAddr = NSS.findNsprExport('PR_GetIdentitiesLayer');
        if (getIdentitiesLayerAddr === null) {
            devlog("NSS: PR_GetIdentitiesLayer not found in the NSPR/NSS modules");
            return -1;
        }
        var getIdentitiesLayer = new NativeFunction(getIdentitiesLayerAddr, "pointer", ["pointer", "int"])

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
        // Per-fd suffix keeps each connection's dummy ID unique so flows are not
        // collapsed when the SSL layer cannot be resolved (e.g. Firefox IPC).
        var fdHex = pRFileDesc.toString(16).padStart(8, '0').slice(-8).toUpperCase();
        var dummySSL_SessionID = DUMMY_SESSION_ID_NSS.slice(0, -8) + fdHex;
        var fdType = NSS.descTypeOf(pRFileDesc)
        //log("pRFileDescType: "+ fdType)
        /*if(fdType == 4){ // LAYERED 
            pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString())
            if(pRFileDesc.toString() == "-1"){
                log("error")
        
            }
        }*/
        var layer = NSS.NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!layer || Java.available || !NSS.SSL_SESSION_get_id) { // on Android/macOS SSL_SESSION_get_id may not be available
            return dummySSL_SessionID;
        }

        var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(layer).toString())


        if (sslSessionIdSECItem == null || sslSessionIdSECItem.isNull()) {
            try {
                devlog_debug("---- getSslSessionIdFromFD -----")
                devlog_debug("ERROR")
                devlog_debug("pRFileDescType: " + NSS.descTypeOf(pRFileDesc))
                if (fdType == 2) {
                    var c = Memory.dup(pRFileDesc, 32)
                    //log(hexdump(c))
                    // Resolved from the detected NSPR (libnspr4.so, nspr4.dll, ...) or a folded
                    // libnss3 / nss3.dll, not a hard-coded Linux module name.
                    var getLayersIdentityAddr = NSS.findNsprExport('PR_GetLayersIdentity');
                    var getNameForIdentityAddr = NSS.findNsprExport('PR_GetNameForIdentity');
                    if (getLayersIdentityAddr === null || getNameForIdentityAddr === null) {
                        throw new Error("PR_GetLayersIdentity / PR_GetNameForIdentity not found");
                    }
                    var getLayersIdentity = new NativeFunction(getLayersIdentityAddr, "uint32", ["pointer"])
                    var getNameOfIdentityLayer = new NativeFunction(getNameForIdentityAddr, "pointer", ["uint32"])
                    var layerID = getLayersIdentity(pRFileDesc);
                    devlog_debug("LayerID: " + layerID);
                    var nameIDentity = getNameOfIdentityLayer(layerID)
                    devlog_debug("name address: " + nameIDentity)
                    devlog_debug("name: " + ptr(nameIDentity.toString()).readCString())


                    var sslSessionIdSECItem2 = ptr(NSS.getSSL_Layer(pRFileDesc).toString())
                    devlog_debug("sslSessionIdSECItem2 =" + sslSessionIdSECItem2)

                    if (sslSessionIdSECItem2.toString().startsWith("0x7f")) {
                        var aa = Memory.dup(sslSessionIdSECItem2, 32)
                        //log(hexdump(aa))

                        var sslSessionIdSECItem3 = ptr(NSS.SSL_SESSION_get_id(sslSessionIdSECItem2).toString())
                        devlog_debug("sslSessionIdSECItem3 =" + sslSessionIdSECItem3)
                    }


                    var sslSessionIdSECItem4 = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString())
                    devlog_debug("sslSessionIdSECItem4 =" + sslSessionIdSECItem4)

                    devlog_debug("Using Dummy Session ID")
                    devlog_debug("")
                } else if (fdType == 4) {
                    pRFileDesc = ptr(NSS.getSSL_Layer(pRFileDesc).toString())
                    var sslSessionIdSECItem = ptr(NSS.SSL_SESSION_get_id(pRFileDesc).toString());

                    devlog_debug("new sessionid_ITEM: " + sslSessionIdSECItem)
                } else {
                    devlog_debug("---- SSL Session Analysis ------------");
                    var c = Memory.dup(sslSessionIdSECItem, 32);
                    devlog_debug(hexdump(c));

                }

                devlog_debug("---- getSslSessionIdFromFD finished -----");
                devlog_debug("");
            } catch (error) {
                devlog_debug("Error:" + error)

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
        if (!ssl_layer || ssl_layer.isNull()) {
            return NULL;
        }

        var sslSocketFD = NSS.get_SSL_Socket(ssl_layer);
        if (!sslSocketFD || sslSocketFD.isNull()) {
            devlog_debug("NSS: SSL layer found but sslSocketFD could not be obtained");
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


    /**
     * sslSocket of a PRFileDesc stack without the noSslLayerFDs cache: used by the key
     * extraction paths, where a stale "no SSL layer" verdict for a reused fd pointer
     * would break the secret-callback bookkeeping. NULL when there is no SSL layer.
     */
    static findSslSocketUncached(pRFileDesc: NativePointer): NativePointer {
        try {
            var ssl_layer = NSS._findIdentityForNameRecursive(pRFileDesc, 'SSL');
            return ssl_layer.isNull() ? NULL : NSS.get_SSL_Socket(ssl_layer);
        } catch (e) {
            devlog_debug("NSS: findSslSocketUncached failed: " + e);
            return NULL;
        }
    }

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
        var at = ssl3.hs.client_random;
        if (!isReadable(at, NSS.SSL3_RANDOM_LENGTH)) return "";
        return NSS.getHexString(at, NSS.SSL3_RANDOM_LENGTH);
    }

    /**
     * ss->ssl3.hs.client_random as lower-case hex, "" when unknown or not yet set.
     * Source order: the offset decoded from the keylog writer (tier 1), the learned /
     * cached offset, this socket's offset validated by the client_random learner, and
     * the version table only inside its verified range. Bytes are always read live
     * (ECH replaces client_random with the inner random). Every read is range-checked.
     *
     * @param atSecretCallback true only from the secret callback: there a learner socket
     *        is validated (first call decides); elsewhere only an already validated offset is used
     */
    static clientRandomHexFromSocket(sslSocketFD: NativePointer, atSecretCallback: boolean = false): string {
        var at: NativePointer;
        var offset = NSS.clientRandomOffsetFor(sslSocketFD, atSecretCallback);
        if (offset !== null) {
            at = sslSocketFD.add(offset);
        } else if (NSS.structReadsAllowed()) {
            at = NSS.parse_struct_ssl3Str(NSS.parse_struct_sslSocketStr(sslSocketFD).ssl3).hs.client_random;
        } else {
            return "";
        }
        if (!isReadable(at, NSS.SSL3_RANDOM_LENGTH)) return "";
        var hex = NSS.getHexString(at, NSS.SSL3_RANDOM_LENGTH);
        return /^0+$/.test(hex) ? "" : hex;
    }

    /**
     * Extract client_random from a PRFileDesc, traversing the NSS struct chain.
     * Reuses the same path as the keylog callback for a single source of truth.
     * Returns empty string on any failure.
     *
     * Results are cached keyed by the underlying sslSocketFD pointer — that
     * pointer identifies a unique NSS socket state struct and changes on
     * every new connection, so cached entries cannot be stale even if the
     * outer PRFileDesc pointer is reused by the OS after close(). An LRU
     * bound keeps memory bounded on long-running captures.
     */
    static clientRandomCache = new LruMap<string, string>(1024);

    /** client_random offset learned this run or loaded from the learned cache (tier-2 source). */
    static learnedClientRandomOffset: number | null = null;
    /** Sticky per process: once any learner saw sockets disagree, no learner ever starts again. */
    static clientRandomLearnerDisagreed = false;
    /** Tier-2 learner, while it runs (null with a known offset, or when PK11_GenerateRandom is missing). */
    static clientRandomLearner: NssClientRandomLearner | null = null;
    /** The read-only PK11_GenerateRandom hook feeding the learner and/or the ECH recorder. */
    private static randomObserverHook: InvocationListener | null = null;
    /** sslSockets the observer attributes randoms to, shared by the learner and the ECH recorder. */
    private static randomTrackedSockets: NssTrackedSockets | null = null;
    /** Tier-2 ECH recorder (outer/inner random per socket) while the PK11_GenerateRandom hook runs. */
    static echRecorder: NssEchRandomRecorder | null = null;
    /** Secret callbacks emitted for both the inner and the outer random (teardown `echDual`). */
    static echDualEmissions = 0;
    private static echDualLinesSent = new FifoSet<string>(4096);

    /** Offset of ss->ssl3.hs.client_random per the source order above, or null (table or nothing). */
    static clientRandomOffsetFor(sslSocketFD: NativePointer, atSecretCallback: boolean): number | null {
        var decodedOffset = nssClientRandomOffset();
        if (decodedOffset !== null) return decodedOffset;
        if (NSS.learnedClientRandomOffset !== null) return NSS.learnedClientRandomOffset;
        var learner = NSS.clientRandomLearner;
        if (learner === null) return null;
        var ss = addressOf(sslSocketFD);
        if (!atSecretCallback) return learner.validatedOffset(ss);
        return learner.validateSocket(ss, (off) => readClientRandomHex(sslSocketFD.add(off)));
    }

    /** The cached offset of this build, when the learned cache has a plausible one. */
    static loadCachedClientRandomOffset(sslModule: Module | null): number | null {
        if (sslModule === null) return null;
        var cached = learnedLayout(sslModule, LEARNED_NSS_CLIENT_RANDOM_OFF);
        if (cached === null) return null;
        if (!isPlausibleClientRandomOffset(cached)) {
            rejectLearnedLayout(sslModule, LEARNED_NSS_CLIENT_RANDOM_OFF);
            devlog(`[-] NSS: cached client_random offset ${cached} implausible; ignored`);
            return null;
        }
        log(`[*] ${sslModule.name}: NSS client_random +0x${cached.toString(16)} from the learned cache`);
        return cached;
    }

    /**
     * Start the read-only PK11_GenerateRandom observer of tier 2. It always records the
     * outer/inner randoms per socket for ECH (NssEchRandomRecorder); with `learn` it also
     * feeds the client_random learner, which learns until the offset is accepted (then
     * cached for this build) or the sockets disagree (fail closed). One hook and one
     * tracked-socket store serve both; the hook is detached on a learner disagreement and
     * in the detach teardown.
     */
    static startRandomObserver(generateRandom: NativePointer, sslModule: Module | null, learn: boolean): boolean {
        // One observer per process, shared across NSS copies: a later module never replaces
        // the live hook nor its tracked-socket store.
        if (NSS.randomObserverHook !== null) return true;
        if (NSS.clientRandomLearnerDisagreed) {
            // Fail closed for the rest of the process: never learn again, and only keep
            // recording ECH randoms when an offset is known from elsewhere (table or cache).
            if (NSS.knownClientRandomOffset() === null) {
                devlog("[-] NSS: client_random learner disagreed earlier; observer not restarted (fail closed)");
                return false;
            }
            learn = false;
        }
        var sockets = NSS.randomTrackedSockets ?? new NssTrackedSockets();
        var learner = learn ? NSS.createClientRandomLearner(sslModule, sockets) : null;
        var recorder = new NssEchRandomRecorder(sockets);
        try {
            NSS.randomObserverHook = attachGeneratedRandomObserver(generateRandom, (data) => {
                NSS.onGeneratedRandom(sockets, learner, NSS.echRecorder, data);
            });
        } catch (e) {
            devlog("[-] NSS: client_random learner could not hook PK11_GenerateRandom: " + e);
            return false;
        }
        NSS.randomTrackedSockets = sockets;
        if (learner !== null || !NSS.clientRandomLearnerDisagreed) NSS.clientRandomLearner = learner;
        NSS.echRecorder = recorder;
        var owner = Process.findModuleByAddress(generateRandom);
        var where = owner ? owner.name : generateRandom;
        if (learner !== null) log(`[*] NSS: client_random learner started (read-only PK11_GenerateRandom hook in ${where})`);
        else NSS.logEchObserverStaysOn();
        return true;
    }

    /**
     * Observer body: attribute one 32-byte generation into `data` ONCE (nearest-socket scan
     * while learning, two O(1) lookups once the client_random offset is known) and hand it
     * to the learner and the ECH recorder. Most RNG calls hit no socket and read no memory.
     */
    private static onGeneratedRandom(sockets: NssTrackedSockets, learner: NssClientRandomLearner | null,
                                     recorder: NssEchRandomRecorder | null, data: NativePointer): void {
        var learning = learner !== null && !learner.settled;
        if (!learning && recorder === null) return;
        var hit = sockets.locate(addressOf(data), learning ? null : NSS.knownClientRandomOffset());
        if (hit === null) return;
        var generated = readClientRandomHex(data);
        if (generated === null) return;
        if (learning) {
            var following = readClientRandomHex(data.add(CLIENT_RANDOM_LENGTH));
            if (following !== null) learner!.attributeAt(hit, generated, ALL_ZERO_RE.test(following));
        }
        recorder?.recordAt(hit, generated);
    }

    /** The client_random offset valid for every socket (decoded or learned/cached), or null. */
    private static knownClientRandomOffset(): number | null {
        return nssClientRandomOffset() ?? NSS.learnedClientRandomOffset;
    }

    private static createClientRandomLearner(sslModule: Module | null, sockets: NssTrackedSockets): NssClientRandomLearner {
        return new NssClientRandomLearner({
            onAccepted: (offset, count) => NSS.onClientRandomOffsetAccepted(offset, count, sslModule),
            onDisagreement: (offsets) => {
                log("[-] NSS: client_random learner: sockets disagree (" +
                    offsets.map((o) => "+0x" + o.toString(16)).join(" vs ") + "); fail closed, nothing cached");
                NSS.clientRandomLearnerDisagreed = true;
                NSS.stopRandomObserver();
            },
        }, undefined, sockets);
    }

    private static logEchObserverStaysOn(): void {
        log("[*] NSS: read-only PK11_GenerateRandom observer stays on for ECH " +
            "(records outer/inner client_random; ECH-accepted secrets are keyed with both)");
    }

    private static onClientRandomOffsetAccepted(offset: number, sockets: number, sslModule: Module | null): void {
        NSS.learnedClientRandomOffset = offset;
        // Keyed per module build (ELF build id or Mach-O LC_UUID); a module without one (PE) is not cacheable.
        var cached = sslModule !== null && isCacheableModule(sslModule);
        if (cached) reportLearned(sslModule!, { layout: { [LEARNED_NSS_CLIENT_RANDOM_OFF]: offset } });
        log(`[*] NSS: client_random +0x${offset.toString(16)} learned from ${sockets} sockets; ` +
            `${cached ? "cached" : "not cached (no build id)"}`);
        // Learning is done; the hook keeps recording ECH randoms while tier 2 is the key source
        // (onAccepted only fires from that hook, so the recorder exists here).
        NSS.logEchObserverStaysOn();
    }

    /**
     * Detach the PK11_GenerateRandom hook (the learner object stays for validated sockets)
     * and drop the ECH recorder with it.
     */
    static stopRandomObserver(): void {
        var hook = NSS.randomObserverHook;
        NSS.randomObserverHook = null;
        NSS.echRecorder?.clear();
        NSS.echRecorder = null;
        if (hook === null) return;
        try {
            hook.detach();
        } catch (e) {
            devlog("[-] NSS: detaching the client_random learner failed: " + e);
        }
    }

    /** The shared tracked-socket store while the learner learns or the ECH recorder runs, else null. */
    private static activeRandomTrackedSockets(): NssTrackedSockets | null {
        var learner = NSS.clientRandomLearner;
        var learning = learner !== null && !learner.settled;
        return learning || NSS.echRecorder !== null ? NSS.randomTrackedSockets : null;
    }

    /** SSL_ImportFD: a new (or reused) sslSocket the learner / ECH recorder may attribute randoms to. */
    static trackLearnerSocket(pRFileDesc: NativePointer): void {
        var sockets = NSS.activeRandomTrackedSockets();
        if (sockets === null) return;
        var sslSocketFD = NSS.findSslSocketUncached(pRFileDesc);
        if (sslSocketFD.isNull()) return;
        sockets.track(addressOf(sslSocketFD));
    }

    static extractClientRandom(fd: NativePointer): string {
        try {
            const sslSocketFD = NSS.get_SSL_FD(fd);
            if (sslSocketFD.isNull()) return "";

            const cacheKey = sslSocketFD.toString();
            const cached = NSS.clientRandomCache.get(cacheKey);
            if (cached !== undefined) return cached;

            const clientRandom = NSS.clientRandomHexFromSocket(sslSocketFD);
            // "" is not cached: the random may simply not be known yet (pre-ClientHello).
            if (clientRandom) NSS.clientRandomCache.set(cacheKey, clientRandom);
            return clientRandom;
        } catch (e) {
            devlog(`NSS extractClientRandom error: ${e}`);
            return "";
        }
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
        devlog("trying to log some keying materials ...");
        devlog(`entering NSS handshake-derivation keylog dump (mode=${dumping_handshake_secrets})`);

        // When secret_callback API is active, handshake secrets (epochs 1 & 2) are already
        // delivered with authoritative values — skip expensive struct parsing entirely
        if ((dumping_handshake_secrets == 1 || dumping_handshake_secrets == 2) && NSS.SSL_SecretCallback_fn) {
            return;
        }
        // Everything below reads the version table: only inside the verified range (tier 3).
        if (!NSS.structReadsAllowed()) {
            return;
        }

        var sslSocketFD = NSS.get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            return;
        }

        var sslSocketStr = NSS.parse_struct_sslSocketStr(sslSocketFD);
        var ssl3_struct = sslSocketStr.ssl3;
        var ssl3 = NSS.parse_struct_ssl3Str(ssl3_struct);

        // the client_random is used to identify the diffrent SSL streams with their corresponding secrets
        var client_random = NSS.clientRandomHexFromSocket(sslSocketFD);
        if (!client_random) {
            return;
        }

        if (NSS.doTLS13_RTT0 == 1) {
            var early_exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.earlyExporterSecret);
            var earlyExpDump = NSS.get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret);
            devlog(earlyExpDump);
            sendKeylog(earlyExpDump);
            NSS.doTLS13_RTT0 = -1;
        }

        if (dumping_handshake_secrets == 1) {
            devlog("exporting TLS 1.3 handshake keying material");

            var client_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientHsTrafficSecret);
            var chsDump = NSS.get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret);
            devlog(chsDump);
            sendKeylog(chsDump);

            var server_handshake_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverHsTrafficSecret);
            var shsDump = NSS.get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret);
            devlog(shsDump);
            sendKeylog(shsDump);

            return;
        } else if (dumping_handshake_secrets == 2) {
            devlog("exporting TLS 1.3 RTT0 handshake keying material");

            var client_early_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientEarlyTrafficSecret);
            var cetsDump = NSS.get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret);
            devlog(cetsDump);
            sendKeylog(cetsDump);
            NSS.doTLS13_RTT0 = 1; // there is no callback for the EARLY_EXPORTER_SECRET
            return;
        }


        var ssl_version_internal_Code = NSS.get_SSL_Version(pRFileDesc);

        if (NSS.is_TLS_1_3(ssl_version_internal_Code)) {
            devlog("exporting TLS 1.3 keying material");

            // When secret_callback API is active, it already delivers traffic secrets with authoritative values
            if (!NSS.SSL_SecretCallback_fn) {
                var client_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.clientTrafficSecret);
                var ctsDump = NSS.get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret);
                devlog(ctsDump);
                sendKeylog(ctsDump);

                var server_traffic_secret = NSS.get_Secret_As_HexString(ssl3.hs.serverTrafficSecret);
                var stsDump = NSS.get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret);
                devlog(stsDump);
                sendKeylog(stsDump);
            }

            // EXPORTER_SECRET is not delivered by secret_callback, so always extract from struct
            var exporter_secret = NSS.get_Secret_As_HexString(ssl3.hs.exporterSecret);
            if (exporter_secret) {
                var expDump = NSS.get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret);
                devlog(expDump);
                sendKeylog(expDump);
            }

        } else {
            devlog("exporting TLS 1.2 keying material");

            var master_secret = NSS.getMasterSecret(ssl3);
            var crDump = NSS.get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret);
            devlog(crDump);
            sendKeylog(crDump);

        }


        NSS.doTLS13_RTT0 = -1;
        return;
    }




    static ssl_RecordKeyLog(sslSocketFD: NativePointer) {
        NSS.getTLS_Keys(sslSocketFD, 0);

    }

    /**
     * Return true if the NSPR PRNetAddr starts with a loopback address.
     * IPv4: 127.0.0.0/8. IPv6: ::1. Used to short-circuit Firefox IPC
     * traffic before the expensive session-id / client-random extraction.
     *
     * Family is passed by the caller so the hot path reads it exactly once.
     * Byte-level reads are endian-invariant: in_addr and in6_addr are
     * stored as network-byte-order uint8[] regardless of host endianness.
     */
    static isLoopbackSockaddr(addr: NativePointer, family: number): boolean {
        if (family === 2) {
            return addr.add(4).readU8() === 0x7F;
        }
        if (family === 10 || family === 30 || family === 100) {
            // Single native read instead of 16 individual readU8 calls.
            const buf = addr.add(8).readByteArray(16);
            if (buf === null) return false;
            const bytes = new Uint8Array(buf);
            for (let i = 0; i < 15; i++) {
                if (bytes[i] !== 0) return false;
            }
            return bytes[15] === 1;
        }
        return false;
    }



    /***** Installing the hooks *****/

    install_plaintext_read_hook() {
        if (!pcap_enabled) return;
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

                    if (retval.toInt32() <= 0 || NSS.descTypeOf(this.fd) == PRDescType.PR_DESC_FILE) {
                        return
                    }

                    // PRNetAddr is up to 28 bytes (IPv6 variant); 32 covers it safely.
                    var addr = Memory.alloc(32);
                    NSS.getpeername(this.fd, addr);
                    // getpeername returns -1 for PIPE descriptors; the family check below
                    // filters those out.

                    // PRNetAddr family@0 (not a BSD sockaddr, so bsdSockaddr=false); on
                    // macOS NSPR stores AF_INET6 as 30, which readSockaddrFamily normalizes
                    // to 10 so the IPv6 gate below matches.
                    var family = readSockaddrFamily(addr, false);
                    if (family == 2 || family == 10 || family == 100) {
                        if (NSS.isLoopbackSockaddr(addr, family)) {
                            // Drop Firefox internal NSS IPC before touching the expensive
                            // session-id / client-random extraction paths.
                            return;
                        }
                        var message = NSS.getPortsAndAddressesFromNSS(this.fd as NativePointer, true, lib_addesses[current_module_name], enable_default_fd)
                        //devlog("Session ID: " + NSS.getSslSessionIdFromFD(this.fd))
                        message["ssl_session_id"] = NSS.getSslSessionIdFromFD(this.fd)
                        message["function"] = "NSS_read"
                        stampRecordLibrary(message, current_module_name)
                        message["client_random"] = NSS.extractClientRandom(this.fd as NativePointer);
                        this.message = message

                        var data = this.buf.readByteArray((new Uint32Array([retval]))[0])
                        sendDatalog(message, data)
                    }
                }
            })

        

    }


    install_plaintext_write_hook() {
        if (!pcap_enabled) return;
        var current_module_name = this.module_name;
        var lib_addesses = this.addresses;

        // PR_Write(fd, buf, amount) -> bytes written, -1 on error (PR_WOULD_BLOCK_ERROR on a
        // non-blocking socket, retried by the app); a non-blocking write can be partial.
        // attachPlaintextWriteHook emits only what this call wrote, never `amount` (PRInt32:
        // read unsigned as an upper bound only, the return value signed — see the helper).
        // Former onLeave gate (kept from HEAD): if (retval.toInt32() <= 0 ){//|| NSS.getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
        attachPlaintextWriteHook(this.addresses[this.moduleName]["PR_Write"], (args) => {
            var fd = args[0]
            // PRNetAddr is up to 28 bytes (IPv6 variant); 32 covers it safely.
            var addr = Memory.alloc(32);
            NSS.getsockname(fd, addr);
            // PRNetAddr family@0 (bsdSockaddr=false); macOS AF_INET6 30 -> 10. Anything
            // else (PIPE / file descriptors) is not wire traffic: no record.
            var family = readSockaddrFamily(addr, false);
            if (family != 2 && family != 10 && family != 100) return null
            if (NSS.isLoopbackSockaddr(addr, family)) return null // Firefox-internal NSS IPC
            var message = NSS.getPortsAndAddressesFromNSS(fd, false, lib_addesses[current_module_name], enable_default_fd)
            message["ssl_session_id"] = NSS.getSslSessionIdFromFD(fd)
            message["function"] = "NSS_write"
            stampRecordLibrary(message, current_module_name)
            message["client_random"] = NSS.extractClientRandom(fd);
            return message
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


    /***** Key extraction tiers 2/3 (tier 1 lives in shared/nss_keylog_locator.ts) *****/

    /** SSL_ImportFD addresses whose tier-2/3 hooks are installed (one install per NSS copy). */
    static fallbackInstalledFor = new Set<string>();
    /** sslSocket address -> PRFileDesc of every live socket carrying friTap's handshake callback (tier 3). */
    static ownedHandshakeCallbackFds = new Map<string, NativePointer>();
    /** PRFileDesc (top of stack, stable across layer pushes) -> sslSocket key, for PR_Close bookkeeping. */
    static ownedSocketByFd = new Map<string, string>();
    private static teardownRegistered = false;

    /** Bind the NSPR/NSS helpers both the plaintext and the key-extraction paths use. */
    static bindNativeHelpers(fnAddrs: NssFunctionAddresses): void {
        const bind = (name: string, ret: NativeFunctionReturnType, args: NativeFunctionArgumentType[]): any => {
            const a = fnAddrs[name];
            return a && !a.isNull() ? new NativeFunction(a, ret, args) : null;
        };
        NSS.getDescType = bind("PR_GetDescType", "int", ["pointer"]) ?? NSS.getDescType;
        NSS.PR_GetNameForIdentity = bind("PR_GetNameForIdentity", "pointer", ["pointer"]) ?? NSS.PR_GetNameForIdentity;
        NSS.get_SSL_Callback = bind("SSL_HandshakeCallback", "int", ["pointer", "pointer", "pointer"]) ?? NSS.get_SSL_Callback;
        NSS.PK11_ExtractKeyValue = bind("PK11_ExtractKeyValue", "int", ["pointer"]) ?? NSS.PK11_ExtractKeyValue;
        NSS.PK11_GetKeyData = bind("PK11_GetKeyData", "pointer", ["pointer"]) ?? NSS.PK11_GetKeyData;
    }

    /**
     * Tiers 2 and 3, installed only after tier 1 missed. Tier 2: friTap's secret_callback
     * via the supported SSL_SecretCallback API on every socket from SSL_ImportFD, with
     * call-through to the app's callback and restore on detach. Tier 3: read-only version
     * table, only for NSS < TABLE_VERIFIED_BELOW. Nothing here writes target memory.
     *
     * @param fnAddrs resolved, module-scoped addresses (SSL_ImportFD, SSL_HandshakeCallback,
     *        SSL_GetExperimentalAPI, PR_Close, ...); bindNativeHelpers must have run
     * @returns true iff at least one key-extraction hook was installed
     */
    static installFallbackKeyHooks(fnAddrs: NssFunctionAddresses): boolean {
        const importFd = fnAddrs["SSL_ImportFD"];
        if (!importFd || importFd.isNull()) {
            devlog("[-] NSS: SSL_ImportFD not resolved — no fallback key extraction");
            return false;
        }
        if (NSS.fallbackInstalledFor.has(importFd.toString())) return true;

        NSS.detectVersionOffsets();
        const tableTier = NSS.structReadsAllowed();
        const sslModule = Process.findModuleByAddress(importFd);
        if (nssClientRandomOffset() === null && NSS.learnedClientRandomOffset === null) {
            NSS.learnedClientRandomOffset = NSS.loadCachedClientRandomOffset(sslModule);
        }
        const secretTier = NSS.useSecretCallbackTier(fnAddrs, tableTier);
        // Tier 2 is the key source: the observer learns the offset when none is known, and
        // always records the ECH outer/inner randoms (tier 2 has no ECH_SECRET line).
        if (secretTier && NSS.learnerResolvable(fnAddrs)) {
            NSS.startRandomObserver(fnAddrs["PK11_GenerateRandom"], sslModule, NSS.needsClientRandomLearner());
        }
        if (!secretTier && !tableTier) {
            log("[-] NSS: no usable key-extraction tier (keylog writer not located, layout unverified)");
            return false;
        }

        NSS.fallbackInstalledFor.add(importFd.toString());
        NSS.installImportFdHook(importFd, secretTier, tableTier);
        if (secretTier) {
            NSS.installSecretCallbackInterceptor();
        }
        if (tableTier) {
            NSS.installHandshakeCallbackInterceptor(fnAddrs["SSL_HandshakeCallback"]);
        }
        NSS.installCloseHook(fnAddrs["PR_Close"]);
        NSS.registerSecretCallbackTeardown();
        log(`[*] NSS: key extraction via ${secretTier ? "SSL_SecretCallback API" : ""}` +
            `${secretTier && tableTier ? " + " : ""}${tableTier ? "read-only struct table" : ""}`);
        return true;
    }

    /** No decoded and no learned/cached client_random offset: tier 2 needs the learner. */
    private static needsClientRandomLearner(): boolean {
        return nssClientRandomOffset() === null && NSS.learnedClientRandomOffset === null;
    }

    /** The learner can run: PK11_GenerateRandom was resolved module-scoped. */
    private static learnerResolvable(fnAddrs: NssFunctionAddresses): boolean {
        const generateRandom = fnAddrs["PK11_GenerateRandom"];
        return !!generateRandom && !generateRandom.isNull();
    }

    /** Tier 2 needs the API, a client_random source and PR_Close (to know which sockets are still alive on detach). */
    private static useSecretCallbackTier(fnAddrs: NssFunctionAddresses, tableTier: boolean): boolean {
        let usable = NSS.resolveExperimentalAPI(fnAddrs["SSL_GetExperimentalAPI"]);
        if (usable && NSS.needsClientRandomLearner() && !NSS.learnerResolvable(fnAddrs) && !tableTier) {
            devlog("NSS: SSL_SecretCallback skipped — no client_random source (offset not decoded or cached, " +
                "PK11_GenerateRandom not resolved, table unverified)");
            usable = false;
        }
        const prClose = fnAddrs["PR_Close"];
        if (usable && (!prClose || prClose.isNull())) {
            devlog("NSS: SSL_SecretCallback skipped — PR_Close not resolved, callbacks could not be restored safely");
            usable = false;
        }
        if (!usable) {
            NSS.SSL_SecretCallback_fn = null;
            NSS.SSL_SecretCallback_ptr = null;
        }
        return usable;
    }

    private static installImportFdHook(importFd: NativePointer, secretTier: boolean, tableTier: boolean): void {
        Interceptor.attach(importFd, {
            onLeave(retval: InvocationReturnValue) {
                if (retval.isNull()) return;
                // Copy the value: Frida's InvocationReturnValue is only valid inside this callback,
                // and the fd is kept in the ownership maps for PR_Close and the detach restore.
                const fd = copyPointer(retval);
                try {
                    if (secretTier) NSS.trackLearnerSocket(fd);
                    if (tableTier) NSS.register_handshake_callback(fd);
                    if (secretTier) NSS.register_secret_callback(fd);
                } catch (e) {
                    devlog("[-] NSS SSL_ImportFD hook: " + e);
                }
            }
        });
    }

    /** Tier 3: friTap's handshake callback on a new socket (the app's own registration replaces it later). */
    static register_handshake_callback(pRFileDesc: NativePointer): boolean {
        if (!NSS.get_SSL_Callback) return false;
        var sslSocketFD = NSS.findSslSocketUncached(pRFileDesc);
        if (sslSocketFD.isNull()) return false;
        if (NSS.get_SSL_Callback(pRFileDesc, NSS.keylog_callback, NULL) < 0) {
            devlog("[-] NSS: SSL_HandshakeCallback registration failed");
            return false;
        }
        NSS.trackOwnedSocket(NSS.ownedHandshakeCallbackFds, sslSocketFD, pRFileDesc);
        devlog("[*] NSS keylog handshake callback installed");
        return true;
    }

    /** Tier 3: hook each distinct app SSLHandshakeCallback (TLS 1.2 keys after the handshake). */
    private static installHandshakeCallbackInterceptor(sslHandshakeCallback: NativePointer | undefined): void {
        if (!sslHandshakeCallback || sslHandshakeCallback.isNull()) return;
        Interceptor.attach(sslHandshakeCallback, {
            onEnter(args: InvocationArguments) {
                try {
                    var sslSocketFD = NSS.findSslSocketUncached(args[0]);
                    // The app replaces ours on this socket: nothing to reset on detach any more.
                    if (!sslSocketFD.isNull()) NSS.ownedHandshakeCallbackFds.delete(sslSocketFD.toString());
                    NSS.hookAppHandshakeCallback(args[1]);
                } catch (e) {
                    devlog("[-] NSS SSL_HandshakeCallback hook: " + e);
                }
            }
        });
    }

    /** Attach once per distinct, executable app callback; the dedupe entry is added before attaching. */
    static hookAppHandshakeCallback(cb: NativePointer): void {
        if (cb.isNull() || cb.equals(NSS.keylog_callback)) return;
        var key = cb.toString();
        if (NSS.hookedAppHandshakeCallbacks.has(key)) return;
        NSS.hookedAppHandshakeCallbacks.add(key);
        if (!isExecutable(cb)) {
            devlog("[-] NSS: app handshake callback " + cb + " is not executable — not hooked");
            return;
        }
        try {
            Interceptor.attach(cb, {
                onEnter(args: InvocationArguments) {
                    devlog("[*] NSS keylog via the application's handshake callback");
                    NSS.ssl_RecordKeyLog(args[0]);
                },
            });
        } catch (e) {
            devlog("[-] NSS: unable to hook app handshake callback " + cb + ": " + e);
        }
    }

    /**
     * Hook SSL_SecretCallback so an app registration on a socket that carries friTap's
     * callback (e.g. Neqo right after SSL_ImportFD) becomes the original we call through
     * to, and friTap's callback is registered again on top.
     */
    static installSecretCallbackInterceptor() {
        if (!NSS.SSL_SecretCallback_ptr) return;

        Interceptor.attach(NSS.SSL_SecretCallback_ptr, {
            onEnter(args: any) {
                this.fd = copyPointer(args[0]);
                this.cb = copyPointer(args[1]);
                this.arg = copyPointer(args[2]);
            },
            onLeave(retval: any) {
                if (NSS.secretCallbackReentryGuard || retval.toInt32() < 0) return;
                if (this.cb.equals(NSS.secret_callback)) return;
                try {
                    NSS.adoptAppSecretCallback(this.fd, this.cb, this.arg);
                } catch (e) {
                    devlog("[-] NSS SSL_SecretCallback hook: " + e);
                }
            }
        });
        devlog("SSL_SecretCallback interceptor installed");
    }

    /** The app registered its own secret callback on `fd`: keep it as the call-through target, put ours back. */
    static adoptAppSecretCallback(fd: NativePointer, cb: NativePointer, arg: NativePointer): void {
        var sslSocketFD = NSS.findSslSocketUncached(fd);
        if (sslSocketFD.isNull()) return;
        var key = sslSocketFD.toString();
        if (!NSS.ownedSecretCallbackFds.has(key)) return; // not a socket friTap registered on: leave it alone
        if (cb.isNull()) {
            NSS.originalSecretCallbacks.delete(key);
        } else {
            NSS.originalSecretCallbacks.set(key, {
                cb: cb, arg: arg,
                fn: new NativeFunction(cb, "void", ["pointer", "uint16", "int", "pointer", "pointer"]),
            });
        }
        if (NSS.setSecretCallback(fd, NSS.secret_callback, NULL) < 0) {
            // The app's registration stands; friTap no longer owns this socket.
            NSS.forgetOwnedSocket(key);
            return;
        }
        devlog("Re-registered secret callback after the app's registration (call-through kept)");
    }

    /** SSL_SecretCallback(fd, cb, arg) with the interceptor's re-entry guard set. */
    static setSecretCallback(fd: NativePointer, cb: NativePointer, arg: NativePointer): number {
        if (!NSS.SSL_SecretCallback_fn) return -1;
        NSS.secretCallbackReentryGuard = true;
        try {
            return NSS.SSL_SecretCallback_fn(fd, cb, arg);
        } finally {
            NSS.secretCallbackReentryGuard = false;
        }
    }

    /**
     * Register friTap's secret_callback on a new socket through the SSL_SecretCallback API
     * (tier 2). A socket fresh from SSL_ImportFD has no secret callback (ssl_DupSocket does
     * not copy it), so any entry under its address belongs to a freed socket and is dropped.
     *
     * @param {*} pRFileDesc a file descriptor (NSS PRFileDesc) to a SSL socket
     * @returns true iff friTap's callback is registered on the socket
     */
    static register_secret_callback(pRFileDesc: NativePointer): boolean {
        if (!NSS.SSL_SecretCallback_fn) return false;
        var sslSocketFD = NSS.findSslSocketUncached(pRFileDesc);
        if (sslSocketFD.isNull()) {
            devlog("[-] register_secret_callback: unable to get SSL socket descriptor");
            return false;
        }
        var key = sslSocketFD.toString();
        NSS.originalSecretCallbacks.delete(key);
        if (NSS.setSecretCallback(pRFileDesc, NSS.secret_callback, NULL) < 0) {
            devlog("[-] SSL_SecretCallback API call failed for " + pRFileDesc);
            NSS.ownedSecretCallbackFds.delete(key);
            return false;
        }
        NSS.trackOwnedSocket(NSS.ownedSecretCallbackFds, sslSocketFD, pRFileDesc);
        devlog("secret_callback registered via SSL_SecretCallback API");
        return true;
    }

    private static trackOwnedSocket(owned: Map<string, NativePointer>, sslSocketFD: NativePointer, pRFileDesc: NativePointer): void {
        owned.set(sslSocketFD.toString(), copyPointer(pRFileDesc));
        NSS.ownedSocketByFd.set(pRFileDesc.toString(), sslSocketFD.toString());
    }

    /** Drop every bookkeeping entry of a socket (closed, or no longer carrying friTap's callbacks). */
    static forgetOwnedSocket(sslSocketKey: string): void {
        NSS.ownedSecretCallbackFds.delete(sslSocketKey);
        NSS.ownedHandshakeCallbackFds.delete(sslSocketKey);
        NSS.originalSecretCallbacks.delete(sslSocketKey);
    }

    /** A closed socket's memory may be reused: the learner must not attribute randoms to it. */
    static forgetLearnerSocket(sslSocketKey: string): void {
        var sockets = NSS.activeRandomTrackedSockets();
        if (sockets === null) return;
        try {
            sockets.forget(addressOf(ptr(sslSocketKey)));
        } catch (_e) { /* malformed key: nothing tracked under it */ }
    }

    /** PR_Close of an owned socket clears its entries, so detach never touches a freed socket. */
    private static installCloseHook(prClose: NativePointer | undefined): void {
        if (!prClose || prClose.isNull()) return;
        Interceptor.attach(prClose, {
            onEnter(args: InvocationArguments) {
                if (NSS.ownedSocketByFd.size === 0) return;
                var fdKey = args[0].toString();
                var sslSocketKey = NSS.ownedSocketByFd.get(fdKey);
                if (sslSocketKey === undefined) return;
                NSS.ownedSocketByFd.delete(fdKey);
                NSS.forgetOwnedSocket(sslSocketKey);
                NSS.forgetLearnerSocket(sslSocketKey);
            }
        });
    }

    private static registerSecretCallbackTeardown(): void {
        if (NSS.teardownRegistered) return;
        NSS.teardownRegistered = true;
        registerDetachTeardown("nss-key-callbacks", NSS.restoreAppCallbacks);
    }

    /**
     * Detach teardown: put the app's own secret callback (or NULL) back on every live socket
     * that still carries friTap's secret_callback, and clear friTap's handshake callback, so
     * no socket keeps a pointer into the unloaded agent. Never throws.
     *
     * Returns the counts for the DetachReport: `owned` sockets, restored `toApp` (the app's
     * callback) or `toNull`, `stale` (no longer the same live socket, left alone), `failed`
     * (negative rv or threw); `hsOwned` / `hsCleared` for the handshake callback.
     */
    static restoreAppCallbacks(): NssRestoreSummary {
        var summary: NssRestoreSummary = {
            owned: NSS.ownedSecretCallbackFds.size, toApp: 0, toNull: 0, stale: 0, failed: 0,
            hsOwned: NSS.ownedHandshakeCallbackFds.size, hsCleared: 0,
            echDual: NSS.echDualEmissions,
        };
        // The read-only PK11_GenerateRandom observer (learner / ECH recorder) goes first.
        NSS.stopRandomObserver();
        NSS.ownedSecretCallbackFds.forEach((fd, key) => {
            if (!NSS.isSameLiveSocket(fd, key)) { summary.stale++; return; }
            var orig = NSS.originalSecretCallbacks.get(key);
            try {
                var rv = NSS.setSecretCallback(fd, orig ? orig.cb : NULL, orig ? orig.arg : NULL);
                if (rv < 0) summary.failed++;
                else if (orig) summary.toApp++;
                else summary.toNull++;
            } catch (e) {
                summary.failed++;
                devlog("[-] NSS: restoring the secret callback failed: " + e);
            }
        });
        NSS.ownedHandshakeCallbackFds.forEach((fd, key) => {
            if (!NSS.isSameLiveSocket(fd, key) || !NSS.get_SSL_Callback) return;
            try {
                NSS.get_SSL_Callback(fd, NULL, NULL);
                summary.hsCleared++;
            } catch (e) {
                devlog("[-] NSS: clearing the handshake callback failed: " + e);
            }
        });
        NSS.ownedSecretCallbackFds.clear();
        NSS.ownedHandshakeCallbackFds.clear();
        NSS.originalSecretCallbacks.clear();
        NSS.ownedSocketByFd.clear();
        return summary;
    }

    /** Defensive re-check before a teardown call: the fd is readable and still resolves to the same sslSocket. */
    private static isSameLiveSocket(fd: NativePointer, sslSocketKey: string): boolean {
        try {
            return isReadable(fd, Process.pointerSize * 6) && NSS.findSslSocketUncached(fd).toString() === sslSocketKey;
        } catch (_e) {
            return false;
        }
    }


    install_tls_keys_callback_hook() {

    }
}