(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("./log");
const shared_1 = require("./shared");
function execute() {
    Java.perform(function () {
        //Hook the inner class "AppDataOutput/input" of ProvSSLSocketDirect, so we can access the 
        //socket information in its outer class by accessing this.this$0
        var appDataOutput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataOutput");
        appDataOutput.write.overload('[B', 'int', 'int').implementation = function (buf, offset, len) {
            var result = [];
            for (var i = 0; i < len; ++i) {
                result.push(buf[i] & 0xff);
            }
            var message = {};
            message["contentType"] = "datalog";
            message["src_port"] = this.this$0.value.getLocalPort();
            message["dst_port"] = this.this$0.value.getPort();
            var localAddress = this.this$0.value.getLocalAddress().getAddress();
            var inetAddress = this.this$0.value.getInetAddress().getAddress();
            if (localAddress.length == 4) {
                message["src_addr"] = (0, shared_1.byteArrayToNumber)(localAddress);
                message["dst_addr"] = (0, shared_1.byteArrayToNumber)(inetAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = (0, shared_1.byteArrayToString)(localAddress);
                message["dst_addr"] = (0, shared_1.byteArrayToString)(inetAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = (0, shared_1.byteArrayToString)(this.this$0.value.getConnection().getSession().getId());
            //log(message["ssl_session_id"])
            message["function"] = "writeApplicationData";
            send(message, result);
            return this.write(buf, offset, len);
        };
        var appDataInput = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect$AppDataInput");
        appDataInput.read.overload('[B', 'int', 'int').implementation = function (buf, offset, len) {
            var bytesRead = this.read(buf, offset, len);
            var result = [];
            for (var i = 0; i < bytesRead; ++i) {
                result.push(buf[i] & 0xff);
            }
            var message = {};
            message["contentType"] = "datalog";
            message["ss_family"] = "AF_INET";
            message["src_port"] = this.this$0.value.getPort();
            message["dst_port"] = this.this$0.value.getLocalPort();
            var localAddress = this.this$0.value.getLocalAddress().getAddress();
            var inetAddress = this.this$0.value.getInetAddress().getAddress();
            if (localAddress.length == 4) {
                message["src_addr"] = (0, shared_1.byteArrayToNumber)(inetAddress);
                message["dst_addr"] = (0, shared_1.byteArrayToNumber)(localAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = (0, shared_1.byteArrayToString)(inetAddress);
                message["dst_addr"] = (0, shared_1.byteArrayToString)(localAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = (0, shared_1.byteArrayToString)(this.this$0.value.getConnection().getSession().getId());
            (0, log_1.log)(message["ssl_session_id"]);
            message["function"] = "readApplicationData";
            send(message, result);
            return bytesRead;
        };
        //Hook the handshake to read the client random and the master key
        var ProvSSLSocketDirect = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect");
        ProvSSLSocketDirect.notifyHandshakeComplete.implementation = function (x) {
            var protocol = this.protocol.value;
            var securityParameters = protocol.securityParameters.value;
            var clientRandom = securityParameters.clientRandom.value;
            var masterSecretObj = (0, shared_1.getAttribute)(securityParameters, "masterSecret");
            //The key is in the AbstractTlsSecret, so we need to access the superclass to get the field
            var clazz = Java.use("java.lang.Class");
            var masterSecretRawField = Java.cast(masterSecretObj.getClass(), clazz).getSuperclass().getDeclaredField("data");
            masterSecretRawField.setAccessible(true);
            var masterSecretReflectArray = masterSecretRawField.get(masterSecretObj);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + (0, shared_1.byteArrayToString)(clientRandom) + " " + (0, shared_1.reflectionByteArrayToString)(masterSecretReflectArray);
            send(message);
            return this.notifyHandshakeComplete(x);
        };
    });
}
exports.execute = execute;

},{"./log":4,"./shared":7}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const log_1 = require("./log");
function findProviderInstallerFromClassloaders(currentClassLoader, backupImplementation) {
    var providerInstallerImpl = null;
    var classLoaders = Java.enumerateClassLoadersSync();
    for (var cl of classLoaders) {
        try {
            var classFactory = Java.ClassFactory.get(cl);
            providerInstallerImpl = classFactory.use("com.google.android.gms.common.security.ProviderInstallerImpl");
            break;
        }
        catch (error) {
            // On error we return null
        }
    }
    //Revert the implementation to avoid an infinitloop of "Loadclass"
    currentClassLoader.loadClass.overload("java.lang.String").implementation = backupImplementation;
    return providerInstallerImpl;
}
function execute() {
    //We have to hook multiple entrypoints: ProviderInstallerImpl and ProviderInstaller
    Java.perform(function () {
        //Part one: Hook ProviderInstallerImpl
        var javaClassLoader = Java.use("java.lang.ClassLoader");
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String").implementation;
        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.  
        javaClassLoader.loadClass.overload("java.lang.String").implementation = function (className) {
            let retval = this.loadClass(className);
            if (className.endsWith("ProviderInstallerImpl")) {
                (0, log_1.log)("Process is loading ProviderInstallerImpl");
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation);
                if (providerInstallerImpl === null) {
                    (0, log_1.log)("ProviderInstallerImpl could not be found, although it has been loaded");
                }
                else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        (0, log_1.log)("ProviderinstallerImpl redirection/blocking");
                    };
                }
            }
            return retval;
        };
        /*
        //Do the same for second overload of javaClassLoader
        var backupImplementation = javaClassLoader.loadClass.overload("java.lang.String", "boolean").implementation
        //The classloader for ProviderInstallerImpl might not be present on startup, so we hook the loadClass method.
        javaClassLoader.loadClass.overload("java.lang.String", "boolean").implementation = function (className: string, resolve: boolean) {
            if (className.endsWith("ProviderInstallerImpl")) {
                log("Process is loading ProviderInstallerImpl (Method 2)")
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation)
                if (providerInstallerImpl === null) {
                    log("ProviderInstallerImpl could not be found, although it has been loaded")
                } else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log("ProviderinstallerImpl redirection/blocking")

                    }

                }
            }
            return this.loadClass(className, resolve)
        }
        */
        //Part two: Hook Providerinstaller
        try {
            var providerInstaller = Java.use("com.google.android.gms.security.ProviderInstaller");
            providerInstaller.installIfNeeded.implementation = function (context) {
                (0, log_1.log)("Providerinstaller redirection/blocking");
            };
            providerInstaller.installIfNeededAsync.implementation = function (context, callback) {
                (0, log_1.log)("Providerinstaller redirection/blocking");
                callback.onProviderInstalled();
            };
        }
        catch (error) {
            // As it is not available, do nothing
        }
    });
}
exports.execute = execute;

},{"./log":4}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["gnutls_record_recv", "gnutls_record_send", "gnutls_session_set_keylog_function", "gnutls_transport_get_int", "gnutls_session_get_id", "gnutls_init", "gnutls_handshake", "gnutls_session_get_keylog_function", "gnutls_session_get_random"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    const gnutls_transport_get_int = new NativeFunction(addresses["gnutls_transport_get_int"], "int", ["pointer"]);
    const gnutls_session_get_id = new NativeFunction(addresses["gnutls_session_get_id"], "int", ["pointer", "pointer", "pointer"]);
    const gnutls_session_set_keylog_function = new NativeFunction(addresses["gnutls_session_set_keylog_function"], "void", ["pointer", "pointer"]);
    const gnutls_session_get_random = new NativeFunction(addresses["gnutls_session_get_random"], "pointer", ["pointer", "pointer", "pointer"]);
    const keylog_callback = new NativeCallback(function (session, label, secret) {
        var message = {};
        message["contentType"] = "keylog";
        var secret_len = secret.add(Process.pointerSize).readUInt();
        var secret_str = "";
        var p = secret.readPointer();
        for (var i = 0; i < secret_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to secret_str.
            secret_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        var server_random_ptr = Memory.alloc(Process.pointerSize + 4);
        var client_random_ptr = Memory.alloc(Process.pointerSize + 4);
        gnutls_session_get_random(session, client_random_ptr, server_random_ptr);
        var client_random_str = "";
        var client_random_len = 32;
        p = client_random_ptr.readPointer();
        for (i = 0; i < client_random_len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to client_random_str.
            client_random_str +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        message["keylog"] = label.readCString() + " " + client_random_str + " " + secret_str;
        send(message);
        return 0;
    }, "int", ["pointer", "pointer", "pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(session) {
        var len_pointer = Memory.alloc(4);
        var err = gnutls_session_get_id(session, NULL, len_pointer);
        if (err != 0) {
            return "";
        }
        var len = len_pointer.readU32();
        var p = Memory.alloc(len);
        err = gnutls_session_get_id(session, p, len_pointer);
        if (err != 0) {
            return "";
        }
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    Interceptor.attach(addresses["gnutls_record_recv"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(gnutls_transport_get_int(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_read";
            this.message = message;
            this.buf = args[1];
        },
        onLeave: function (retval) {
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            this.message["contentType"] = "datalog";
            send(this.message, this.buf.readByteArray(retval));
        }
    });
    Interceptor.attach(addresses["gnutls_record_send"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(gnutls_transport_get_int(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["gnutls_init"], {
        onEnter: function (args) {
            this.session = args[0];
        },
        onLeave: function (retval) {
            gnutls_session_set_keylog_function(this.session.readPointer(), keylog_callback);
        }
    });
}
exports.execute = execute;

},{"./log":4,"./shared":7}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.devlog = exports.log = void 0;
function log(str) {
    var message = {};
    message["contentType"] = "console";
    message["console"] = str;
    send(message);
}
exports.log = log;
function devlog(str) {
    var message = {};
    message["contentType"] = "console_dev";
    message["console_dev"] = str;
    send(message);
}
exports.devlog = devlog;

},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = exports.getSSLLibrary = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
/**
 *  Current Todo:
 *  - Make code more readable
 *  - Fix SessionID-Problems
 *  - Fix issue that the hooks wont get applied when spawning thunderbird --> this is related how frida is spawning thunderbird ...
 *  - Fix PR_Read and PR_Write issue when the decrypted content is send via Pipes
 *
 *
 */
// Globals
var doTLS13_RTT0 = -1;
var SSL3_RANDOM_LENGTH = 32;
const { readU32, readU64, readPointer, writeU32, writeU64, writePointer } = NativePointer.prototype;
// Exported for use in openssl_boringssl.ts
function getSSLLibrary() {
    var moduleNames = (0, shared_1.getModuleNames)();
    //TODO: CONTINUE
}
exports.getSSLLibrary = getSSLLibrary;
function execute(moduleName) {
    var socket_library = (0, shared_1.getSocketLibrary)();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"];
    library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];
    library_method_mapping[Process.platform === "linux" ? "*libssl*.so" : "*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    const SSL_get_fd = new NativeFunction(addresses["PR_FileDesc2NativeHandle"], "int", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
    const getsockname = new NativeFunction(addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
    const getpeername = new NativeFunction(addresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
    const getDescType = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetDescType'), "int", ["pointer"]);
    // SSL Handshake Functions:
    const PR_GetNameForIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["pointer"]);
    /*
            SECStatus SSL_HandshakeCallback(PRFileDesc *fd, SSLHandshakeCallback cb, void *client_data);
            more at https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc#1112702
    */
    const get_SSL_Callback = new NativeFunction(addresses["SSL_HandshakeCallback"], "int", ["pointer", "pointer", "pointer"]);
    // SSL Key helper Functions 
    const PK11_ExtractKeyValue = new NativeFunction(addresses["PK11_ExtractKeyValue"], "int", ["pointer"]);
    const PK11_GetKeyData = new NativeFunction(addresses["PK11_GetKeyData"], "pointer", ["pointer"]);
    // https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/ssltyp#1026722
    let SECStatus;
    (function (SECStatus) {
        SECStatus[SECStatus["SECWouldBlock"] = -2] = "SECWouldBlock";
        SECStatus[SECStatus["SECFailure"] = -1] = "SECFailure";
        SECStatus[SECStatus["SECSuccess"] = 0] = "SECSuccess";
    })(SECStatus || (SECStatus = {}));
    ;
    let PRDescType;
    (function (PRDescType) {
        PRDescType[PRDescType["PR_DESC_FILE"] = 1] = "PR_DESC_FILE";
        PRDescType[PRDescType["PR_DESC_SOCKET_TCP"] = 2] = "PR_DESC_SOCKET_TCP";
        PRDescType[PRDescType["PR_DESC_SOCKET_UDP"] = 3] = "PR_DESC_SOCKET_UDP";
        PRDescType[PRDescType["PR_DESC_LAYERED"] = 4] = "PR_DESC_LAYERED";
        PRDescType[PRDescType["PR_DESC_PIPE"] = 5] = "PR_DESC_PIPE";
    })(PRDescType || (PRDescType = {}));
    PRDescType;
    function parse_struct_SECItem(secitem) {
        /*
         * struct SECItemStr {
         * SECItemType type;
         * unsigned char *data;
         * unsigned int len;
         * }; --> size = 20
        */
        return {
            "type": secitem.readU64(),
            "data": secitem.add(shared_1.pointerSize).readPointer(),
            "len": secitem.add(shared_1.pointerSize * 2).readU32()
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L971
    function parse_struct_sslSocketStr(sslSocketFD) {
        return {
            "fd": sslSocketFD.readPointer(),
            "version": sslSocketFD.add(160),
            "handshakeCallback": sslSocketFD.add(464),
            "secretCallback": sslSocketFD.add(568),
            "ssl3": sslSocketFD.add(1432)
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslimpl.h#L771
    function parse_struct_ssl3Str(ssl3_struct) {
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
            "prSpec": ssl3_struct.add(shared_1.pointerSize).readPointer(),
            "cwSpec": ssl3_struct.add(shared_1.pointerSize * 2).readPointer(),
            "pwSpec": ssl3_struct.add(shared_1.pointerSize * 3).readPointer(),
            "peerRequestedKeyUpdate": ssl3_struct.add(shared_1.pointerSize * 4).readU32(),
            "keyUpdateDeferred": ssl3_struct.add(shared_1.pointerSize * 4 + 4).readU32(),
            "deferredKeyUpdateRequest": ssl3_struct.add(shared_1.pointerSize * 4 + 8).readU32(),
            "clientCertRequested": ssl3_struct.add(shared_1.pointerSize * 4 + 12).readU32(),
            "clientCertificate": ssl3_struct.add(shared_1.pointerSize * 4 + 16).readPointer(),
            "clientPrivateKey": ssl3_struct.add(shared_1.pointerSize * 5 + 16).readPointer(),
            "clientCertChain": ssl3_struct.add(shared_1.pointerSize * 6 + 16).readPointer(),
            "sendEmptyCert": ssl3_struct.add(shared_1.pointerSize * 7 + 16).readU32(),
            "policy": ssl3_struct.add(shared_1.pointerSize * 7 + 20).readU32(),
            "peerCertArena": ssl3_struct.add(shared_1.pointerSize * 7 + 24).readPointer(),
            "peerCertChain": ssl3_struct.add(shared_1.pointerSize * 8 + 24).readPointer(),
            "ca_list": ssl3_struct.add(shared_1.pointerSize * 9 + 24).readPointer(),
            "hs": {
                "server_random": ssl3_struct.add(shared_1.pointerSize * 10 + 24),
                "client_random": ssl3_struct.add(shared_1.pointerSize * 10 + 56),
                "client_inner_random": ssl3_struct.add(shared_1.pointerSize * 10 + 88),
                "ws": ssl3_struct.add(shared_1.pointerSize * 10 + 120).readU32(),
                "hashType": ssl3_struct.add(shared_1.pointerSize * 10 + 124).readU32(),
                "messages": {
                    "data": ssl3_struct.add(shared_1.pointerSize * 10 + 128).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 11 + 128).readU32(),
                    "space": ssl3_struct.add(shared_1.pointerSize * 11 + 132).readU32(),
                    "fixed": ssl3_struct.add(shared_1.pointerSize * 11 + 136).readU32(),
                },
                "echInnerMessages": {
                    "data": ssl3_struct.add(shared_1.pointerSize * 11 + 140).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 12 + 140).readU32(),
                    "space": ssl3_struct.add(shared_1.pointerSize * 12 + 144).readU32(),
                    "fixed": ssl3_struct.add(shared_1.pointerSize * 12 + 148).readU32(),
                },
                "md5": ssl3_struct.add(shared_1.pointerSize * 12 + 152).readPointer(),
                "sha": ssl3_struct.add(shared_1.pointerSize * 13 + 152).readPointer(),
                "shaEchInner": ssl3_struct.add(shared_1.pointerSize * 14 + 152).readPointer(),
                "shaPostHandshake": ssl3_struct.add(shared_1.pointerSize * 15 + 152).readPointer(),
                "signatureScheme": ssl3_struct.add(shared_1.pointerSize * 16 + 152).readU32(),
                "kea_def": ssl3_struct.add(shared_1.pointerSize * 16 + 156).readPointer(),
                "cipher_suite": ssl3_struct.add(shared_1.pointerSize * 17 + 156).readU32(),
                "suite_def": ssl3_struct.add(shared_1.pointerSize * 17 + 160).readPointer(),
                "msg_body": {
                    "data": ssl3_struct.add(shared_1.pointerSize * 18 + 160).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 19 + 160).readU32(),
                    "space": ssl3_struct.add(shared_1.pointerSize * 19 + 164).readU32(),
                    "fixed": ssl3_struct.add(shared_1.pointerSize * 19 + 168).readU32(),
                },
                "header_bytes": ssl3_struct.add(shared_1.pointerSize * 19 + 172).readU32(),
                "msg_type": ssl3_struct.add(shared_1.pointerSize * 19 + 176).readU32(),
                "msg_len": ssl3_struct.add(shared_1.pointerSize * 19 + 180).readU32(),
                "isResuming": ssl3_struct.add(shared_1.pointerSize * 19 + 184).readU32(),
                "sendingSCSV": ssl3_struct.add(shared_1.pointerSize * 19 + 188).readU32(),
                "receivedNewSessionTicket": ssl3_struct.add(shared_1.pointerSize * 19 + 192).readU32(),
                "newSessionTicket": ssl3_struct.add(shared_1.pointerSize * 19 + 196),
                "finishedBytes": ssl3_struct.add(shared_1.pointerSize * 19 + 240).readU32(),
                "finishedMsgs": ssl3_struct.add(shared_1.pointerSize * 19 + 244),
                "authCertificatePending": ssl3_struct.add(shared_1.pointerSize * 18 + 316).readU32(),
                "restartTarget": ssl3_struct.add(shared_1.pointerSize * 19 + 320).readU32(),
                "canFalseStart": ssl3_struct.add(shared_1.pointerSize * 19 + 324).readU32(),
                "preliminaryInfo": ssl3_struct.add(shared_1.pointerSize * 19 + 328).readU32(),
                "remoteExtensions": {
                    "next": ssl3_struct.add(shared_1.pointerSize * 19 + 332).readPointer(),
                    "prev": ssl3_struct.add(shared_1.pointerSize * 20 + 332).readPointer(),
                },
                "echOuterExtensions": {
                    "next": ssl3_struct.add(shared_1.pointerSize * 21 + 332).readPointer(),
                    "prev": ssl3_struct.add(shared_1.pointerSize * 22 + 332).readPointer(),
                },
                "sendMessageSeq": ssl3_struct.add(shared_1.pointerSize * 23 + 332).readU32(),
                "lastMessageFlight": {
                    "next": ssl3_struct.add(shared_1.pointerSize * 23 + 336).readPointer(),
                    "prev": ssl3_struct.add(shared_1.pointerSize * 24 + 336).readPointer(),
                },
                "maxMessageSent": ssl3_struct.add(shared_1.pointerSize * 25 + 336).readU16(),
                "recvMessageSeq": ssl3_struct.add(shared_1.pointerSize * 25 + 338).readU16(),
                "recvdFragments": {
                    "data": ssl3_struct.add(shared_1.pointerSize * 25 + 340).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 26 + 340).readU32(),
                    "space": ssl3_struct.add(shared_1.pointerSize * 26 + 344).readU32(),
                    "fixed": ssl3_struct.add(shared_1.pointerSize * 26 + 348).readU32(),
                },
                "recvdHighWater": ssl3_struct.add(shared_1.pointerSize * 26 + 352).readU32(),
                "cookie": {
                    "type": ssl3_struct.add(shared_1.pointerSize * 26 + 356).readU64(),
                    "data": ssl3_struct.add(shared_1.pointerSize * 27 + 356).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 28 + 356).readU32(),
                },
                "times_array": ssl3_struct.add(shared_1.pointerSize * 28 + 360).readU32(),
                "rtTimer": ssl3_struct.add(shared_1.pointerSize * 28 + 432).readPointer(),
                "ackTimer": ssl3_struct.add(shared_1.pointerSize * 29 + 432).readPointer(),
                "hdTimer": ssl3_struct.add(shared_1.pointerSize * 30 + 432).readPointer(),
                "rtRetries": ssl3_struct.add(shared_1.pointerSize * 31 + 432).readU32(),
                "srvVirtName": {
                    "type": ssl3_struct.add(shared_1.pointerSize * 31 + 436).readU64(),
                    "data": ssl3_struct.add(shared_1.pointerSize * 32 + 436).readPointer(),
                    "len": ssl3_struct.add(shared_1.pointerSize * 33 + 436).readU32(),
                },
                "currentSecret": ssl3_struct.add(shared_1.pointerSize * 33 + 440).readPointer(),
                "resumptionMasterSecret": ssl3_struct.add(shared_1.pointerSize * 34 + 440).readPointer(),
                "dheSecret": ssl3_struct.add(shared_1.pointerSize * 35 + 440).readPointer(),
                "clientEarlyTrafficSecret": ssl3_struct.add(shared_1.pointerSize * 36 + 440).readPointer(),
                "clientHsTrafficSecret": ssl3_struct.add(shared_1.pointerSize * 37 + 440).readPointer(),
                "serverHsTrafficSecret": ssl3_struct.add(shared_1.pointerSize * 38 + 440).readPointer(),
                "clientTrafficSecret": ssl3_struct.add(shared_1.pointerSize * 39 + 440).readPointer(),
                "serverTrafficSecret": ssl3_struct.add(shared_1.pointerSize * 40 + 440).readPointer(),
                "earlyExporterSecret": ssl3_struct.add(shared_1.pointerSize * 41 + 440).readPointer(),
                "exporterSecret": ssl3_struct.add(shared_1.pointerSize * 42 + 440).readPointer()
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
        };
    }
    // https://github.com/nss-dev/nss/blob/master/lib/ssl/sslspec.h#L140 
    function parse_struct_sl3CipherSpecStr(cwSpec) {
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
            "refCt": cwSpec.add(shared_1.pointerSize * 2),
            "direction": cwSpec.add(shared_1.pointerSize * 2 + 4),
            "version": cwSpec.add(shared_1.pointerSize * 2 + 8),
            "recordVersion": cwSpec.add(shared_1.pointerSize * 2 + 12),
            "cipherDef": cwSpec.add(shared_1.pointerSize * 2 + 16).readPointer(),
            "macDef": cwSpec.add(shared_1.pointerSize * 3 + 16).readPointer(),
            "cipher": cwSpec.add(shared_1.pointerSize * 4 + 16),
            "cipherContext": cwSpec.add(shared_1.pointerSize * 4 + 24).readPointer(),
            "master_secret": cwSpec.add(shared_1.pointerSize * 5 + 24).readPointer()
        };
    }
    /********* NSS Callbacks ************/
    /*
    This callback gets called whenever a SSL Handshake completed
    
    typedef void (*SSLHandshakeCallback)(
            PRFileDesc *fd,
            void *client_data);
    */
    var keylog_callback = new NativeCallback(function (sslSocketFD, client_data) {
        ssl_RecordKeyLog(sslSocketFD);
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
    var secret_callback = new NativeCallback(function (sslSocketFD, epoch, dir, secret, arg_ptr) {
        parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch);
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
    function getPortsAndAddressesFromNSS(sockfd, isRead, methodAddresses) {
        var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
        var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
        var message = {};
        var addrType = Memory.alloc(2); // PRUint16 is a 2 byte (16 bit) value on all plattforms
        //var prNetAddr = Memory.alloc(Process.pointerSize)
        var addrlen = Memory.alloc(4);
        var addr = Memory.alloc(128);
        var src_dst = ["src", "dst"];
        for (var i = 0; i < src_dst.length; i++) {
            addrlen.writeU32(128);
            if ((src_dst[i] == "src") !== isRead) {
                getsockname(sockfd, addr);
            }
            else {
                getpeername(sockfd, addr);
            }
            if (addr.readU16() == shared_1.AF_INET) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
                message["ss_family"] = "AF_INET";
            }
            else if (addr.readU16() == shared_1.AF_INET6) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = "";
                var ipv6_addr = addr.add(8);
                for (var offset = 0; offset < 16; offset += 1) {
                    message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2);
                }
                if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                    message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32());
                    message["ss_family"] = "AF_INET";
                }
                else {
                    message["ss_family"] = "AF_INET6";
                }
            }
            else {
                (0, log_1.devlog)("[-] PIPE descriptor error");
                //FIXME: Sometimes addr.readU16() will be 0 when a PIPE Read oder Write gets interpcepted, thus this error will be thrown.
                throw "Only supporting IPv4/6";
            }
        }
        return message;
    }
    /**
     * This functions tests if a given address is a readable pointer
     *
     * @param {*} ptr_addr is a pointer to the memory location where we want to check if there is already an address
     * @returns 1 to indicate that there is a ptr at
     */
    function is_ptr_at_mem_location(ptr_addr) {
        try {
            // an exception is thrown if there isn't a readable address
            ptr_addr.readPointer();
            return 1;
        }
        catch (error) {
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
    function NSS_FindIdentityForName(pRFileDesc, layer_name) {
        var lower_ptr = pRFileDesc.add(shared_1.pointerSize * 2).readPointer();
        var higher_ptr = pRFileDesc.add(shared_1.pointerSize * 3).readPointer();
        var identity = pRFileDesc.add(shared_1.pointerSize * 5).readPointer();
        if (!identity.isNull()) {
            var nameptr = PR_GetNameForIdentity(identity).readCString();
            if (nameptr == layer_name) {
                return pRFileDesc;
            }
        }
        if (!lower_ptr.isNull()) {
            return NSS_FindIdentityForName(lower_ptr, layer_name);
        }
        if (!higher_ptr.isNull()) {
            (0, log_1.devlog)('Have upper');
        }
        // when we reach this we have some sort of error 
        (0, log_1.devlog)("[-] error while getting SSL layer");
        return NULL;
    }
    function getSessionIdString(session_id_ptr, len) {
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    function getSSL_Layer(pRFileDesc) {
        var ssl_layer_id = 3; // SSL has the Layer ID 3 normally.
        var getIdentitiesLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetIdentitiesLayer'), "pointer", ["pointer", "int"]);
        var ssl_layer = getIdentitiesLayer(pRFileDesc, ssl_layer_id);
        if (ptr(ssl_layer.toString()).isNull()) {
            (0, log_1.devlog)("PR_BAD_DESCRIPTOR_ERROR: " + ssl_layer);
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
    function getHexString(readAddr, len) {
        var secret_str = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xab ==> "ab"), and append
            // it to secret_str.
            secret_str +=
                ("0" + readAddr.add(i).readU8().toString(16).toLowerCase()).substr(-2);
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
    function getSslSessionIdFromFD(pRFileDesc) {
        var dummySSL_SessionID = "3E8ABF58649A1A1C58824D704173BA9AAFA2DA33B45FFEA341D218B29BBACF8F";
        var fdType = getDescType(pRFileDesc);
        //log("pRFileDescType: "+ fdType)
        /*if(fdType == 4){ // LAYERED
            pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString())
            if(pRFileDesc.toString() == "-1"){
                log("error")
    
            }
        }*/
        var layer = NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!layer) {
            return dummySSL_SessionID;
        }
        var sslSessionIdSECItem = ptr(SSL_SESSION_get_id(layer).toString());
        if (sslSessionIdSECItem == null || sslSessionIdSECItem.isNull()) {
            (0, log_1.devlog)("---- getSslSessionIdFromFD -----");
            (0, log_1.devlog)("ERROR");
            (0, log_1.devlog)("pRFileDescType: " + getDescType(pRFileDesc));
            if (fdType == 2) {
                var c = Memory.dup(pRFileDesc, 32);
                //log(hexdump(c))
                var getLayersIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetLayersIdentity'), "uint32", ["pointer"]);
                var getNameOfIdentityLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["uint32"]);
                var layerID = getLayersIdentity(pRFileDesc);
                (0, log_1.devlog)("LayerID: " + layerID);
                var nameIDentity = getNameOfIdentityLayer(layerID);
                (0, log_1.devlog)("name address: " + nameIDentity);
                (0, log_1.devlog)("name: " + ptr(nameIDentity.toString()).readCString());
                var sslSessionIdSECItem2 = ptr(getSSL_Layer(pRFileDesc).toString());
                (0, log_1.devlog)("sslSessionIdSECItem2 =" + sslSessionIdSECItem2);
                if (sslSessionIdSECItem2.toString().startsWith("0x7f")) {
                    var aa = Memory.dup(sslSessionIdSECItem2, 32);
                    //log(hexdump(aa))
                    var sslSessionIdSECItem3 = ptr(SSL_SESSION_get_id(sslSessionIdSECItem2).toString());
                    (0, log_1.devlog)("sslSessionIdSECItem3 =" + sslSessionIdSECItem3);
                }
                var sslSessionIdSECItem4 = ptr(SSL_SESSION_get_id(pRFileDesc).toString());
                (0, log_1.devlog)("sslSessionIdSECItem4 =" + sslSessionIdSECItem4);
                (0, log_1.devlog)("Using Dummy Session ID");
                (0, log_1.devlog)("");
            }
            else if (fdType == 4) {
                pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString());
                var sslSessionIdSECItem = ptr(SSL_SESSION_get_id(pRFileDesc).toString());
                (0, log_1.devlog)("new sessionid_ITEM: " + sslSessionIdSECItem);
            }
            else {
                (0, log_1.devlog)("---- SSL Session Analysis ------------");
                var c = Memory.dup(sslSessionIdSECItem, 32);
                (0, log_1.devlog)(hexdump(c));
            }
            (0, log_1.devlog)("---- getSslSessionIdFromFD finished -----");
            (0, log_1.devlog)("");
            return dummySSL_SessionID;
        }
        var len = sslSessionIdSECItem.add(shared_1.pointerSize * 2).readU32();
        var session_id_ptr = sslSessionIdSECItem.add(shared_1.pointerSize).readPointer();
        var session_id = getSessionIdString(session_id_ptr, len);
        return session_id;
    }
    function get_SSL_FD(pRFileDesc) {
        var ssl_layer = NSS_FindIdentityForName(pRFileDesc, 'SSL');
        if (!ssl_layer) {
            (0, log_1.devlog)("error: couldn't get SSL Layer from pRFileDesc");
            return NULL;
        }
        var sslSocketFD = get_SSL_Socket(ssl_layer);
        if (!sslSocketFD) {
            (0, log_1.devlog)("error: couldn't get sslSocketFD");
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
    function get_SSL_Socket(ssl_layer) {
        var sslSocket = ssl_layer.add(shared_1.pointerSize * 1).readPointer();
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
    function getMasterSecret(ssl3) {
        var cwSpec = ssl3.cwSpec;
        var masterSecret_Ptr = parse_struct_sl3CipherSpecStr(cwSpec).master_secret;
        var master_secret = get_Secret_As_HexString(masterSecret_Ptr);
        return master_secret;
    }
    /**
     * ss->ssl3.hs.client_random
     *
     * @param {*} ssl3 is a ptr to current parsed ssl3 struct
     * @returns the client_random as hex string (lower case)
     */
    function getClientRandom(ssl3) {
        var client_random = getHexString(ssl3.hs.client_random, SSL3_RANDOM_LENGTH);
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
    function get_SSL_Version(pRFileDesc) {
        var ssl_version_internal_Code = -1;
        var sslSocket = get_SSL_FD(pRFileDesc);
        if (sslSocket.isNull()) {
            return -1;
        }
        var sslVersion_pointerSize = 160;
        ssl_version_internal_Code = sslSocket.add((sslVersion_pointerSize)).readU16();
        return ssl_version_internal_Code;
    }
    function get_Secret_As_HexString(secret_key_Ptr) {
        var rv = PK11_ExtractKeyValue(secret_key_Ptr);
        if (rv != SECStatus.SECSuccess) {
            //log("[**] ERROR access the secret key");
            return "";
        }
        var keyData = PK11_GetKeyData(secret_key_Ptr); // return value is a SECItem
        var keyData_SECITem = parse_struct_SECItem(keyData);
        var secret_as_hexString = getHexString(keyData_SECITem.data, keyData_SECITem.len);
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
    function is_TLS_1_3(ssl_version_internal_Code) {
        if (ssl_version_internal_Code > 771) {
            return true;
        }
        else {
            return false;
        }
    }
    //see nss/lib/ssl/sslinfo.c for details */
    function get_Keylog_Dump(type, client_random, key) {
        return type + " " + client_random + " " + key;
    }
    /**
     *
     * @param {*} pRFileDesc
     * @param {*} dumping_handshake_secrets  a zero indicates an false and that the handshake just completed. A 1 indicates a true so that we are during the handshake itself
     * @returns
     */
    function getTLS_Keys(pRFileDesc, dumping_handshake_secrets) {
        var message = {};
        message["contentType"] = "keylog";
        (0, log_1.devlog)("[*] trying to log some keying materials ...");
        var sslSocketFD = get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            return;
        }
        var sslSocketStr = parse_struct_sslSocketStr(sslSocketFD);
        var ssl3_struct = sslSocketStr.ssl3;
        var ssl3 = parse_struct_ssl3Str(ssl3_struct);
        // the client_random is used to identify the diffrent SSL streams with their corresponding secrets
        var client_random = getClientRandom(ssl3);
        if (doTLS13_RTT0 == 1) {
            //var early_exporter_secret = get_Secret_As_HexString(ssl3_struct.add(768).readPointer()); //EARLY_EXPORTER_SECRET
            var early_exporter_secret = get_Secret_As_HexString(ssl3.hs.earlyExporterSecret); //EARLY_EXPORTER_SECRET
            (0, log_1.devlog)(get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret));
            message["keylog"] = get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret);
            send(message);
            doTLS13_RTT0 = -1;
        }
        if (dumping_handshake_secrets == 1) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 handshake keying material");
            /*
             * Those keys are computed in the beginning of a handshake
             */
            //var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(736).readPointer()); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientHsTrafficSecret); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            //parse_struct_ssl3Str(ssl3_struct)
            (0, log_1.devlog)(get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret);
            send(message);
            //var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(744).readPointer()); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3.hs.serverHsTrafficSecret); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            (0, log_1.devlog)(get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret));
            message["keylog"] = get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret);
            send(message);
            return;
        }
        else if (dumping_handshake_secrets == 2) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 RTT0 handshake keying material");
            var client_early_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientEarlyTrafficSecret); //CLIENT_EARLY_TRAFFIC_SECRET
            (0, log_1.devlog)(get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret);
            send(message);
            doTLS13_RTT0 = 1; // there is no callback for the EARLY_EXPORTER_SECRET
            return;
        }
        var ssl_version_internal_Code = get_SSL_Version(pRFileDesc);
        if (is_TLS_1_3(ssl_version_internal_Code)) {
            (0, log_1.devlog)("[*] exporting TLS 1.3 keying material");
            var client_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientTrafficSecret); //CLIENT_TRAFFIC_SECRET_0
            (0, log_1.devlog)(get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret);
            send(message);
            var server_traffic_secret = get_Secret_As_HexString(ssl3.hs.serverTrafficSecret); //SERVER_TRAFFIC_SECRET_0
            (0, log_1.devlog)(get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret));
            message["keylog"] = get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret);
            send(message);
            var exporter_secret = get_Secret_As_HexString(ssl3.hs.exporterSecret); //EXPORTER_SECRET 
            (0, log_1.devlog)(get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret));
            message["keylog"] = get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret);
            send(message);
        }
        else {
            (0, log_1.devlog)("[*] exporting TLS 1.2 keying material");
            var master_secret = getMasterSecret(ssl3);
            (0, log_1.devlog)(get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret);
            send(message);
        }
        doTLS13_RTT0 = -1;
        return;
    }
    function ssl_RecordKeyLog(sslSocketFD) {
        getTLS_Keys(sslSocketFD, 0);
    }
    /***** Intecepting the read and write operations to the socket *****/
    Interceptor.attach(addresses["PR_Read"], {
        onEnter: function (args) {
            this.fd = ptr(args[0]);
            this.buf = ptr(args[1]);
        },
        onLeave: function (retval) {
            if (retval.toInt32() <= 0 || getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                return;
            }
            var addr = Memory.alloc(8);
            var res = getpeername(this.fd, addr);
            // peername return -1 this is due to the fact that a PIPE descriptor is used to read from the SSL socket
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                (0, log_1.devlog)("Session ID: " + getSslSessionIdFromFD(this.fd));
                message["ssl_session_id"] = getSslSessionIdFromFD(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                var data = this.buf.readByteArray((new Uint32Array([retval]))[0]);
            }
            else {
                var temp = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                (0, log_1.devlog)(temp);
            }
        }
    });
    Interceptor.attach(addresses["PR_Write"], {
        onEnter: function (args) {
            this.fd = ptr(args[0]);
            this.buf = args[1];
            this.len = args[2];
        },
        onLeave: function (retval) {
            if (retval.toInt32() <= 0 || getDescType(this.fd) == PRDescType.PR_DESC_FILE) {
                return;
            }
            var addr = Memory.alloc(8);
            getsockname(this.fd, addr);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, false, addresses);
                message["ssl_session_id"] = getSslSessionIdFromFD(this.fd);
                message["function"] = "NSS_write";
                message["contentType"] = "datalog";
                send(message, this.buf.readByteArray((parseInt(this.len))));
            }
        }
    });
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
    function parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch) {
        if (epoch == 1) { // client_early_traffic_secret
            getTLS_Keys(sslSocketFD, 2);
        }
        else if (epoch == 2) { // client|server}_handshake_traffic_secret
            getTLS_Keys(sslSocketFD, 1);
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
        }
        else if (epoch >= 3) { // {client|server}_application_traffic_secret_{N}
            return;
            // we intercept this through the handshake_callback
        }
        else {
            (0, log_1.devlog)("[-] secret_callback invocation: UNKNOWN");
        }
    }
    function insert_hook_into_secretCallback(addr_of_installed_secretCallback) {
        Interceptor.attach(addr_of_installed_secretCallback, {
            onEnter(args) {
                this.sslSocketFD = args[0];
                this.epoch = args[1];
                parse_epoch_value_from_SSL_SetSecretCallback(this.sslSocketFD, this.epoch);
            },
            onLeave(retval) {
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
    function register_secret_callback(pRFileDesc) {
        var sslSocketFD = get_SSL_FD(pRFileDesc);
        if (sslSocketFD.isNull()) {
            (0, log_1.devlog)("[-] error while installing secret callback: unable get SSL socket descriptor");
            return;
        }
        var sslSocketStr = parse_struct_sslSocketStr(sslSocketFD);
        if (is_ptr_at_mem_location(sslSocketStr.secretCallback.readPointer()) == 1) {
            insert_hook_into_secretCallback(sslSocketStr.secretCallback.readPointer());
        }
        else {
            sslSocketStr.secretCallback.writePointer(secret_callback);
        }
        (0, log_1.devlog)("[**] secret callback (" + secret_callback + ") installed to address: " + sslSocketStr.secretCallback);
    }
    Interceptor.attach(addresses["SSL_ImportFD"], {
        onEnter(args) {
            this.fd = args[1];
        },
        onLeave(retval) {
            if (retval.isNull()) {
                (0, log_1.devlog)("[-] SSL_ImportFD error: unknow null");
                return;
            }
            var retValue = get_SSL_Callback(retval, keylog_callback, NULL);
            register_secret_callback(retval);
            // typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;
            if (retValue < 0) {
                (0, log_1.devlog)("Callback Error");
                var getErrorText = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetErrorText'), "int", ["pointer"]);
                var outbuffer = Memory.alloc(200); // max out size
                getErrorText(outbuffer);
                (0, log_1.devlog)("Error msg: " + outbuffer);
            }
            else {
                (0, log_1.devlog)("[*] keylog callback successfull installed");
            }
        }
    });
    /*
        SECStatus SSL_HandshakeCallback(
            PRFileDesc *fd,
            SSLHandshakeCallback cb,
            void *client_data
        );
     */
    Interceptor.attach(addresses["SSL_HandshakeCallback"], {
        onEnter(args) {
            this.originalCallback = args[1];
            Interceptor.attach(ptr(this.originalCallback), {
                onEnter(args) {
                    var sslSocketFD = args[0];
                    (0, log_1.devlog)("[*] keylog callback successfull installed via applications callback function");
                    ssl_RecordKeyLog(sslSocketFD);
                },
                onLeave(retval) {
                }
            });
        },
        onLeave(retval) {
        }
    });
}
exports.execute = execute;

},{"./log":4,"./shared":7}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    const SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    const SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    const SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
    const keylog_callback = new NativeCallback(function (ctxPtr, linePtr) {
        var message = {};
        message["contentType"] = "keylog";
        message["keylog"] = linePtr.readCString();
        send(message);
    }, "void", ["pointer", "pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(ssl) {
        var session = SSL_get_session(ssl);
        if (session.isNull()) {
            (0, log_1.log)("Session is null");
            return 0;
        }
        var len_pointer = Memory.alloc(4);
        var p = SSL_SESSION_get_id(session, len_pointer);
        var len = len_pointer.readU32();
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    Interceptor.attach(addresses["SSL_read"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(SSL_get_fd(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_read";
            this.message = message;
            this.buf = args[1];
        },
        onLeave: function (retval) {
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            this.message["contentType"] = "datalog";
            send(this.message, this.buf.readByteArray(retval));
        }
    });
    Interceptor.attach(addresses["SSL_write"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(SSL_get_fd(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "SSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["SSL_new"], {
        onEnter: function (args) {
            SSL_CTX_set_keylog_callback(args[0], keylog_callback);
        }
    });
}
exports.execute = execute;

},{"./log":4,"./shared":7}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAttribute = exports.byteArrayToNumber = exports.reflectionByteArrayToString = exports.byteArrayToString = exports.getPortsAndAddresses = exports.readAddresses = exports.getModuleNames = exports.getSocketLibrary = exports.pointerSize = exports.AF_INET6 = exports.AF_INET = void 0;
const log_1 = require("./log");
/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */
//GLOBALS
exports.AF_INET = 2;
exports.AF_INET6 = 10;
exports.pointerSize = Process.pointerSize;
//TODO: 
function getSocketLibrary() {
    var moduleNames = getModuleNames();
    var socket_library_name = "";
    switch (Process.platform) {
        case "linux":
            return moduleNames.find(element => element.match(/libc.*\.so/));
        case "windows":
            return "WS2_32.dll";
        case "darwin":
            return "";
            //TODO:Darwin implementation pending...
            break;
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
            return "";
    }
}
exports.getSocketLibrary = getSocketLibrary;
function getModuleNames() {
    var moduleNames = [];
    Process.enumerateModules().forEach(item => moduleNames.push(item.name));
    return moduleNames;
}
exports.getModuleNames = getModuleNames;
/**
 * Read the addresses for the given methods from the given modules
 * @param {{[key: string]: Array<String> }} library_method_mapping A string indexed list of arrays, mapping modules to methods
 * @return {{[key: string]: NativePointer }} A string indexed list of NativePointers, which point to the respective methods
 */
function readAddresses(library_method_mapping) {
    var resolver = new ApiResolver("module");
    var addresses = {};
    for (let library_name in library_method_mapping) {
        library_method_mapping[library_name].forEach(function (method) {
            var matches = resolver.enumerateMatches("exports:" + library_name + "!" + method);
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            }
            else {
                //log("Found " + method + " " + matches[0].address)
            }
            if (matches.length == 0) {
                throw "Could not find " + library_name + "!" + method;
            }
            else if (matches.length != 1) {
                // Sometimes Frida returns duplicates.
                var address = null;
                var s = "";
                var duplicates_only = true;
                for (var k = 0; k < matches.length; k++) {
                    if (s.length != 0) {
                        s += ", ";
                    }
                    s += matches[k].name + "@" + matches[k].address;
                    if (address == null) {
                        address = matches[k].address;
                    }
                    else if (!address.equals(matches[k].address)) {
                        duplicates_only = false;
                    }
                }
                if (!duplicates_only) {
                    throw "More than one match found for " + library_name + "!" + method + ": " +
                        s;
                }
            }
            addresses[method.toString()] = matches[0].address;
        });
    }
    return addresses;
}
exports.readAddresses = readAddresses;
/**
* Returns a dictionary of a sockfd's "src_addr", "src_port", "dst_addr", and
* "dst_port".
* @param {int} sockfd The file descriptor of the socket to inspect.
* @param {boolean} isRead If true, the context is an SSL_read call. If
*     false, the context is an SSL_write call.
* @param {{ [key: string]: NativePointer}} methodAddresses Dictionary containing (at least) addresses for getpeername, getsockname, ntohs and ntohl
* @return {{ [key: string]: string | number }} Dictionary of sockfd's "src_addr", "src_port", "dst_addr",
*     and "dst_port".
*/
function getPortsAndAddresses(sockfd, isRead, methodAddresses) {
    var getpeername = new NativeFunction(methodAddresses["getpeername"], "int", ["int", "pointer", "pointer"]);
    var getsockname = new NativeFunction(methodAddresses["getsockname"], "int", ["int", "pointer", "pointer"]);
    var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
    var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
    var message = {};
    var addrlen = Memory.alloc(4);
    var addr = Memory.alloc(128);
    var src_dst = ["src", "dst"];
    for (var i = 0; i < src_dst.length; i++) {
        addrlen.writeU32(128);
        if ((src_dst[i] == "src") !== isRead) {
            getsockname(sockfd, addr, addrlen);
        }
        else {
            getpeername(sockfd, addr, addrlen);
        }
        if (addr.readU16() == exports.AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
            message["ss_family"] = "AF_INET";
        }
        else if (addr.readU16() == exports.AF_INET6) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = "";
            var ipv6_addr = addr.add(8);
            for (var offset = 0; offset < 16; offset += 1) {
                message[src_dst[i] + "_addr"] += ("0" + ipv6_addr.add(offset).readU8().toString(16).toUpperCase()).substr(-2);
            }
            if (message[src_dst[i] + "_addr"].toString().indexOf("00000000000000000000FFFF") === 0) {
                message[src_dst[i] + "_addr"] = ntohl(ipv6_addr.add(12).readU32());
                message["ss_family"] = "AF_INET";
            }
            else {
                message["ss_family"] = "AF_INET6";
            }
        }
        else {
            throw "Only supporting IPv4/6";
        }
    }
    return message;
}
exports.getPortsAndAddresses = getPortsAndAddresses;
/**
 * Convert a Java byte array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
function byteArrayToString(byteArray) {
    return Array.from(byteArray, function (byte) {
        return ('0' + (byte & 0xFF).toString(16)).slice(-2);
    }).join('');
}
exports.byteArrayToString = byteArrayToString;
/**
 * Convert a Java Reflection array to string
 * @param byteArray The array to convert
 * @returns {string} The resulting string
 */
function reflectionByteArrayToString(byteArray) {
    var result = "";
    var arrayReflect = Java.use("java.lang.reflect.Array");
    for (var i = 0; i < arrayReflect.getLength(byteArray); i++) {
        result += ('0' + (arrayReflect.get(byteArray, i) & 0xFF).toString(16)).slice(-2);
    }
    return result;
}
exports.reflectionByteArrayToString = reflectionByteArrayToString;
/**
 * Convert a Java byte arry to number (Big Endian)
 * @param byteArray The array to convert
 * @returns {number} The resulting number
 */
function byteArrayToNumber(byteArray) {
    var value = 0;
    for (var i = 0; i < byteArray.length; i++) {
        value = (value * 256) + (byteArray[i] & 0xFF);
    }
    return value;
}
exports.byteArrayToNumber = byteArrayToNumber;
/**
 * Access an attribute of a Java Class
 * @param Instance The instace you want to access
 * @param fieldName The name of the attribute
 * @returns The value of the attribute of the requested field
 */
function getAttribute(Instance, fieldName) {
    var clazz = Java.use("java.lang.Class");
    var field = Java.cast(Instance.getClass(), clazz).getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(Instance);
}
exports.getAttribute = getAttribute;

},{"./log":4}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const nss_1 = require("./nss");
const gnutls_1 = require("./gnutls");
const log_1 = require("./log");
const shared_1 = require("./shared");
// sometimes libraries loaded but don't have function implemented we need to hook
function hasRequiredFunctions(libName, expectedFuncName) {
    var functionList = Process.getModuleByName(libName).enumerateExports().filter(exports => exports.name.toLowerCase().includes(expectedFuncName));
    if (functionList.length == 0) {
        return false;
    }
    else {
        return true;
    }
}
var moduleNames = (0, shared_1.getModuleNames)();
var module_library_mapping = {};
module_library_mapping["windows"] = [[/libssl-[0-9]+(_[0-9]+)?\.dll/, openssl_boringssl_1.execute], [/.*wolfssl.*\.dll/, wolfssl_1.execute], [/.*libgnutls-[0-9]+\.dll/, gnutls_1.execute], [/nspr[0-9]*\.dll/, nss_1.execute]]; //TODO: Map all the other libraries
module_library_mapping["linux"] = [[/.*libssl\.so/, openssl_boringssl_1.execute], [/.*libgnutls\.so/, gnutls_1.execute], [/.*libwolfssl\.so/, wolfssl_1.execute], [/.*libnspr[0-9]?\.so/, nss_1.execute]];
if (Process.platform === "windows") {
    for (let map of module_library_mapping["windows"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            //console.log(module + "vs" + map[0])
            if (regex.test(module)) {
                (0, log_1.log)(`${module} found & will be hooked on Windows!`);
                func(module);
            }
        }
    }
}
if (Process.platform === "linux") {
    for (let map of module_library_mapping["linux"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            if (regex.test(module)) {
                (0, log_1.log)(`${module} found & will be hooked on Linux!`);
                func(module);
            }
        }
    }
}
if (Java.available) {
    Java.perform(function () {
        try {
            //If we can load a class of spongycastle, we know its present and we have to hook it
            var testLoad = Java.use("org.spongycastle.jsse.provider.ProvSSLSocketDirect");
            (0, log_1.log)("Bouncycastle/Spongycastle detected.");
            (0, bouncycastle_1.execute)();
        }
        catch (error) {
            //On error, just do nothing
        }
    });
}
//Hook the dynamic loaders, in case library gets loaded at a later point in time
//! Repeated module loading results in multiple intereceptions. This will cause multiple log entries if module is loaded into the same address space 
try {
    switch (Process.platform) {
        case "windows":
            hookWindowsDynamicLoader();
            break;
        case "linux":
            hookLinuxDynamicLoader();
            break;
        default:
            console.log("Missing dynamic loader hook implementation!");
    }
}
catch (error) {
    console.log("Loader error: ", error);
    (0, log_1.log)("No dynamic loader present for hooking.");
}
function hookLinuxDynamicLoader() {
    const regex_libdl = /.*libdl.*\.so/;
    const libdl = moduleNames.find(element => element.match(regex_libdl));
    if (libdl === undefined)
        throw "Linux Dynamic loader not found!";
    let dl_exports = Process.getModuleByName(libdl).enumerateExports();
    var dlopen = "dlopen";
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext";
            break;
        }
    }
    Interceptor.attach(Module.getExportByName(libdl, dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString();
        },
        onLeave: function (retval) {
            if (this.moduleName != undefined) {
                if (this.moduleName.endsWith("libssl.so")) {
                    (0, log_1.log)("OpenSSL/BoringSSL detected.");
                    (0, openssl_boringssl_1.execute)("libssl");
                }
                else if (this.moduleName.endsWith("libwolfssl.so")) {
                    (0, log_1.log)("WolfSSL detected.");
                    (0, wolfssl_1.execute)("libwolfssl");
                }
            }
        }
    });
    console.log(`[*] ${dlopen.indexOf("android") == -1 ? "Linux" : "Android"} dynamic loader hooked.`);
}
function hookWindowsDynamicLoader() {
    const resolver = new ApiResolver('module');
    var loadLibraryExW = resolver.enumerateMatches("exports:KERNELBASE.dll!*LoadLibraryExW");
    if (loadLibraryExW.length == 0)
        return console.log("[!] Missing windows dynamic loader!");
    Interceptor.attach(loadLibraryExW[0].address, {
        onLeave(retval) {
            let map = new ModuleMap();
            let moduleName = map.findName(retval);
            if (moduleName === null)
                return;
            if (moduleName.indexOf("libssl-1_1.dll") != -1) {
                (0, log_1.log)("OpenSSL/BoringSSL detected.");
                (0, openssl_boringssl_1.execute)("libssl-1_1.dll");
            }
            //TODO:More module comparisons
        }
    });
    console.log("[*] Windows dynamic loader hooked.");
}
if (Java.available) {
    Java.perform(function () {
        //Conscrypt needs early instrumentation as we block the provider installation
        var Security = Java.use("java.security.Security");
        if (Security.getProviders().toString().includes("GmsCore_OpenSSL")) {
            (0, log_1.log)("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Trying to remove it to fall back on default Provider");
            Security.removeProvider("GmsCore_OpenSSL");
            (0, log_1.log)("Removed GmsCore_OpenSSL");
        }
        //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
        //we always have to watch the classloader activity
        (0, conscrypt_1.execute)();
        //Now do the same for Ssl_guard
        if (Security.getProviders().toString().includes("Ssl_Guard")) {
            (0, log_1.log)("Ssl_Guard deteced, removing it to fall back on default Provider");
            Security.removeProvider("Ssl_Guard");
            (0, log_1.log)("Removed Ssl_Guard");
        }
        //Same thing for Conscrypt provider which has been manually inserted (not by providerinstaller)
        if (Security.getProviders().toString().includes("Conscrypt version")) {
            (0, log_1.log)("Conscrypt detected");
            Security.removeProvider("Conscrypt");
            (0, log_1.log)("Removed Conscrypt");
        }
        //Uncomment this line to show all remaining providers
        //log("Remaining: " + Security.getProviders().toString())
        //Hook insertProviderAt/addprovider for dynamic provider blocking
        Security.insertProviderAt.implementation = function (provider, position) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                (0, log_1.log)("Blocking provider registration of " + provider.getName());
                return position;
            }
            else {
                return this.insertProviderAt(provider, position);
            }
        };
        //Same for addProvider
        Security.insertProviderAt.implementation = function (provider) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                (0, log_1.log)("Blocking provider registration of " + provider.getName());
                return 1;
            }
            else {
                return this.addProvider(provider);
            }
        };
    });
}

},{"./bouncycastle":1,"./conscrypt":2,"./gnutls":3,"./log":4,"./nss":5,"./openssl_boringssl":6,"./shared":7,"./wolfssl":9}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute(moduleName) {
    var socket_library = "";
    switch (Process.platform) {
        case "linux":
            socket_library = "libc";
            break;
        case "windows":
            socket_library = "WS2_32.dll";
            break;
        case "darwin":
            //TODO:Darwin implementation pending...
            break;
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_KeepArrays"];
    //? Just in case darwin methods are different to linux and windows ones
    if (socket_library === "libc" || socket_library === "WS2_32.dll") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    const wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"]);
    const wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"]);
    //const wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"])
    //const wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "uint"])
    const wolfSSL_KeepArrays = new NativeFunction(addresses["wolfSSL_KeepArrays"], "void", ["pointer"]);
    /**
       * Get the session_id of SSL object and return it as a hex string.
       * @param {!NativePointer} ssl A pointer to an SSL object.
       * @return {dict} A string representing the session_id of the SSL object's
       *     SSL_SESSION. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getSslSessionId(ssl) {
        var session = wolfSSL_get_session(ssl);
        if (session.isNull()) {
            (0, log_1.log)("Session is null");
            return 0;
        }
        var p = session.add(8);
        var len = 32; // This comes from internals.h. It is untested!
        var session_id = "";
        for (var i = 0; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + p.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
    }
    /**
       * Get the masterKey of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the masterKey of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    /*function getMasterKey(wolfSslPtr: NativePointer) {
        var session = wolfSSL_get_session(wolfSslPtr)
        var nullPtr = ptr(0)
        var masterKeySize = wolfSSL_SESSION_get_master_key(session, nullPtr, 0) as number
        var buffer = Memory.alloc(masterKeySize)
        wolfSSL_SESSION_get_master_key(session, buffer, masterKeySize)

        var masterKey = ""
        for (var i = 0; i < masterKeySize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            masterKey +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return masterKey;
    }
    */
    /**
       * Get the clientRandom of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the clientRandom of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    /*function getClientRandom(wolfSslPtr: NativePointer) {
        var nullPtr = ptr(0)
        var clientRandomSize = wolfSSL_get_client_random(wolfSslPtr, nullPtr, 0) as number
        var buffer = Memory.alloc(clientRandomSize)
        //console.log(wolfSSL_get_client_random(wolfSslPtr, buffer, clientRandomSize))

        var clientRandom = ""
        for (var i = 0; i < clientRandomSize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.

            clientRandom +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2)
        }
        return clientRandom;
    }
    */
    Interceptor.attach(addresses["wolfSSL_read"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(wolfSSL_get_fd(args[0]), true, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "wolfSSL_read";
            this.message = message;
            this.buf = args[1];
        },
        onLeave: function (retval) {
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            this.message["contentType"] = "datalog";
            send(this.message, this.buf.readByteArray(retval));
        }
    });
    Interceptor.attach(addresses["wolfSSL_write"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(wolfSSL_get_fd(args[0]), false, addresses);
            message["ssl_session_id"] = getSslSessionId(args[0]);
            message["function"] = "wolfSSL_write";
            message["contentType"] = "datalog";
            send(message, args[1].readByteArray(parseInt(args[2])));
        },
        onLeave: function (retval) {
        }
    });
    Interceptor.attach(addresses["wolfSSL_connect"], {
        onEnter: function (args) {
            this.wolfSslPtr = args[0];
            wolfSSL_KeepArrays(this.wolfSslPtr);
        },
        onLeave: function (retval) {
            //var clientRandom = getClientRandom(this.wolfSslPtr)
            //var masterKey = getMasterKey(this.wolfSslPtr)
            var message = {};
            message["contentType"] = "keylog";
            //message["keylog"] = "CLIENT_RANDOM " + clientRandom + " " + masterKey
            send(message);
        }
    });
}
exports.execute = execute;

},{"./log":4,"./shared":7}]},{},[8])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uL2dpdF9wcm9qZWN0cy9vdGhlci9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9ib3VuY3ljYXN0bGUudHMiLCJhZ2VudC9jb25zY3J5cHQudHMiLCJhZ2VudC9nbnV0bHMudHMiLCJhZ2VudC9sb2cudHMiLCJhZ2VudC9uc3MudHMiLCJhZ2VudC9vcGVuc3NsX2JvcmluZ3NzbC50cyIsImFnZW50L3NoYXJlZC50cyIsImFnZW50L3NzbF9sb2cudHMiLCJhZ2VudC93b2xmc3NsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7O0FDQUEsK0JBQTJCO0FBQzNCLHFDQUEwRztBQUMxRyxTQUFnQixPQUFPO0lBQ25CLElBQUksQ0FBQyxPQUFPLENBQUM7UUFFVCwwRkFBMEY7UUFDMUYsZ0VBQWdFO1FBQ2hFLElBQUksYUFBYSxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsa0VBQWtFLENBQUMsQ0FBQTtRQUNoRyxhQUFhLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsS0FBSyxFQUFFLEtBQUssQ0FBQyxDQUFDLGNBQWMsR0FBRyxVQUFVLEdBQVEsRUFBRSxNQUFXLEVBQUUsR0FBUTtZQUN2RyxJQUFJLE1BQU0sR0FBa0IsRUFBRSxDQUFDO1lBQy9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUUsRUFBRSxDQUFDLEVBQUU7Z0JBQzFCLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDO2FBQzlCO1lBQ0QsSUFBSSxPQUFPLEdBQTJCLEVBQUUsQ0FBQTtZQUN4QyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxDQUFBO1lBQ2xDLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxZQUFZLEVBQUUsQ0FB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
