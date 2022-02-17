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

},{"./log":4,"./shared":8}],2:[function(require,module,exports){
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

},{"./log":4,"./shared":8}],4:[function(require,module,exports){
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
exports.execute = void 0;
const shared_1 = require("./shared");
var getSocketDescriptor = function (sslcontext) {
    var ssl_context = parse_mbedtls_ssl_context_struct(sslcontext);
    return ssl_context.p_bio.readS32();
};
var getSessionId = function (sslcontext) {
    var ssl_context = parse_mbedtls_ssl_context_struct(sslcontext);
    var session_id = '';
    for (var byteCounter = 0; byteCounter < ssl_context.session.id_len; byteCounter++) {
        session_id = `${session_id}${ssl_context.session.id?.unwrap().add(byteCounter).readU8().toString(16).toUpperCase()}`;
    }
    return session_id;
};
//TODO: Complete for full parsing
function parse_mbedtls_ssl_context_struct(sslcontext) {
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
        p_bio: sslcontext.add(Process.platform == 'windows' ? 48 : 56).readPointer(),
        session_in: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 4 * Process.pointerSize).readPointer(),
        session_out: sslcontext.add(Process.pointerSize + 4 + 4 + 4 + 4 + 4 + 4 + 5 * Process.pointerSize).readPointer(),
        session: {
            start: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().readPointer(),
            ciphersuite: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8).readS32(),
            compression: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4).readS32(),
            id_len: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32(),
            id: sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4 + 4).readByteArray(sslcontext.add(24 + 7 * Process.pointerSize).readPointer().add(8 + 4 + 4).readU32())
        }
    };
}
function execute(moduleName) {
    var socket_library = (0, shared_1.getSocketLibrary)();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["mbedtls_ssl_read", "mbedtls_ssl_write"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    //https://tls.mbed.org/api/ssl_8h.html#aa2c29eeb1deaf5ad9f01a7515006ede5
    Interceptor.attach(addresses["mbedtls_ssl_read"], {
        onEnter: function (args) {
            this.buffer = args[1];
            this.len = args[2];
            this.sslContext = args[0];
            var message = (0, shared_1.getPortsAndAddresses)(getSocketDescriptor(args[0]), true, addresses);
            message["ssl_session_id"] = getSessionId(args[0]);
            message["function"] = "mbedtls_ssl_read";
            this.message = message;
        },
        onLeave: function (retval) {
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            var data = this.buffer.readByteArray(retval);
            this.message["contentType"] = "datalog";
            send(this.message, data);
        }
    });
    //https://tls.mbed.org/api/ssl_8h.html#a5bbda87d484de82df730758b475f32e5
    Interceptor.attach(addresses["mbedtls_ssl_write"], {
        onEnter: function (args) {
            var buffer = args[1];
            var len = args[2];
            len |= 0; // Cast retval to 32-bit integer.
            if (len <= 0) {
                return;
            }
            var data = buffer.readByteArray(len);
            var message = (0, shared_1.getPortsAndAddresses)(getSocketDescriptor(args[0]), false, addresses);
            message["ssl_session_id"] = getSessionId(args[0]);
            message["function"] = "mbedtls_ssl_write";
            message["contentType"] = "datalog";
            send(message, data);
        }
    });
}
exports.execute = execute;

},{"./shared":8}],6:[function(require,module,exports){
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
                (0, log_1.devlog)(JSON.stringify(temp));
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

},{"./log":4,"./shared":8}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
/**
 *
 * ToDO
 *  We need to find a way to calculate the offsets in a automated manner
 */
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
            socket_library = "libSystem.B.dylib";
            break;
        default:
            (0, log_1.log)(`Platform "${Process.platform} currently not supported!`);
    }
    var library_method_mapping = {};
    if (ObjC.available) {
        // the follwoing functions are avaible SSL_read SSL_write SSL_new SSL_get_session SSL_SESSION_get_id SSL_SESSION_get_id
        /*
        dont now what these functions are doingß
        BIO_write/read, boringssl_session_read/write BIO_get_fd

         */
        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "BIO_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_info_callback"];
    }
    else {
        library_method_mapping[`*${moduleName}*`] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback"];
    }
    // the socket methods are in all systems the same
    if (ObjC.available) {
        library_method_mapping[`*${socket_library}*`] = ["getpeername*", "getsockname*", "ntohs*", "ntohl*"];
    }
    else {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    const SSL_get_fd = ObjC.available ? new NativeFunction(addresses["BIO_get_fd"], "int", ["pointer"]) : new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    const SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    const SSL_CTX_set_keylog_callback = ObjC.available ? new NativeFunction(addresses["SSL_CTX_set_info_callback"], "void", ["pointer", "pointer"]) : new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
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
            if (!ObjC.available) {
                var message = (0, shared_1.getPortsAndAddresses)(SSL_get_fd(args[0]), true, addresses);
                message["ssl_session_id"] = getSslSessionId(args[0]);
                /* var my_Bio = args[0] as NativePointer
                my_Bio.readPointer*/
                message["function"] = "SSL_read";
                this.message = message;
                this.buf = args[1];
            } // this is a temporary workaround for the fd problem on iOS
        },
        onLeave: function (retval) {
            if (!ObjC.available) {
                retval |= 0; // Cast retval to 32-bit integer.
                if (retval <= 0) {
                    return;
                }
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            } // this is a temporary workaround for the fd problem on iOS
        }
    });
    Interceptor.attach(addresses["SSL_write"], {
        onEnter: function (args) {
            if (!ObjC.available) {
                var message = (0, shared_1.getPortsAndAddresses)(SSL_get_fd(args[0]), false, addresses);
                message["ssl_session_id"] = getSslSessionId(args[0]);
                message["function"] = "SSL_write";
                message["contentType"] = "datalog";
                send(message, args[1].readByteArray(parseInt(args[2])));
            } // this is a temporary workaround for the fd problem on iOS
        },
        onLeave: function (retval) {
        }
    });
    if (ObjC.available) { // inspired from https://codeshare.frida.re/@andydavies/ios-tls-keylogger/
        var CALLBACK_OFFSET = 0x2A8;
        var foundationNumber = Module.findExportByName('CoreFoundation', 'kCFCoreFoundationVersionNumber')?.readDouble();
        if (foundationNumber == undefined) {
            CALLBACK_OFFSET = 0x2A8;
        }
        else if (foundationNumber >= 1751.108) {
            CALLBACK_OFFSET = 0x2B8; // >= iOS 14.x 
        }
        Interceptor.attach(addresses["SSL_CTX_set_info_callback"], {
            onEnter: function (args) {
                (0, log_1.log)("found boringSSL TLS key");
                ptr(args[0]).add(CALLBACK_OFFSET).writePointer(keylog_callback);
            }
        });
    }
    Interceptor.attach(addresses["SSL_new"], {
        onEnter: function (args) {
            if (!ObjC.available) {
                SSL_CTX_set_keylog_callback(args[0], keylog_callback);
            }
        }
    });
}
exports.execute = execute;

},{"./log":4,"./shared":8}],8:[function(require,module,exports){
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
            return "libSystem.B.dylib";
            //TODO: improve it with regular expressions. libboringssl.dylib
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

},{"./log":4}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const sspi_1 = require("./sspi");
const nss_1 = require("./nss");
const gnutls_1 = require("./gnutls");
const mbedTLS_1 = require("./mbedTLS");
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
module_library_mapping["windows"] = [[/libssl-[0-9]+(_[0-9]+)?\.dll/, openssl_boringssl_1.execute], [/.*wolfssl.*\.dll/, wolfssl_1.execute], [/.*libgnutls-[0-9]+\.dll/, gnutls_1.execute], [/nspr[0-9]*\.dll/, nss_1.execute], [/sspicli\.dll/i, sspi_1.execute], [/mbedTLS\.dll/, mbedTLS_1.execute]];
module_library_mapping["linux"] = [[/.*libssl_sb.so/, openssl_boringssl_1.execute], [/.*libssl\.so/, openssl_boringssl_1.execute], [/.*libgnutls\.so/, gnutls_1.execute], [/.*libwolfssl\.so/, wolfssl_1.execute], [/.*libnspr[0-9]?\.so/, nss_1.execute], [/libmbedtls\.so.*/, mbedTLS_1.execute]];
module_library_mapping["darwin"] = [[/.*libboringssl\.dylib/, openssl_boringssl_1.execute]];
if (Process.platform === "windows") {
    for (let map of module_library_mapping["windows"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
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
                try {
                    func(module); // on some Android Apps we encounterd the problem of multiple SSL libraries but only one was used for the SSL encryption/decryption
                }
                catch (error) {
                    (0, log_1.log)(`error: skipping module ${module}`);
                    //  {'description': 'Could not find *libssl*.so!SSL_ImportFD', 'type': 'error'}
                }
            }
        }
    }
}
if (Process.platform === "darwin") {
    for (let map of module_library_mapping["darwin"]) {
        let regex = map[0];
        let func = map[1];
        for (let module of moduleNames) {
            if (regex.test(module)) {
                (0, log_1.log)(`${module} found & will be hooked on Darwin!`);
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
                for (let map of module_library_mapping["linux"]) {
                    let regex = map[0];
                    let func = map[1];
                    if (regex.test(this.moduleName)) {
                        (0, log_1.log)(`${this.moduleName} was loaded & will be hooked on Linux!`);
                        func(this.moduleName);
                    }
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
            for (let map of module_library_mapping["windows"]) {
                let regex = map[0];
                let func = map[1];
                if (regex.test(moduleName)) {
                    (0, log_1.log)(`${moduleName} was loaded & will be hooked on Windows!`);
                    func(moduleName);
                }
            }
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

},{"./bouncycastle":1,"./conscrypt":2,"./gnutls":3,"./log":4,"./mbedTLS":5,"./nss":6,"./openssl_boringssl":7,"./shared":8,"./sspi":10,"./wolfssl":11}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
/*
SspiCli.dll!DecryptMessage called!
ncrypt.dll!SslDecryptPacket called!
bcrypt.dll!BCryptDecrypt called!
*/
function execute(moduleName) {
    var socket_library = (0, shared_1.getSocketLibrary)();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["DecryptMessage", "EncryptMessage"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = (0, shared_1.readAddresses)(library_method_mapping);
    Interceptor.attach(addresses["DecryptMessage"], {
        onEnter: function (args) {
            this.pMessage = args[1];
        },
        onLeave: function () {
            this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
            this.pBuffers = this.pMessage.add(8).readPointer(); //PSecBuffer  pBuffers (Pointer to array of secBuffers)
            //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
            //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
            //--> Bytes to read: cBuffers + 16 Bytes
            this.secBuffers = []; //Addresses of all secBuffers
            for (let i = 0; i < this.cBuffers; i++) {
                var secBuffer = this.pBuffers.add(i * 16);
                this.secBuffers.push(secBuffer);
            }
            for (let i = 0; i < this.secBuffers.length; i++) {
                var size = this.secBuffers[i].add(0).readULong();
                var type = this.secBuffers[i].add(4).readULong();
                var bufferPointer = this.secBuffers[i].add(8).readPointer();
                if (type == 1) {
                    //TODO: Obtain information from the running process       
                    var bytes = bufferPointer.readByteArray(size);
                    var message = {};
                    message["ss_family"] = "AF_INET";
                    message["src_port"] = 444;
                    message["src_addr"] = 222;
                    message["dst_port"] = 443;
                    message["dst_addr"] = 222;
                    message["function"] = "DecryptMessage";
                    message["contentType"] = "datalog";
                    message["ssl_session_id"] = 10;
                    console.log(bytes);
                    send(message, bytes);
                }
            }
        }
    });
    Interceptor.attach(addresses["EncryptMessage"], {
        onEnter: function (args) {
            this.pMessage = args[2]; //PSecBufferDesc pMessage (https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc)
            this.cBuffers = this.pMessage.add(4).readULong(); //unsigned long cBuffers (Count of buffers)
            this.pBuffers = this.pMessage.add(8).readPointer(); //PSecBuffer  pBuffers (Pointer to array of secBuffers)
            //https://docs.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
            //One SecBuffer got 16 Bytes (unsigned long + unsigned long + pointer (64 Bit))
            //--> Bytes to read: cBuffers + 16 Bytes
            this.secBuffers = []; //Addresses of all secBuffers
            for (let i = 0; i < this.cBuffers; i++) {
                var secBuffer = this.pBuffers.add(i * 16);
                this.secBuffers.push(secBuffer);
            }
            for (let i = 0; i < this.secBuffers.length; i++) {
                var size = this.secBuffers[i].add(0).readULong();
                var type = this.secBuffers[i].add(4).readULong();
                var bufferPointer = this.secBuffers[i].add(8).readPointer();
                if (type == 1) {
                    //TODO: Obtain information from the running process
                    var bytes = bufferPointer.readByteArray(size);
                    var message = {};
                    message["ss_family"] = "AF_INET";
                    message["src_port"] = 443;
                    message["src_addr"] = 222;
                    message["dst_port"] = 444;
                    message["dst_addr"] = 222;
                    message["function"] = "EncryptMessage";
                    message["contentType"] = "datalog";
                    message["ssl_session_id"] = 10;
                    send(message, bytes);
                }
            }
        }
    });
}
exports.execute = execute;

},{"./shared":8}],11:[function(require,module,exports){
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
    Interceptor.attach(addresses["wolfSSL_read"], {
        onEnter: function (args) {
            var message = (0, shared_1.getPortsAndAddresses)(wolfSSL_get_fd(args[0]), true, addresses);
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
}
exports.execute = execute;

},{"./log":4,"./shared":8}]},{},[9])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uLy4uLy4uL2dpdF9wcm9qZWN0cy9vdGhlci9mcmlkYS1jb21waWxlL25vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9ib3VuY3ljYXN0bGUudHMiLCJhZ2VudC9jb25zY3J5cHQudHMiLCJhZ2VudC9nbnV0bHMudHMiLCJhZ2VudC9sb2cudHMiLCJhZ2VudC9tYmVkVExTLnRzIiwiYWdlbnQvbnNzLnRzIiwiYWdlbnQvb3BlbnNzbF9ib3Jpbmdzc2wudHMiLCJhZ2VudC9zaGFyZWQudHMiLCJhZ2VudC9zc2xfbG9nLnRzIiwiYWdlbnQvc3NwaS50cyIsImFnZW50L3dvbGZzc2wudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7QUNBQSwrQkFBMkI7QUFDM0IscUNBQTBHO0FBQzFHLFNBQWdCLE9BQU87SUFDbkIsSUFBSSxDQUFDLE9BQU8sQ0FBQztRQUVULDBGQUEwRjtRQUMxRixnRUFBZ0U7UUFDaEUsSUFBSSxhQUFhLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxrRUFBa0UsQ0FBQyxDQUFBO1FBQ2hHLGFBQWEsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLElBQUksRUFBRSxLQUFLLEVBQUUsS0FBSyxDQUFDLENBQUMsY0FBYyxHQUFHLFVBQVUsR0FBUSxFQUFFLE1BQVcsRUFBRSxHQUFRO1lBQ3ZHLElBQUksTUFBTSxHQUFrQixFQUFFLENBQUM7WUFDL0IsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLEdBQUcsRUFBRSxFQUFFLENBQUMsRUFBRTtnQkFDMUIsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUM7YUFDOUI7WUFDRCxJQUFJLE9BQU8sR0FBMkIsRUFBRSxDQUFBO1lBQ3hDLE9BQU8sQ0FBQyxhQUFhLENBQUMsR0FBRyxTQUFTLENBQUE7WUFDbEMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxHQUFHLElBQUks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QUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUUsQ0FBQyxHQUFFLENBQUMsR0FBRyxDQUFDLEdBQUcsT0FBTyxDQUFDLFdBQVcsQ0FBQyxDQUFDLFdBQVcsRUFBRTtRQUNyRyxjQUFjLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsV0FBVyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFFLENBQUMsR0FBRSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRSxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFO1FBQ2hILEtBQUssRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxRQUFRLElBQUksU0FBUyxDQUFDLENBQUMsQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLFdBQVcsRUFBRTtRQUU1RSxVQUFVLEVBQUUsVUFBVSxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsV0FBVyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFFLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFO1FBQzlHLFdBQVcsRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLE9BQU8sQ0FBQyxXQUFXLEdBQUcsQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLEdBQUUsQ0FBQyxHQUFFLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxHQUFHLE9BQU8sQ0FBQyxXQUFXLENBQUMsQ0FBQyxXQUFXLEVBQUU7UUFDOUcsT0FBTyxFQUFFO1lBQ0wsS0FBSyxFQUFFLFVBQVUsQ0FBQyxHQUFHLENBQUMsRUFBRSxHQUFHLENBQUMsR0FBRyxPQUFPLENBQUMsV0FBVyxDQUFDLENBQUMsV0FBVyxFQUFFLENBQUMsV0FBVyxFQUFFO1lBQy9FLFdBQVcsRUFBRSxVQUFVLENBQUMsR0FBRyxDQUFDLEVBQUUs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RUFBRSxDQUFDLFFBQVEsQ0FBQyxFQUFFLENBQUMsQ0FBQyxXQUFXLEVBQUUsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1NBQ3RFO1FBQ0QsT0FBTyxVQUFVLENBQUE7SUFDckIsQ0FBQztJQUVELFdBQVcsQ0FBQyxNQUFNLENBQUMsU0FBUyxDQUFDLGNBQWMsQ0FBQyxFQUN4QztRQUNJLE9BQU8sRUFBRSxVQUFVLElBQVM7WUFFeEIsSUFBSSxPQUFPLEdBQUcsSUFBQSw2QkFBb0IsRUFBQyxjQUFjLENBQUMsSUFBSSxDQUFDLENBQUMsQ0FBQyxDQUFXLEVBQUUsSUFBSSxFQUFFLFNBQVMsQ0FBQyxDQUFBO1lBRXRGLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxjQUFjLENBQUE7WUFDcEMsSUFBSSxDQUFDLE9BQU8sR0FBRyxPQUFPLENBQUE7WUFDdEIsSUFBSSxDQUFDLEdBQUcsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7UUFFdEIsQ0FBQztRQUNELE9BQU8sRUFBRSxVQUFVLE1BQVc7WUFDMUIsTUFBTSxJQUFJLENBQUMsQ0FBQSxDQUFDLGlDQUFpQztZQUM3QyxJQUFJLE1BQU0sSUFBSSxDQUFDLEVBQUU7Z0JBQ2IsT0FBTTthQUNUO1lBQ0QsSUFBSSxDQUFDLE9BQU8sQ0FBQyxhQUFhLENBQUMsR0FBRyxTQUFTLENBQUE7WUFDdkMsSUFBSSxDQUFDLElBQUksQ0FBQyxPQUFPLEVBQUUsSUFBSSxDQUFDLEdBQUcsQ0FBQyxhQUFhLENBQUMsTUFBTSxDQUFDLENBQUMsQ0FBQTtRQUN0RCxDQUFDO0tBQ0osQ0FBQyxDQUFBO0lBQ04sV0FBVyxDQUFDLE1BQU0sQ0FBQyxTQUFTLENBQUMsZUFBZSxDQUFDLEVBQ3pDO1FBQ0ksT0FBTyxFQUFFLFVBQVUsSUFBUztZQUN4QixJQUFJLE9BQU8sR0FBRyxJQUFBLDZCQUFvQixFQUFDLGNBQWMsQ0FBQyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQVcsRUFBRSxLQUFLLEVBQUUsU0FBUyxDQUFDLENBQUE7WUFDdkYsT0FBTyxDQUFDLGdCQUFnQixDQUFDLEdBQUcsZUFBZSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFBO1lBQ3BELE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxlQUFlLENBQUE7WUFDckMsT0FBTyxDQUFDLGFBQWEsQ0FBQyxHQUFHLFNBQVMsQ0FBQTtZQUNsQyxJQUFJLENBQUMsT0FBTyxFQUFFLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxhQUFhLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQTtRQUMzRCxDQUFDO1FBQ0QsT0FBTyxFQUFFLFVBQVUsTUFBVztRQUM5QixDQUFDO0tBQ0osQ0FBQyxDQUFBO0FBQ1YsQ0FBQztBQTVGRCwwQkE0RkMiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9
