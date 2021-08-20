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
                message["src_addr"] = shared_1.byteArrayToNumber(localAddress);
                message["dst_addr"] = shared_1.byteArrayToNumber(inetAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = shared_1.byteArrayToString(localAddress);
                message["dst_addr"] = shared_1.byteArrayToString(inetAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = shared_1.byteArrayToString(this.this$0.value.getConnection().getSession().getId());
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
                message["src_addr"] = shared_1.byteArrayToNumber(inetAddress);
                message["dst_addr"] = shared_1.byteArrayToNumber(localAddress);
                message["ss_family"] = "AF_INET";
            }
            else {
                message["src_addr"] = shared_1.byteArrayToString(inetAddress);
                message["dst_addr"] = shared_1.byteArrayToString(localAddress);
                message["ss_family"] = "AF_INET6";
            }
            message["ssl_session_id"] = shared_1.byteArrayToString(this.this$0.value.getConnection().getSession().getId());
            log_1.log(message["ssl_session_id"]);
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
            var masterSecretObj = shared_1.getAttribute(securityParameters, "masterSecret");
            //The key is in the AbstractTlsSecret, so we need to access the superclass to get the field
            var clazz = Java.use("java.lang.Class");
            var masterSecretRawField = Java.cast(masterSecretObj.getClass(), clazz).getSuperclass().getDeclaredField("data");
            masterSecretRawField.setAccessible(true);
            var masterSecretReflectArray = masterSecretRawField.get(masterSecretObj);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + shared_1.byteArrayToString(clientRandom) + " " + shared_1.reflectionByteArrayToString(masterSecretReflectArray);
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
                log_1.log("Process is loading ProviderInstallerImpl");
                var providerInstallerImpl = findProviderInstallerFromClassloaders(javaClassLoader, backupImplementation);
                if (providerInstallerImpl === null) {
                    log_1.log("ProviderInstallerImpl could not be found, although it has been loaded");
                }
                else {
                    providerInstallerImpl.insertProvider.implementation = function () {
                        log_1.log("ProviderinstallerImpl redirection/blocking");
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
                log_1.log("Providerinstaller redirection/blocking");
            };
            providerInstaller.installIfNeededAsync.implementation = function (context, callback) {
                log_1.log("Providerinstaller redirection/blocking");
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
            log_1.log(`Platform "${Process.platform} currently not supported!`);
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
    var addresses = shared_1.readAddresses(library_method_mapping);
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
            var message = shared_1.getPortsAndAddresses(gnutls_transport_get_int(args[0]), true, addresses);
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
            var message = shared_1.getPortsAndAddresses(gnutls_transport_get_int(args[0]), false, addresses);
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
exports.log = void 0;
function log(str) {
    var message = {};
    message["contentType"] = "console";
    message["console"] = str;
    send(message);
}
exports.log = log;

},{}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = exports.getSSLLibrary = void 0;
const shared_1 = require("./shared");
// Globals
var doTLS13_RTT0 = -1;
var SSL3_RANDOM_LENGTH = 32;
const { readU32, readU64, readPointer, writeU32, writeU64, writePointer } = NativePointer.prototype;
// Exported for use in openssl_boringssl.ts
function getSSLLibrary() {
    var moduleNames = shared_1.getModuleNames();
    //TODO: CONTINUE
}
exports.getSSLLibrary = getSSLLibrary;
function execute(moduleName) {
    var socket_library = shared_1.getSocketLibrary();
    var library_method_mapping = {};
    library_method_mapping[`*${moduleName}*`] = ["PR_Write", "PR_Read", "PR_SetEnv", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName", "PR_GetNameForIdentity", "PR_GetDescType"];
    library_method_mapping[`*libnss*`] = ["PK11_ExtractKeyValue", "PK11_GetKeyData"];
    library_method_mapping[Process.platform === "linux" ? "*libssl*.so" : "*ssl*.dll"] = ["SSL_ImportFD", "SSL_GetSessionID", "SSL_HandshakeCallback"];
    //? Just in case darwin methods are different to linux and windows ones
    if (Process.platform === "linux" || Process.platform === "windows") {
        library_method_mapping[`*${socket_library}*`] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    }
    else {
        //TODO: Darwin implementation pending
    }
    var addresses = shared_1.readAddresses(library_method_mapping);
    const SSL_get_fd = new NativeFunction(addresses["PR_FileDesc2NativeHandle"], "int", ["pointer"]);
    const SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"]);
    const SSL_SESSION_get_id = new NativeFunction(addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
    //var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])
    const getsockname = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetSockName'), "int", ["pointer", "pointer"]); //? Why libnspr4.so?
    const getpeername = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetPeerName'), "int", ["pointer", "pointer"]); //? Why libnspr4.so?
    const getDescType = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetDescType'), "int", ["pointer"]);
    var message_read = {};
    // SSL Handshake Functions:
    const PR_GetNameForIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["pointer"]);
    /*
            SECStatus SSL_HandshakeCallback(PRFileDesc *fd, SSLHandshakeCallback cb, void *client_data);
            more at https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/sslfnc#1112702
    */
    const get_SSL_Callback = new NativeFunction(addresses["SSL_HandshakeCallback"], "int", ["pointer", "pointer", "pointer"]);
    // SSL Key helper Functions 
    const PK11_ExtractKeyValue = new NativeFunction(Module.getExportByName('libnss3.so', 'PK11_ExtractKeyValue'), "int", ["pointer"]);
    const PK11_GetKeyData = new NativeFunction(Module.getExportByName('libnss3.so', 'PK11_GetKeyData'), "pointer", ["pointer"]);
    //Commented out for testing purposes on Linux
    //const getsockname = new NativeFunction(addresses["PR_GetSockName"], "int", ["pointer", "pointer"]);
    //const getpeername = new NativeFunction(addresses["PR_GetPeerName"], "int", ["pointer", "pointer"]);
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
                //FIXME: Sometimes addr.readU16() will be 0, thus this error will be thrown.
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
            log('Have upper');
        }
        // when we reach this we have some sort of error 
        console.log("[-] error while getting SSL layer");
        return NULL;
    }
    function log(str) {
        var message = {};
        message["contentType"] = "console";
        message["console"] = str;
        send(message);
    }
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
    // https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/SSL_functions/ssltyp#1026722
    let SECStatus;
    (function (SECStatus) {
        SECStatus[SECStatus["SECWouldBlock"] = -2] = "SECWouldBlock";
        SECStatus[SECStatus["SECFailure"] = -1] = "SECFailure";
        SECStatus[SECStatus["SECSuccess"] = 0] = "SECSuccess";
    })(SECStatus || (SECStatus = {}));
    ;
    /*
    SSLHandshakeCallback handshakeCallback;
        void *handshakeCallbackData;
        SSLCanFalseStartCallback canFalseStartCallback;
        void *canFalseStartCallbackData;
        void *pkcs11PinArg;
        SSLNextProtoCallback nextProtoCallback;
        void *nextProtoArg;
        SSLHelloRetryRequestCallback hrrCallback;
        void *hrrCallbackArg;
        PRCList extensionHooks;
        SSLResumptionTokenCallback resumptionTokenCallback;
        void *resumptionTokenContext;
        SSLSecretCallback secretCallback;
        void *secretCallbackArg;
    */
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
                    "len": ssl3_struct.add(shared_1.pointerSize * 33 + 436).readU32(), // 444
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
                "exporterSecret": ssl3_struct.add(shared_1.pointerSize * 42 + 440).readPointer() // derzeit 812 (falsch) --> hier muss 776 raus kommen --> 448  // */
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
            log("PR_BAD_DESCRIPTOR_ERROR: " + ssl_layer);
            return -1;
        }
        return ssl_layer;
    }
    /**
     *  wrong impl:
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
       * };
       *
       *
       */
    function getSslSessionId(sslSessionIdSECItem) {
        if (sslSessionIdSECItem == null) {
            log("Session is null");
            return 0;
        }
        var session_id = "";
        /*var a = Memory.dup(sslSessionIdSECItem, 32)
        log(hexdump(a))*/
        //var type_field = sslSessionIdSECItem.readByteArray(1) // enum should be the same size as char => 1 byte
        //session_id = sslSessionIdSECItem.add(1+Process.pointerSize).readPointer().readUtf8String() || "";
        var session_id_ptr = sslSessionIdSECItem.add(8).readPointer();
        var len_tmp = sslSessionIdSECItem.add(16).readU32();
        var len = (len_tmp > 32) ? 32 : len_tmp;
        var session_id = "";
        var b = Memory.dup(sslSessionIdSECItem, 32);
        /*log(hexdump(b))
        log("lenght value")
        log(len.toString());*/
        for (var i = 8; i < len; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to session_id.
            session_id +=
                ("0" + session_id_ptr.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return session_id;
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
            return;
        }
        var SSL_SESSION_get_id = new NativeFunction(Module.getExportByName('libssl3.so', 'SSL_GetSessionID'), "pointer", ["pointer"]);
        var sslSessionIdSECItem = ptr(SSL_SESSION_get_id(layer).toString());
        if (sslSessionIdSECItem == null || sslSessionIdSECItem.isNull()) {
            log("---- getSslSessionIdFromFD -----");
            log("ERROR");
            log("pRFileDescType: " + getDescType(pRFileDesc));
            if (fdType == 2) {
                var c = Memory.dup(pRFileDesc, 32);
                //log(hexdump(c))
                var getLayersIdentity = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetLayersIdentity'), "uint32", ["pointer"]);
                var getNameOfIdentityLayer = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetNameForIdentity'), "pointer", ["uint32"]);
                var layerID = getLayersIdentity(pRFileDesc);
                log("LayerID: " + layerID);
                //log("PRFileDesc *lower dump:");
                var nameIDentity = getNameOfIdentityLayer(layerID);
                log("name address: " + nameIDentity);
                log("name: " + ptr(nameIDentity.toString()).readCString());
                var sslSessionIdSECItem2 = ptr(getSSL_Layer(pRFileDesc).toString());
                log("sslSessionIdSECItem2 =" + sslSessionIdSECItem2);
                if (sslSessionIdSECItem2.toString().startsWith("0x7f")) {
                    var aa = Memory.dup(sslSessionIdSECItem2, 32);
                    //log(hexdump(aa))
                    var sslSessionIdSECItem3 = ptr(SSL_SESSION_get_id(sslSessionIdSECItem2).toString());
                    log("sslSessionIdSECItem3 =" + sslSessionIdSECItem3);
                }
                var sslSessionIdSECItem4 = ptr(SSL_SESSION_get_id(pRFileDesc).toString());
                log("sslSessionIdSECItem4 =" + sslSessionIdSECItem4);
                log("Using Dummy Session ID");
                log("");
                log("");
            }
            else if (fdType == 4) {
                pRFileDesc = ptr(getSSL_Layer(pRFileDesc).toString());
                var sslSessionIdSECItem = ptr(SSL_SESSION_get_id(pRFileDesc).toString());
                log("new sessionid_ITEM: " + sslSessionIdSECItem);
            }
            else {
                log("---- SSL Session Analysis ------------");
                var c = Memory.dup(sslSessionIdSECItem, 32);
                log(hexdump(c));
            }
            var dummySSL_SessionID = "3E8ABF58649A1A1C58824D704173BA9AAFA2DA33B45FFEA341D218B29BBACF8F";
            log("---- getSslSessionIdFromFD finished -----");
            log("");
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
            log("error: couldn't get SSL Layer from pRFileDesc");
            return NULL;
        }
        var sslSocketFD = get_SSL_Socket(ssl_layer);
        if (!sslSocketFD) {
            log("error: couldn't get sslSocketFD");
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
        console.log("[*] trying to log some keying materials ...");
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
            log(get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret));
            message["keylog"] = get_Keylog_Dump("EARLY_EXPORTER_SECRET", client_random, early_exporter_secret);
            send(message);
            doTLS13_RTT0 = -1;
        }
        if (dumping_handshake_secrets == 1) {
            log("[*] exporting TLS 1.3 handshake keying material");
            /*
             * Those keys are computed in the beginning of a handshake
             */
            //var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(736).readPointer()); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            var client_handshake_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientHsTrafficSecret); //CLIENT_HANDSHAKE_TRAFFIC_SECRET
            //parse_struct_ssl3Str(ssl3_struct)
            log(get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_HANDSHAKE_TRAFFIC_SECRET", client_random, client_handshake_traffic_secret);
            send(message);
            //var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(744).readPointer()); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            var server_handshake_traffic_secret = get_Secret_As_HexString(ssl3.hs.serverHsTrafficSecret); //SERVER_HANDSHAKE_TRAFFIC_SECRET
            log(get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret));
            message["keylog"] = get_Keylog_Dump("SERVER_HANDSHAKE_TRAFFIC_SECRET", client_random, server_handshake_traffic_secret);
            send(message);
            return;
        }
        else if (dumping_handshake_secrets == 2) {
            log("[*] exporting TLS 1.3 RTT0 handshake keying material");
            //var client_early_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(728).readPointer()); //CLIENT_EARLY_TRAFFIC_SECRET
            var client_early_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientEarlyTrafficSecret); //CLIENT_EARLY_TRAFFIC_SECRET
            log(get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_EARLY_TRAFFIC_SECRET", client_random, client_early_traffic_secret);
            send(message);
            doTLS13_RTT0 = 1; // there is no callback for the EARLY_EXPORTER_SECRET
            return;
        }
        var ssl_version_internal_Code = get_SSL_Version(pRFileDesc);
        if (is_TLS_1_3(ssl_version_internal_Code)) {
            log("[*] exporting TLS 1.3 keying material");
            //var client_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(752).readPointer()); //CLIENT_TRAFFIC_SECRET_0
            var client_traffic_secret = get_Secret_As_HexString(ssl3.hs.clientTrafficSecret); //CLIENT_TRAFFIC_SECRET_0
            log(get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_TRAFFIC_SECRET_0", client_random, client_traffic_secret);
            send(message);
            //var server_traffic_secret = get_Secret_As_HexString(ssl3_struct.add(760).readPointer()); //SERVER_TRAFFIC_SECRET_0
            var server_traffic_secret = get_Secret_As_HexString(ssl3.hs.serverTrafficSecret); //SERVER_TRAFFIC_SECRET_0
            log(get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret));
            message["keylog"] = get_Keylog_Dump("SERVER_TRAFFIC_SECRET_0", client_random, server_traffic_secret);
            send(message);
            var exporter_secret = get_Secret_As_HexString(ssl3.hs.exporterSecret); //EXPORTER_SECRET 
            // var exporter_secret = get_Secret_As_HexString(ssl3_struct.add(776).readPointer());
            log(get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret));
            message["keylog"] = get_Keylog_Dump("EXPORTER_SECRET", client_random, exporter_secret);
            send(message);
            /*
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
            */
        }
        else {
            log("[*] exporting TLS 1.2 keying material");
            var master_secret = getMasterSecret(ssl3);
            log(get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret));
            message["keylog"] = get_Keylog_Dump("CLIENT_RANDOM", client_random, master_secret);
            send(message);
        }
        doTLS13_RTT0 = -1;
        return;
    }
    function ssl_RecordKeyLog(sslSocketFD) {
        getTLS_Keys(sslSocketFD, 0);
    }
    /*
    typedef void (*SSLHandshakeCallback)(
            PRFileDesc *fd,
            void *client_data);
    */
    var keylog_callback = new NativeCallback(function (sslSocketFD, client_data) {
        ssl_RecordKeyLog(sslSocketFD);
        return 0;
    }, "void", ["pointer", "pointer"]);
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
            log("[+] secret_callback invocation: UNKNOWN");
        }
    }
    /**
     * https://github.com/nss-dev/nss/blob/master/lib/ssl/sslexp.h#L614
     *
     * SSL_SetSecretCallback installs a callback that TLS calls when it installs new
     * traffic secrets.
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
     */
    var secret_callback = new NativeCallback(function (sslSocketFD, epoch, dir, secret, arg_ptr) {
        parse_epoch_value_from_SSL_SetSecretCallback(sslSocketFD, epoch);
        return;
    }, "void", ["pointer", "uint16", "uint16", "pointer", "pointer"]);
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
            log("[-] error while installing secret callback: unable get SSL socket descriptor");
            return;
        }
        var sslSocketStr = parse_struct_sslSocketStr(sslSocketFD);
        if (is_ptr_at_mem_location(sslSocketStr.secretCallback.readPointer()) == 1) {
            insert_hook_into_secretCallback(sslSocketStr.secretCallback.readPointer());
        }
        else {
            sslSocketStr.secretCallback.writePointer(secret_callback);
        }
        log("[**] secret callback (" + secret_callback + ") installed to address: " + sslSocketStr.secretCallback);
    }
    Interceptor.attach(addresses["PR_Read"], {
        onEnter: function (args) {
            this.fd = ptr(args[0]);
            this.buf = ptr(args[1]);
        },
        onLeave: function (retval) {
            if (retval.toInt32() <= 0) {
                return;
                console.log("[*] PR_READ ...");
            }
            var addr = Memory.alloc(128);
            var res = getpeername(this.fd, addr); //FIXME: Results in crash! Fix: More Memory: why? Fix: 128 Bytes for addr (libnspr4 needed 8 Bytes for that)
            //!Der getpeername call gibt bei mir -1 zurück. Wenn ich mir die Daten unte in dem else ausgeben lasse, dann sehen die aber top aus!
            console.log(res);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                //console.log("Session ID: ", getSslSessionId(this.fd))
                message["ssl_session_id"] = getSslSessionId(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                var data = this.buf.readByteArray((new Uint32Array([retval]))[0]);
            }
            else {
                var temp = this.buf.readByteArray((new Uint32Array([retval]))[0]);
                console.log(temp);
            }
        }
    });
    Interceptor.attach(addresses["PR_Write"], {
        onEnter: function (args) {
            console.log("[*] PR_WRITE ...");
            var addr = Memory.alloc(128);
            getsockname(args[0], addr);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(args[0], false, addresses);
                message["ssl_session_id"] = getSslSessionId(args[0]);
                message["function"] = "NSS_write";
                message["contentType"] = "datalog";
                send(message, args[1].readByteArray(parseInt(args[2])));
            }
        },
        onLeave: function (retval) {
        }
    });
    // KEY loging
    Interceptor.attach(addresses["SSL_ImportFD"], {
        onEnter(args) {
            this.fd = args[1];
        },
        onLeave(retval) {
            if (retval.isNull()) {
                log("unknow null");
                return;
            }
            console.log("[*] SSL_ImportFD ...");
            var retValue = get_SSL_Callback(retval, keylog_callback, NULL);
            register_secret_callback(retval);
            // typedef enum { PR_FAILURE = -1, PR_SUCCESS = 0 } PRStatus;
            if (retValue < 0) {
                log("Callback Error");
                var getErrorText = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetErrorText'), "int", ["pointer"]);
                var outbuffer = Memory.alloc(200); // max out size
                getErrorText(outbuffer);
                log("Error msg: " + outbuffer);
            }
            else {
                log("[*] keylog callback successfull installed");
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
                    console.log("asdsd");
                    var sslSocketFD = args[0];
                    log("[*] keylog callback successfull installed via applications callback function");
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

},{"./shared":7}],6:[function(require,module,exports){
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
            log_1.log(`Platform "${Process.platform} currently not supported!`);
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
    var addresses = shared_1.readAddresses(library_method_mapping);
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
            log_1.log("Session is null");
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
            var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), true, addresses);
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
            var message = shared_1.getPortsAndAddresses(SSL_get_fd(args[0]), false, addresses);
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
            log_1.log(`Platform "${Process.platform} currently not supported!`);
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
var moduleNames = shared_1.getModuleNames();
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
                log_1.log(`${module} found & will be hooked on Windows!`);
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
                log_1.log(`${module} found & will be hooked on Linux!`);
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
            log_1.log("Bouncycastle/Spongycastle detected.");
            bouncycastle_1.execute();
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
    log_1.log("No dynamic loader present for hooking.");
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
                    log_1.log("OpenSSL/BoringSSL detected.");
                    openssl_boringssl_1.execute("libssl");
                }
                else if (this.moduleName.endsWith("libwolfssl.so")) {
                    log_1.log("WolfSSL detected.");
                    wolfssl_1.execute("libwolfssl");
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
                log_1.log("OpenSSL/BoringSSL detected.");
                openssl_boringssl_1.execute("libssl-1_1.dll");
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
            log_1.log("WARNING: PID " + Process.id + " Detected GmsCore_OpenSSL Provider. This can be a bit unstable. If you having issues, rerun with -spawn for early instrumentation. Trying to remove it to fall back on default Provider");
            Security.removeProvider("GmsCore_OpenSSL");
            log_1.log("Removed GmsCore_OpenSSL");
        }
        //As the classloader responsible for loading ProviderInstaller sometimes is not present from the beginning on,
        //we always have to watch the classloader activity
        conscrypt_1.execute();
        //Now do the same for Ssl_guard
        if (Security.getProviders().toString().includes("Ssl_Guard")) {
            log_1.log("Ssl_Guard deteced, removing it to fall back on default Provider");
            Security.removeProvider("Ssl_Guard");
            log_1.log("Removed Ssl_Guard");
        }
        //Same thing for Conscrypt provider which has been manually inserted (not by providerinstaller)
        if (Security.getProviders().toString().includes("Conscrypt version")) {
            log_1.log("Conscrypt detected");
            Security.removeProvider("Conscrypt");
            log_1.log("Removed Conscrypt");
        }
        //Uncomment this line to show all remaining providers
        //log("Remaining: " + Security.getProviders().toString())
        //Hook insertProviderAt/addprovider for dynamic provider blocking
        Security.insertProviderAt.implementation = function (provider, position) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log_1.log("Blocking provider registration of " + provider.getName());
                return position;
            }
            else {
                return this.insertProviderAt(provider, position);
            }
        };
        //Same for addProvider
        Security.insertProviderAt.implementation = function (provider) {
            if (provider.getName().includes("Conscrypt") || provider.getName().includes("Ssl_Guard") || provider.getName().includes("GmsCore_OpenSSL")) {
                log_1.log("Blocking provider registration of " + provider.getName());
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
            log_1.log(`Platform "${Process.platform} currently not supported!`);
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
    var addresses = shared_1.readAddresses(library_method_mapping);
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
            log_1.log("Session is null");
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
            var message = shared_1.getPortsAndAddresses(wolfSSL_get_fd(args[0]), true, addresses);
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
            var message = shared_1.getPortsAndAddresses(wolfSSL_get_fd(args[0]), false, addresses);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9ib3VuY3ljYXN0bGUudHMiLCJhZ2VudC9jb25zY3J5cHQudHMiLCJhZ2VudC9nbnV0bHMudHMiLCJhZ2VudC9sb2cudHMiLCJhZ2VudC9uc3MudHMiLCJhZ2VudC9vcGVuc3NsX2JvcmluZ3NzbC50cyIsImFnZW50L3NoYXJlZC50cyIsImFnZW50L3NzbF9sb2cudHMiLCJhZ2VudC93b2xmc3NsLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBOzs7O0FDQUEsK0JBQTJCO0FBQzNCLHFDQUEwRztBQUMxRyxTQUFnQixPQUFPO0lBQ25CLElBQUksQ0FBQyxPQUFPLENBQUM7UUFFVCwwRkFBMEY7UUFDMUYsZ0VBQWdFO1FBQ2hFLElBQUksYUFBYSxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsa0VBQWtFLENBQUMsQ0FBQTtRQUNoRyxhQUFhLENBQUMsS0FBSyxDQUFDLFFBQVEsQ0FBQyxJQUFJLEVBQUUsS0FBSyxFQUFFLEtBQUssQ0FBQyxDQUFDLGNBQWMsR0FBRyxVQUFVLEdBQVEsRUFBRSxNQUFXLEVBQUUsR0FBUTtZQUN2RyxJQUFJLE1BQU0sR0FBa0IsRUFBRSxDQUFDO1lBQy9CLEtBQUssSUFBSSxDQUFDLEdBQUcsQ0FBQyxFQUFFLENBQUMsR0FBRyxHQUFHLEVBQUUsRUFBRSxDQUFDLEVBQUU7Z0JBQzFCLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsQ0FBQyxHQUFHLElBQUksQ0FBQyxDQUFDO2FBQzlCO1lBQ0QsSUFBSSxPQUFPLEdBQTJCLEVBQUUsQ0FBQTtZQUN4QyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsU0FBUyxDQUFBO1lBQ2xDLE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxZQUFZLEVBQUUsQ0FBQTtZQUN0RCxPQUFPLENBQUMsVUFBVSxDQUFDLEdBQUcsSUFBSSxDQUFD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LEVBQUUsVUFBVSxNQUFXO1FBQzlCLENBQUM7S0FDSixDQUFDLENBQUE7SUFHTixXQUFXLENBQUMsTUFBTSxDQUFDLFNBQVMsQ0FBQyxpQkFBaUIsQ0FBQyxFQUMzQztRQUNJLE9BQU8sRUFBRSxVQUFVLElBQVM7WUFFeEIsSUFBSSxDQUFDLFVBQVUsR0FBRyxJQUFJLENBQUMsQ0FBQyxDQUFDLENBQUE7WUFDekIsa0JBQWtCLENBQUMsSUFBSSxDQUFDLFVBQVUsQ0FBQyxDQUFBO1FBQ3ZDLENBQUM7UUFDRCxPQUFPLEVBQUUsVUFBVSxNQUFXO1lBQzFCLHFEQUFxRDtZQUNyRCwrQ0FBK0M7WUFDL0MsSUFBSSxPQUFPLEdBQTJCLEVBQUUsQ0FBQTtZQUN4QyxPQUFPLENBQUMsYUFBYSxDQUFDLEdBQUcsUUFBUSxDQUFBO1lBQ2pDLHVFQUF1RTtZQUN2RSxJQUFJLENBQUMsT0FBTyxDQUFDLENBQUE7UUFFakIsQ0FBQztLQUNKLENBQUMsQ0FBQTtBQUdWLENBQUM7QUFyS0QsMEJBcUtDIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==
