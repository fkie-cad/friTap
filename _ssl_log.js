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

},{"./log":3,"./shared":6}],2:[function(require,module,exports){
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

},{"./log":3}],3:[function(require,module,exports){
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

},{}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
/*
SSL_ImportFD === SSL_NEW


*/
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 100;
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libssl*"] = ["SSL_ImportFD", "SSL_GetSessionID"];
    library_method_mapping["*libnspr*"] = ["PR_Write", "PR_Read", "PR_SetEnv", "PR_FileDesc2NativeHandle", "PR_GetPeerName", "PR_GetSockName"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var SSL_get_fd = new NativeFunction(addresses["PR_FileDesc2NativeHandle"], "int", ["pointer"]);
    var SET_NSS_ENV = new NativeFunction(addresses["PR_SetEnv"], "pointer", ["pointer"]);
    var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_GetSessionID"], "pointer", ["pointer"]);
    //var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"])
    var getsockname = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetSockName'), "int", ["pointer", "pointer"]);
    var getpeername = new NativeFunction(Module.getExportByName('libnspr4.so', 'PR_GetPeerName'), "int", ["pointer", "pointer"]);
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
        //var getpeername = new NativeFunction(methodAddresses["PR_GetPeerName"], "int", ["pointer", "pointer"])
        //var getsockname = new NativeFunction(methodAddresses["PR_GetSockName"], "int", ["pointer", "pointer"])
        var ntohs = new NativeFunction(methodAddresses["ntohs"], "uint16", ["uint16"]);
        var ntohl = new NativeFunction(methodAddresses["ntohl"], "uint32", ["uint32"]);
        var message = {};
        var addrType = Memory.alloc(2); // PRUint16 is a 2 byte (16 bit) value on all plattforms
        //var prNetAddr = Memory.alloc(Process.pointerSize)
        var addrlen = Memory.alloc(4);
        var addr = Memory.alloc(128);
        var src_dst = ["src", "dst"];
        log_1.log("reached1");
        for (var i = 0; i < src_dst.length; i++) {
            addrlen.writeU32(128);
            if ((src_dst[i] == "src") !== isRead) {
                log_1.log("reached2");
                getsockname(sockfd, addr);
            }
            else {
                log_1.log("reached3");
                getpeername(sockfd, addr);
            }
            if (addr.readU16() == AF_INET) {
                message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
                message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
                message["ss_family"] = "AF_INET";
            }
            else if (addr.readU16() == AF_INET6) {
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
       * };
       *
       *
       */
    function getSslSessionId(sslSessionIdSECItem) {
        if (sslSessionIdSECItem == null) {
            log_1.log("Session is null");
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
    Interceptor.attach(addresses["PR_Read"], {
        onEnter: function (args) {
            this.fd = args[0];
            this.buf = args[1];
        },
        onLeave: function (retval) {
            //log("write")
            retval |= 0; // Cast retval to 32-bit integer.
            if (retval <= 0) {
                return;
            }
            var addr = Memory.alloc(8);
            getpeername(this.fd, addr);
            if (addr.readU16() == 2 || addr.readU16() == 10 || addr.readU16() == 100) {
                var message = getPortsAndAddressesFromNSS(this.fd, true, addresses);
                message["ssl_session_id"] = getSslSessionId(this.fd);
                message["function"] = "NSS_read";
                this.message = message;
                this.message["contentType"] = "datalog";
                send(this.message, this.buf.readByteArray(retval));
            }
        }
    });
    Interceptor.attach(addresses["PR_Write"], {
        onEnter: function (args) {
            //log("write")
            var addr = Memory.alloc(8);
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
    Interceptor.attach(addresses["SSL_ImportFD"], {
        onEnter: function (args) {
            var keylog = Memory.allocUtf8String("SSLKEYLOGFILE=keylogfile");
            SET_NSS_ENV(keylog);
        }
    });
}
exports.execute = execute;

},{"./log":3,"./shared":6}],5:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libssl*"] = ["SSL_read", "SSL_write", "SSL_get_fd", "SSL_get_session", "SSL_SESSION_get_id", "SSL_new", "SSL_CTX_set_keylog_callback", "SSL_get_SSL_CTX"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var SSL_get_fd = new NativeFunction(addresses["SSL_get_fd"], "int", ["pointer"]);
    var SSL_get_session = new NativeFunction(addresses["SSL_get_session"], "pointer", ["pointer"]);
    var SSL_SESSION_get_id = new NativeFunction(addresses["SSL_SESSION_get_id"], "pointer", ["pointer", "pointer"]);
    var SSL_CTX_set_keylog_callback = new NativeFunction(addresses["SSL_CTX_set_keylog_callback"], "void", ["pointer", "pointer"]);
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
            var keylog_callback = new NativeCallback(function (ctxPtr, linePtr) {
                var message = {};
                message["contentType"] = "keylog";
                message["keylog"] = linePtr.readCString();
                send(message);
            }, "void", ["pointer", "pointer"]);
            SSL_CTX_set_keylog_callback(args[0], keylog_callback);
        }
    });
}
exports.execute = execute;

},{"./log":3,"./shared":6}],6:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getAttribute = exports.byteArrayToNumber = exports.reflectionByteArrayToString = exports.byteArrayToString = exports.getPortsAndAddresses = exports.readAddresses = void 0;
const log_1 = require("./log");
/**
 * This file contains methods which are shared for reading
 * secrets/data from different libraries. These methods are
 * indipendent from the implementation of ssl/tls, but they depend
 * on libc.
 */
//GLOBALS
const AF_INET = 2;
const AF_INET6 = 10;
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
                send("Found " + library_name + "!" + method);
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
    log_1.log("using strange");
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
            log_1.log("writing socket");
            log_1.log(sockfd.toString());
            getsockname(sockfd, addr, addrlen);
        }
        else {
            log_1.log("reading socket");
            log_1.log(sockfd.toString());
            getpeername(sockfd, addr, addrlen);
        }
        if (addr.readU16() == AF_INET) {
            message[src_dst[i] + "_port"] = ntohs(addr.add(2).readU16());
            message[src_dst[i] + "_addr"] = ntohl(addr.add(4).readU32());
            message["ss_family"] = "AF_INET";
        }
        else if (addr.readU16() == AF_INET6) {
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
            log_1.log("addr.readU16() ==");
            log_1.log(addr.readU16().toString());
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

},{"./log":3}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const openssl_boringssl_1 = require("./openssl_boringssl");
const wolfssl_1 = require("./wolfssl");
const bouncycastle_1 = require("./bouncycastle");
const conscrypt_1 = require("./conscrypt");
const nss_1 = require("./nss");
const log_1 = require("./log");
var moduleNames = [];
Process.enumerateModules().forEach(item => moduleNames.push(item.name));
for (var mod of moduleNames) {
    if (mod.indexOf("libssl.so") >= 0) {
        log_1.log("OpenSSL/BoringSSL detected.");
        openssl_boringssl_1.execute();
        break;
    }
}
for (var mod of moduleNames) {
    if (mod.indexOf("libwolfssl.so") >= 0) {
        log_1.log("WolfSSL detected.");
        wolfssl_1.execute();
        break;
    }
}
for (var mod of moduleNames) {
    if (mod.indexOf("libnspr") >= 0) {
        log_1.log("NSS SSL detected.");
        nss_1.execute();
        break;
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
//Hook the dynamic loader, in case library gets loaded at a later point in time
//check wether we are on android or linux
try {
    let dl_exports = Process.getModuleByName("libdl.so").enumerateExports();
    var dlopen = "dlopen";
    for (var ex of dl_exports) {
        if (ex.name === "android_dlopen_ext") {
            dlopen = "android_dlopen_ext";
            break;
        }
    }
    Interceptor.attach(Module.getExportByName("libdl.so", dlopen), {
        onEnter: function (args) {
            this.moduleName = args[0].readCString();
        },
        onLeave: function (retval) {
            if (this.moduleName != undefined) {
                if (this.moduleName.endsWith("libssl.so")) {
                    log_1.log("OpenSSL/BoringSSL detected.");
                    openssl_boringssl_1.execute();
                }
                else if (this.moduleName.endsWith("libwolfssl.so")) {
                    log_1.log("WolfSSL detected.");
                    wolfssl_1.execute();
                }
            }
        }
    });
}
catch (error) {
    log_1.log("No dynamic loader present for hooking.");
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
        log_1.log("Remaining: " + Security.getProviders().toString());
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

},{"./bouncycastle":1,"./conscrypt":2,"./log":3,"./nss":4,"./openssl_boringssl":5,"./wolfssl":8}],8:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.execute = void 0;
const shared_1 = require("./shared");
const log_1 = require("./log");
function execute() {
    var library_method_mapping = {};
    library_method_mapping["*libwolfssl*"] = ["wolfSSL_read", "wolfSSL_write", "wolfSSL_get_fd", "wolfSSL_get_session", "wolfSSL_connect", "wolfSSL_SESSION_get_master_key", "wolfSSL_get_client_random", "wolfSSL_KeepArrays"];
    library_method_mapping["*libc*"] = ["getpeername", "getsockname", "ntohs", "ntohl"];
    var addresses = shared_1.readAddresses(library_method_mapping);
    var wolfSSL_get_fd = new NativeFunction(addresses["wolfSSL_get_fd"], "int", ["pointer"]);
    var wolfSSL_get_session = new NativeFunction(addresses["wolfSSL_get_session"], "pointer", ["pointer"]);
    var wolfSSL_SESSION_get_master_key = new NativeFunction(addresses["wolfSSL_SESSION_get_master_key"], "int", ["pointer", "pointer", "int"]);
    var wolfSSL_get_client_random = new NativeFunction(addresses["wolfSSL_get_client_random"], "int", ["pointer", "pointer", "uint"]);
    var wolfSSL_KeepArrays = new NativeFunction(addresses["wolfSSL_KeepArrays"], "void", ["pointer"]);
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
    function getMasterKey(wolfSslPtr) {
        var session = wolfSSL_get_session(wolfSslPtr);
        var nullPtr = ptr(0);
        var masterKeySize = wolfSSL_SESSION_get_master_key(session, nullPtr, 0);
        var buffer = Memory.alloc(masterKeySize);
        wolfSSL_SESSION_get_master_key(session, buffer, masterKeySize);
        var masterKey = "";
        for (var i = 0; i < masterKeySize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.
            masterKey +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return masterKey;
    }
    /**
       * Get the clientRandom of the current session and return it as a hex string.
       * @param {!NativePointer} wolfSslPtr A pointer to an SSL object.
       * @return {string} A string representing the clientRandom of the SSL object's
       *     current session. For example,
       *     "59FD71B7B90202F359D89E66AE4E61247954E28431F6C6AC46625D472FF76336".
       */
    function getClientRandom(wolfSslPtr) {
        var nullPtr = ptr(0);
        var clientRandomSize = wolfSSL_get_client_random(wolfSslPtr, nullPtr, 0);
        var buffer = Memory.alloc(clientRandomSize);
        console.log(wolfSSL_get_client_random(wolfSslPtr, buffer, clientRandomSize));
        var clientRandom = "";
        for (var i = 0; i < clientRandomSize; i++) {
            // Read a byte, convert it to a hex string (0xAB ==> "AB"), and append
            // it to message.
            clientRandom +=
                ("0" + buffer.add(i).readU8().toString(16).toUpperCase()).substr(-2);
        }
        return clientRandom;
    }
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
            var clientRandom = getClientRandom(this.wolfSslPtr);
            var masterKey = getMasterKey(this.wolfSslPtr);
            var message = {};
            message["contentType"] = "keylog";
            message["keylog"] = "CLIENT_RANDOM " + clientRandom + " " + masterKey;
            send(message);
        }
    });
}
exports.execute = execute;

},{"./log":3,"./shared":6}]},{},[7])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL2ZyaWRhLWNvbXBpbGUvbm9kZV9tb2R1bGVzL2Jyb3dzZXItcGFjay9fcHJlbHVkZS5qcyIsImFnZW50L2JvdW5jeWNhc3RsZS50cyIsImFnZW50L2NvbnNjcnlwdC50cyIsImFnZW50L2xvZy50cyIsImFnZW50L25zcy50cyIsImFnZW50L29wZW5zc2xfYm9yaW5nc3NsLnRzIiwiYWdlbnQvc2hhcmVkLnRzIiwiYWdlbnQvc3NsX2xvZy50cyIsImFnZW50L3dvbGZzc2wudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7Ozs7QUNBQSwrQkFBMkI7QUFDM0IscUNBQTJHO0FBRzNHLFNBQWdCLE9BQU87SUFDbkIsSUFBSSxDQUFDLE9BQU8sQ0FBQztRQUVULDBGQUEwRjtRQUMxRixnRUFBZ0U7UUFDaEUsSUFBSSxhQUFhLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxrRUFBa0UsQ0FBQyxDQUFBO1FBQ2hHLGFBQWEsQ0FBQyxLQUFLLENBQUMsUUFBUSxDQUFDLElBQUksRUFBRSxLQUFLLEVBQUUsS0FBSyxDQUFDLENBQUMsY0FBYyxHQUFHLFVBQVUsR0FBUSxFQUFFLE1BQVcsRUFBRSxHQUFRO1lBQ3ZHLElBQUksTUFBTSxHQUFrQixFQUFFLENBQUM7WUFDL0IsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLEdBQUcsRUFBRSxFQUFFLENBQUMsRUFBRTtnQkFDMUIsTUFBTSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQyxDQUFDLEdBQUcsSUFBSSxDQUFDLENBQUM7YUFDOUI7WUFDRCxJQUFJLE9BQU8sR0FBMkIsRUFBRSxDQUFBO1lBQ3hDLE9BQU8sQ0FBQyxhQUFhLENBQUMsR0FBRyxTQUFTLENBQUE7WUFDbEMsT0FBTyxDQUFDLFVBQVUsQ0FBQyxHQUFHLElBQUksQ0FBQyxNQUFNLENBQUMsS0FBSyxDQUFDLFlBQVksRUFBRSxDQUFBO1lBQ3RELE9BQU8sQ0FBQyxVQUFVLENBQUMsR0FBRyxJQUFJLENBQUMs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
